"""
HydraRecon - Breach Simulation Engine GUI
Visual breach scenario simulation and impact analysis
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QTextEdit, QComboBox,
    QProgressBar, QSplitter, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QTabWidget, QListWidget, QListWidgetItem, QStackedWidget,
    QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush


class ScenarioCard(QFrame):
    """Card displaying a breach scenario"""
    
    selected = pyqtSignal(str)
    
    def __init__(self, scenario_data: Dict, parent=None):
        super().__init__(parent)
        self.scenario_data = scenario_data
        self.is_selected = False
        self.setup_ui()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def setup_ui(self):
        difficulty = self.scenario_data.get("difficulty", "medium")
        diff_colors = {
            "easy": "#27ae60",
            "medium": "#f1c40f",
            "hard": "#e67e22",
            "advanced": "#e74c3c",
        }
        color = diff_colors.get(difficulty, "#f1c40f")
        
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {color}15, stop:1 {color}08);
                border: 1px solid {color}30;
                border-left: 4px solid {color};
                border-radius: 12px;
                padding: 15px;
            }}
            QFrame:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {color}25, stop:1 {color}15);
                border: 1px solid {color}50;
                border-left: 4px solid {color};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QHBoxLayout()
        
        name = QLabel(self.scenario_data.get("name", "Unknown"))
        name.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        name.setStyleSheet("color: #fff; background: transparent;")
        header.addWidget(name)
        
        header.addStretch()
        
        diff_label = QLabel(difficulty.upper())
        diff_label.setStyleSheet(f"""
            color: {color};
            background: {color}20;
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
        """)
        header.addWidget(diff_label)
        
        layout.addLayout(header)
        
        # Description
        desc = QLabel(self.scenario_data.get("description", "")[:100])
        desc.setStyleSheet("color: #888; font-size: 11px; background: transparent;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # Info row
        info = QHBoxLayout()
        
        vector = self.scenario_data.get("vector", "unknown")
        vector_icons = {
            "phishing": "📧",
            "supply_chain": "📦",
            "insider_threat": "👤",
            "ransomware": "🔒",
            "zero_day": "💀",
            "apt": "🎯",
            "misconfiguration": "⚙️",
            "credential_stuffing": "🔑",
            "sql_injection": "💉",
        }
        vector_icon = vector_icons.get(vector, "⚡")
        
        vector_label = QLabel(f"{vector_icon} {vector.replace('_', ' ').title()}")
        vector_label.setStyleSheet("color: #aaa; font-size: 10px; background: transparent;")
        info.addWidget(vector_label)
        
        info.addStretch()
        
        duration = self.scenario_data.get("duration", 0)
        duration_label = QLabel(f"⏱️ {duration}h")
        duration_label.setStyleSheet("color: #aaa; font-size: 10px; background: transparent;")
        info.addWidget(duration_label)
        
        layout.addLayout(info)
        
        # TTPs
        ttps = self.scenario_data.get("ttps", [])[:3]
        if ttps:
            ttps_str = " | ".join(ttps)
            ttps_label = QLabel(f"🎯 {ttps_str}")
            ttps_label.setStyleSheet("color: #666; font-size: 9px; background: transparent;")
            layout.addWidget(ttps_label)
            
    def mousePressEvent(self, event):
        self.selected.emit(self.scenario_data.get("id", ""))
        super().mousePressEvent(event)
        
    def set_selected(self, selected: bool):
        self.is_selected = selected
        if selected:
            self.setStyleSheet(self.styleSheet().replace("border: 1px", "border: 2px"))


class EventWidget(QFrame):
    """Widget displaying a simulation event"""
    
    def __init__(self, event_data: Dict, parent=None):
        super().__init__(parent)
        self.event_data = event_data
        self.setup_ui()
        
    def setup_ui(self):
        success = self.event_data.get("success", False)
        detected = self.event_data.get("detected", False)
        
        if detected:
            color = "#e74c3c"
            border = "2px solid #e74c3c"
        elif success:
            color = "#27ae60"
            border = "1px solid #27ae6040"
        else:
            color = "#95a5a6"
            border = "1px solid #95a5a640"
            
        self.setStyleSheet(f"""
            QFrame {{
                background: {color}10;
                border: {border};
                border-radius: 8px;
                padding: 10px;
                margin: 2px 0;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        
        # Header
        header = QHBoxLayout()
        
        success_icon = "✅" if success else "❌"
        detected_icon = "🚨" if detected else ""
        
        technique = QLabel(f"{success_icon} {self.event_data.get('technique', 'Unknown')} {detected_icon}")
        technique.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        technique.setStyleSheet(f"color: {color}; background: transparent;")
        header.addWidget(technique)
        
        header.addStretch()
        
        mitre = QLabel(self.event_data.get("mitre_id", ""))
        mitre.setStyleSheet("color: #888; font-size: 9px; background: transparent;")
        header.addWidget(mitre)
        
        layout.addLayout(header)
        
        # Details
        details = QLabel(self.event_data.get("details", ""))
        details.setStyleSheet("color: #aaa; font-size: 10px; background: transparent;")
        details.setWordWrap(True)
        layout.addWidget(details)
        
        # Phase badge
        phase = self.event_data.get("phase", "unknown")
        phase_label = QLabel(f"📍 {phase.replace('_', ' ').title()}")
        phase_label.setStyleSheet("color: #666; font-size: 9px; background: transparent;")
        layout.addWidget(phase_label)


class BreachSimulationPage(QWidget):
    """Main page for Breach Simulation Engine"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = None
        self.selected_scenario = None
        self.current_simulation = None
        self.setup_ui()
        self.load_engine()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Scenarios
        left_panel = self.create_scenarios_panel()
        splitter.addWidget(left_panel)
        
        # Center - Simulation control & timeline
        center_panel = self.create_simulation_panel()
        splitter.addWidget(center_panel)
        
        # Right - Results
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([300, 500, 400])
        layout.addWidget(splitter, 1)
        
    def create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
                border-radius: 15px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_section = QVBoxLayout()
        
        title = QLabel("💥 Breach Simulation Engine")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #e74c3c; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Simulate Real-World Attack Scenarios and Measure Defense Effectiveness")
        subtitle.setStyleSheet("color: #888; font-size: 12px; background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Quick stats
        stats_frame = QFrame()
        stats_frame.setStyleSheet("background: transparent;")
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setSpacing(30)
        
        self.quick_stats = {}
        quick_stats = [
            ("Scenarios", "0", "#3498db"),
            ("Assets", "0", "#27ae60"),
            ("Simulations", "0", "#9b59b6"),
        ]
        
        for label, value, color in quick_stats:
            stat_widget = QVBoxLayout()
            value_label = QLabel(value)
            value_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
            value_label.setStyleSheet(f"color: {color}; background: transparent;")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_widget.addWidget(value_label)
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_widget.addWidget(name_label)
            
            self.quick_stats[label] = value_label
            stats_layout.addLayout(stat_widget)
            
        layout.addWidget(stats_frame)
        
        return frame
        
    def create_scenarios_panel(self) -> QFrame:
        """Create scenarios panel"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Header
        title = QLabel("🎯 Attack Scenarios")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(title)
        
        # Filter
        filter_layout = QHBoxLayout()
        
        self.difficulty_filter = QComboBox()
        self.difficulty_filter.addItems(["All Difficulties", "Easy", "Medium", "Hard", "Advanced"])
        self.difficulty_filter.setStyleSheet("""
            QComboBox {
                background: #16213e;
                color: #fff;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        filter_layout.addWidget(self.difficulty_filter)
        
        layout.addLayout(filter_layout)
        
        # Scenarios scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.scenarios_container = QWidget()
        self.scenarios_layout = QVBoxLayout(self.scenarios_container)
        self.scenarios_layout.setSpacing(10)
        self.scenarios_layout.addStretch()
        
        scroll.setWidget(self.scenarios_container)
        layout.addWidget(scroll, 1)
        
        return frame
        
    def create_simulation_panel(self) -> QFrame:
        """Create simulation control panel"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Selected scenario
        self.selected_scenario_frame = QFrame()
        self.selected_scenario_frame.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        selected_layout = QVBoxLayout(self.selected_scenario_frame)
        
        self.selected_title = QLabel("No scenario selected")
        self.selected_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.selected_title.setStyleSheet("color: #fff; background: transparent;")
        selected_layout.addWidget(self.selected_title)
        
        self.selected_desc = QLabel("Select a scenario to begin simulation")
        self.selected_desc.setStyleSheet("color: #888; background: transparent;")
        self.selected_desc.setWordWrap(True)
        selected_layout.addWidget(self.selected_desc)
        
        # Objectives
        self.objectives_label = QLabel("")
        self.objectives_label.setStyleSheet("color: #27ae60; font-size: 11px; background: transparent;")
        self.objectives_label.setWordWrap(True)
        selected_layout.addWidget(self.objectives_label)
        
        layout.addWidget(self.selected_scenario_frame)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        btn_style = """
            QPushButton {
                background: %s;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 15px 30px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: %s;
            }
            QPushButton:disabled {
                background: #555;
            }
        """
        
        self.run_btn = QPushButton("▶️ Run Simulation")
        self.run_btn.setStyleSheet(btn_style % ("#e74c3c", "#c0392b"))
        self.run_btn.clicked.connect(self.run_simulation)
        self.run_btn.setEnabled(False)
        btn_layout.addWidget(self.run_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setStyleSheet(btn_style % ("#95a5a6", "#7f8c8d"))
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress_frame = QFrame()
        self.progress_frame.setStyleSheet("background: transparent;")
        self.progress_frame.setVisible(False)
        progress_layout = QVBoxLayout(self.progress_frame)
        
        self.phase_label = QLabel("Phase: Initializing...")
        self.phase_label.setStyleSheet("color: #fff; font-weight: bold; background: transparent;")
        progress_layout.addWidget(self.phase_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #0a0a15;
                border-radius: 5px;
                height: 10px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #e74c3c, stop:1 #c0392b);
                border-radius: 5px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        layout.addWidget(self.progress_frame)
        
        # Timeline title
        timeline_title = QLabel("📅 Attack Timeline")
        timeline_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        timeline_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(timeline_title)
        
        # Event timeline
        timeline_scroll = QScrollArea()
        timeline_scroll.setWidgetResizable(True)
        timeline_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.timeline_container = QWidget()
        self.timeline_layout = QVBoxLayout(self.timeline_container)
        self.timeline_layout.setSpacing(5)
        self.timeline_layout.addStretch()
        
        timeline_scroll.setWidget(self.timeline_container)
        layout.addWidget(timeline_scroll, 1)
        
        return frame
        
    def create_results_panel(self) -> QFrame:
        """Create results panel"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: #16213e;
                color: #888;
                padding: 10px 20px;
                margin-right: 5px;
                border-radius: 5px 5px 0 0;
            }
            QTabBar::tab:selected {
                background: #0f3460;
                color: #fff;
            }
        """)
        
        # Summary tab
        summary_widget = QWidget()
        summary_layout = QVBoxLayout(summary_widget)
        
        self.summary_stats = {}
        stat_pairs = [
            ("Total Events", "#3498db"),
            ("Successful Attacks", "#e74c3c"),
            ("Detected Events", "#27ae60"),
            ("Compromised Assets", "#f1c40f"),
            ("Detection Rate", "#9b59b6"),
            ("MTTD (hours)", "#e67e22"),
            ("Impact Score", "#e74c3c"),
        ]
        
        for stat_name, color in stat_pairs:
            row = QHBoxLayout()
            
            name = QLabel(stat_name)
            name.setStyleSheet("color: #888; background: transparent;")
            row.addWidget(name)
            
            row.addStretch()
            
            value = QLabel("--")
            value.setFont(QFont("Arial", 14, QFont.Weight.Bold))
            value.setStyleSheet(f"color: {color}; background: transparent;")
            self.summary_stats[stat_name] = value
            row.addWidget(value)
            
            summary_layout.addLayout(row)
            
        summary_layout.addStretch()
        
        tabs.addTab(summary_widget, "📊 Summary")
        
        # Assets tab
        assets_widget = QWidget()
        assets_layout = QVBoxLayout(assets_widget)
        
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(4)
        self.assets_table.setHorizontalHeaderLabels(["Asset", "Type", "Status", "Criticality"])
        self.assets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.assets_table.setStyleSheet("""
            QTableWidget {
                background: #0a0a15;
                color: #fff;
                border: none;
                gridline-color: #333;
            }
            QHeaderView::section {
                background: #16213e;
                color: #888;
                padding: 8px;
                border: none;
            }
        """)
        assets_layout.addWidget(self.assets_table)
        
        tabs.addTab(assets_widget, "🖥️ Assets")
        
        # Recommendations tab
        rec_widget = QWidget()
        rec_layout = QVBoxLayout(rec_widget)
        
        self.rec_list = QListWidget()
        self.rec_list.setStyleSheet("""
            QListWidget {
                background: #0a0a15;
                color: #fff;
                border: none;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #333;
            }
        """)
        rec_layout.addWidget(self.rec_list)
        
        tabs.addTab(rec_widget, "💡 Recommendations")
        
        layout.addWidget(tabs)
        
        return frame
        
    def load_engine(self):
        """Load the breach simulation engine"""
        from core.breach_simulation import get_breach_simulation_engine
        self.engine = get_breach_simulation_engine()
        self.refresh_display()
        
    def refresh_display(self):
        """Refresh all displays"""
        if not self.engine:
            return
            
        stats = self.engine.stats
        
        # Update quick stats
        self.quick_stats["Scenarios"].setText(str(stats["scenarios"]))
        self.quick_stats["Assets"].setText(str(stats["assets"]))
        self.quick_stats["Simulations"].setText(str(stats["simulations_run"]))
        
        # Load scenarios
        self.load_scenarios()
        
        # Load assets
        self.load_assets()
        
    def load_scenarios(self):
        """Load scenarios into UI"""
        # Clear existing
        while self.scenarios_layout.count() > 1:
            item = self.scenarios_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Add scenario cards
        scenarios = self.engine.get_all_scenarios()
        for scenario in scenarios:
            card = ScenarioCard(scenario)
            card.selected.connect(self.on_scenario_selected)
            self.scenarios_layout.insertWidget(self.scenarios_layout.count() - 1, card)
            
    def load_assets(self):
        """Load assets into table"""
        assets = list(self.engine.assets.values())
        
        self.assets_table.setRowCount(len(assets))
        
        for i, asset in enumerate(assets):
            name_item = QTableWidgetItem(asset.name)
            type_item = QTableWidgetItem(asset.asset_type.value.replace("_", " ").title())
            
            if asset.compromised:
                status = "🔴 Compromised"
                color = "#e74c3c"
            else:
                status = "🟢 Secure"
                color = "#27ae60"
                
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor(color))
            
            crit_item = QTableWidgetItem(f"{asset.criticality}/10")
            if asset.criticality >= 8:
                crit_item.setForeground(QColor("#e74c3c"))
            elif asset.criticality >= 5:
                crit_item.setForeground(QColor("#f1c40f"))
            else:
                crit_item.setForeground(QColor("#27ae60"))
                
            self.assets_table.setItem(i, 0, name_item)
            self.assets_table.setItem(i, 1, type_item)
            self.assets_table.setItem(i, 2, status_item)
            self.assets_table.setItem(i, 3, crit_item)
            
    def on_scenario_selected(self, scenario_id: str):
        """Handle scenario selection"""
        scenarios = self.engine.get_all_scenarios()
        scenario = next((s for s in scenarios if s["id"] == scenario_id), None)
        
        if scenario:
            self.selected_scenario = scenario
            self.selected_title.setText(f"🎯 {scenario['name']}")
            self.selected_desc.setText(scenario["description"])
            
            objectives = " → ".join(scenario.get("objectives", []))
            self.objectives_label.setText(f"📋 {objectives}")
            
            self.run_btn.setEnabled(True)
            
    def run_simulation(self):
        """Run the selected simulation"""
        if not self.selected_scenario:
            return
            
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_frame.setVisible(True)
        
        # Clear timeline
        while self.timeline_layout.count() > 1:
            item = self.timeline_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Simulate progress
        self.simulation_step = 0
        self.simulation_phases = [
            "Initial Access", "Execution", "Persistence", 
            "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement"
        ]
        
        self.sim_timer = QTimer()
        self.sim_timer.timeout.connect(self.simulation_tick)
        self.sim_timer.start(300)
        
    def simulation_tick(self):
        """Update simulation progress"""
        self.simulation_step += 1
        progress = min(100, self.simulation_step * 5)
        self.progress_bar.setValue(progress)
        
        if self.simulation_step <= len(self.simulation_phases):
            phase_idx = min(self.simulation_step - 1, len(self.simulation_phases) - 1)
            self.phase_label.setText(f"Phase: {self.simulation_phases[phase_idx]}...")
            
        if progress >= 100:
            self.sim_timer.stop()
            self.simulation_complete()
            
    def simulation_complete(self):
        """Handle simulation completion"""
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        # Run actual simulation
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            self.engine.run_simulation(self.selected_scenario["id"])
        )
        loop.close()
        
        self.current_simulation = result
        
        # Update timeline
        events = self.engine.get_attack_timeline(result.id)
        for event in events[:20]:
            widget = EventWidget(event)
            self.timeline_layout.insertWidget(self.timeline_layout.count() - 1, widget)
            
        # Update summary stats
        summary = self.engine.get_simulation_summary(result.id)
        if summary:
            self.summary_stats["Total Events"].setText(str(summary["total_events"]))
            self.summary_stats["Successful Attacks"].setText(str(summary["successful_attacks"]))
            self.summary_stats["Detected Events"].setText(str(summary["detected_events"]))
            self.summary_stats["Compromised Assets"].setText(str(summary["compromised_assets"]))
            self.summary_stats["Detection Rate"].setText(f"{summary['detection_rate']:.1f}%")
            self.summary_stats["MTTD (hours)"].setText(f"{summary['mean_time_to_detect']:.2f}")
            self.summary_stats["Impact Score"].setText(f"{summary['total_impact']:.0f}")
            
            # Update recommendations
            self.rec_list.clear()
            for rec in summary["recommendations"]:
                item = QListWidgetItem(f"💡 {rec}")
                self.rec_list.addItem(item)
                
        # Refresh assets to show compromised status
        self.load_assets()
        
        # Show summary message
        QMessageBox.information(
            self, "Simulation Complete",
            f"Breach simulation completed!\n\n"
            f"Scenario: {result.scenario.name}\n"
            f"Events: {len(result.events)}\n"
            f"Compromised Assets: {len(result.compromised_assets)}\n"
            f"Detection Rate: {result.detection_rate:.1f}%"
        )
