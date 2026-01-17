"""
HydraRecon - Attack Path Analyzer GUI
Visual attack path analysis and risk visualization
"""

from datetime import datetime
from typing import Optional, Dict, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QProgressBar, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QListWidget, QListWidgetItem, QGraphicsView, QGraphicsScene,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
    QMessageBox, QComboBox
)
from PyQt6.QtCore import Qt, QTimer, QPointF, QRectF
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush


class PathCard(QFrame):
    """Card displaying an attack path"""
    
    def __init__(self, path_data: Dict, on_click=None, parent=None):
        super().__init__(parent)
        self.path_data = path_data
        self.on_click = on_click
        self.setup_ui()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def setup_ui(self):
        risk = self.path_data.get("risk_score", 0)
        
        if risk >= 70:
            color = "#e74c3c"
        elif risk >= 50:
            color = "#e67e22"
        elif risk >= 30:
            color = "#f1c40f"
        else:
            color = "#27ae60"
            
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
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        
        # Header
        header = QHBoxLayout()
        
        entry = self.path_data.get("entry", "Unknown")
        target = self.path_data.get("target", "Unknown")
        
        path_label = QLabel(f"🎯 {entry} → {target}")
        path_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        path_label.setStyleSheet("color: #fff; background: transparent;")
        header.addWidget(path_label)
        
        header.addStretch()
        
        risk_label = QLabel(f"Risk: {risk:.0f}")
        risk_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        risk_label.setStyleSheet(f"color: {color}; background: transparent;")
        header.addWidget(risk_label)
        
        layout.addLayout(header)
        
        # Path visualization
        path = self.path_data.get("path", [])
        if len(path) > 4:
            path_str = " → ".join(path[:2]) + " → ... → " + path[-1]
        else:
            path_str = " → ".join(path)
            
        path_viz = QLabel(f"📍 {path_str}")
        path_viz.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        path_viz.setWordWrap(True)
        layout.addWidget(path_viz)
        
        # Stats row
        stats = QHBoxLayout()
        
        hops = self.path_data.get("hops", 0)
        difficulty = self.path_data.get("difficulty", 0)
        detection = self.path_data.get("detection_risk", 0)
        time_hrs = self.path_data.get("time_hours", 0)
        
        stats_data = [
            (f"🔗 {hops} hops", "#3498db"),
            (f"⚡ {difficulty:.0%} difficulty", "#f1c40f"),
            (f"👁️ {detection:.0%} detection", "#e67e22"),
            (f"⏱️ {time_hrs:.1f}h", "#9b59b6"),
        ]
        
        for text, stat_color in stats_data:
            label = QLabel(text)
            label.setStyleSheet(f"color: {stat_color}; font-size: 10px; background: transparent;")
            stats.addWidget(label)
            
        stats.addStretch()
        layout.addLayout(stats)
        
        # Techniques
        techniques = self.path_data.get("techniques", [])[:3]
        if techniques:
            tech_str = " | ".join([t.replace("_", " ").title() for t in techniques])
            tech_label = QLabel(f"🛠️ {tech_str}")
            tech_label.setStyleSheet("color: #666; font-size: 9px; background: transparent;")
            layout.addWidget(tech_label)
            
    def mousePressEvent(self, event):
        if self.on_click:
            self.on_click(self.path_data.get("id"))
        super().mousePressEvent(event)


class PathStepWidget(QFrame):
    """Widget for a single path step"""
    
    def __init__(self, step_data: Dict, parent=None):
        super().__init__(parent)
        self.step_data = step_data
        self.setup_ui()
        
    def setup_ui(self):
        difficulty = self.step_data.get("difficulty", 0)
        
        if difficulty >= 0.7:
            color = "#27ae60"  # Hard = good for defense
        elif difficulty >= 0.4:
            color = "#f1c40f"
        else:
            color = "#e74c3c"  # Easy = bad for defense
            
        self.setStyleSheet(f"""
            QFrame {{
                background: {color}15;
                border-left: 3px solid {color};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        
        # Header
        header = QHBoxLayout()
        
        step_num = self.step_data.get("step", 0)
        technique = self.step_data.get("technique", "Unknown")
        
        title = QLabel(f"Step {step_num}: {technique}")
        title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {color}; background: transparent;")
        header.addWidget(title)
        
        header.addStretch()
        
        mitre = QLabel(self.step_data.get("mitre_id", ""))
        mitre.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        header.addWidget(mitre)
        
        layout.addLayout(header)
        
        # From -> To
        from_node = self.step_data.get("from", "")
        to_node = self.step_data.get("to", "")
        
        path_label = QLabel(f"📍 {from_node} → {to_node}")
        path_label.setStyleSheet("color: #aaa; font-size: 10px; background: transparent;")
        layout.addWidget(path_label)
        
        # Stats
        detection = self.step_data.get("detection_risk", 0)
        
        stats = QLabel(f"Difficulty: {difficulty:.0%} | Detection Risk: {detection:.0%}")
        stats.setStyleSheet("color: #666; font-size: 10px; background: transparent;")
        layout.addWidget(stats)


class AttackPathAnalyzerPage(QWidget):
    """Attack Path Analyzer page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.analyzer = None
        self.selected_path = None
        self.setup_ui()
        self.load_analyzer()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Attack paths list
        left_panel = self.create_paths_panel()
        splitter.addWidget(left_panel)
        
        # Right - Path details
        right_panel = self.create_details_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([450, 750])
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
        
        title = QLabel("🛤️ Attack Path Analyzer")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #e67e22; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Identify and Visualize Potential Attack Paths to Critical Assets")
        subtitle.setStyleSheet("color: #888; font-size: 12px; background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Quick stats
        self.quick_stats = {}
        stats_data = [
            ("Attack Paths", "0", "#e74c3c"),
            ("High Risk", "0", "#e67e22"),
            ("Entry Points", "0", "#3498db"),
            ("Targets", "0", "#9b59b6"),
        ]
        
        for stat_name, value, color in stats_data:
            stat_widget = QVBoxLayout()
            
            value_label = QLabel(value)
            value_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
            value_label.setStyleSheet(f"color: {color}; background: transparent;")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_widget.addWidget(value_label)
            
            name_label = QLabel(stat_name)
            name_label.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_widget.addWidget(name_label)
            
            self.quick_stats[stat_name] = value_label
            layout.addLayout(stat_widget)
            
        # Buttons
        btn_style = """
            QPushButton {
                background: %s;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 25px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: %s;
            }
        """
        
        analyze_btn = QPushButton("🔄 Re-analyze")
        analyze_btn.setStyleSheet(btn_style % ("#e67e22", "#d35400"))
        analyze_btn.clicked.connect(self.refresh_analysis)
        layout.addWidget(analyze_btn)
        
        return frame
        
    def create_paths_panel(self) -> QFrame:
        """Create attack paths panel"""
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
        header = QHBoxLayout()
        
        title = QLabel("🎯 Attack Paths")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #fff; background: transparent;")
        header.addWidget(title)
        
        header.addStretch()
        
        # Filter
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["All Paths", "High Risk (70+)", "Medium Risk (50+)", "Low Risk"])
        self.risk_filter.setStyleSheet("""
            QComboBox {
                background: #16213e;
                color: #fff;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        self.risk_filter.currentIndexChanged.connect(self.filter_paths)
        header.addWidget(self.risk_filter)
        
        layout.addLayout(header)
        
        # Paths scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.paths_container = QWidget()
        self.paths_layout = QVBoxLayout(self.paths_container)
        self.paths_layout.setSpacing(10)
        self.paths_layout.addStretch()
        
        scroll.setWidget(self.paths_container)
        layout.addWidget(scroll, 1)
        
        return frame
        
    def create_details_panel(self) -> QFrame:
        """Create path details panel"""
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
        
        # Path steps tab
        steps_widget = QWidget()
        steps_layout = QVBoxLayout(steps_widget)
        
        self.path_title = QLabel("Select a path to view details")
        self.path_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.path_title.setStyleSheet("color: #fff; background: transparent;")
        steps_layout.addWidget(self.path_title)
        
        self.path_summary = QLabel("")
        self.path_summary.setStyleSheet("color: #888; background: transparent;")
        steps_layout.addWidget(self.path_summary)
        
        steps_scroll = QScrollArea()
        steps_scroll.setWidgetResizable(True)
        steps_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.steps_container = QWidget()
        self.steps_layout = QVBoxLayout(self.steps_container)
        self.steps_layout.setSpacing(10)
        self.steps_layout.addStretch()
        
        steps_scroll.setWidget(self.steps_container)
        steps_layout.addWidget(steps_scroll, 1)
        
        tabs.addTab(steps_widget, "📋 Path Steps")
        
        # Recommendations tab
        rec_widget = QWidget()
        rec_layout = QVBoxLayout(rec_widget)
        
        rec_title = QLabel("🛡️ Mitigation Recommendations")
        rec_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        rec_title.setStyleSheet("color: #fff; background: transparent;")
        rec_layout.addWidget(rec_title)
        
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
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
        rec_layout.addWidget(self.recommendations_list)
        
        tabs.addTab(rec_widget, "🛡️ Recommendations")
        
        # MITRE tab
        mitre_widget = QWidget()
        mitre_layout = QVBoxLayout(mitre_widget)
        
        mitre_title = QLabel("🎯 MITRE ATT&CK Techniques")
        mitre_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        mitre_title.setStyleSheet("color: #fff; background: transparent;")
        mitre_layout.addWidget(mitre_title)
        
        self.mitre_list = QListWidget()
        self.mitre_list.setStyleSheet("""
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
        mitre_layout.addWidget(self.mitre_list)
        
        tabs.addTab(mitre_widget, "🎯 MITRE ATT&CK")
        
        # Network topology tab
        topology_widget = QWidget()
        topology_layout = QVBoxLayout(topology_widget)
        
        topo_title = QLabel("🗺️ Network Topology")
        topo_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        topo_title.setStyleSheet("color: #fff; background: transparent;")
        topology_layout.addWidget(topo_title)
        
        self.topology_table = QTableWidget()
        self.topology_table.setColumnCount(5)
        self.topology_table.setHorizontalHeaderLabels(["Name", "Type", "Zone", "Criticality", "Vulnerabilities"])
        self.topology_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.topology_table.setStyleSheet("""
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
        topology_layout.addWidget(self.topology_table)
        
        tabs.addTab(topology_widget, "🗺️ Topology")
        
        layout.addWidget(tabs)
        
        return frame
        
    def load_analyzer(self):
        """Load the attack path analyzer"""
        from core.attack_path_analyzer import get_attack_path_analyzer
        self.analyzer = get_attack_path_analyzer()
        self.refresh_display()
        
    def refresh_display(self):
        """Refresh all displays"""
        if not self.analyzer:
            return
            
        stats = self.analyzer.stats
        
        # Update quick stats
        self.quick_stats["Attack Paths"].setText(str(stats["paths"]))
        self.quick_stats["High Risk"].setText(str(stats["high_risk"]))
        self.quick_stats["Entry Points"].setText(str(stats["entry_points"]))
        self.quick_stats["Targets"].setText(str(stats["targets"]))
        
        # Load paths
        self.load_paths()
        
        # Load topology
        self.load_topology()
        
    def load_paths(self, min_risk: float = 0):
        """Load attack paths"""
        # Clear existing
        while self.paths_layout.count() > 1:
            item = self.paths_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Add path cards
        paths = self.analyzer.get_all_paths()
        if min_risk > 0:
            paths = [p for p in paths if p["risk_score"] >= min_risk]
            
        for path in paths[:20]:
            card = PathCard(path, on_click=self.on_path_selected)
            self.paths_layout.insertWidget(self.paths_layout.count() - 1, card)
            
    def load_topology(self):
        """Load network topology table"""
        topology = self.analyzer.get_network_topology()
        nodes = topology.get("nodes", [])
        
        self.topology_table.setRowCount(len(nodes))
        
        for i, node in enumerate(nodes):
            name_item = QTableWidgetItem(node["name"])
            if node.get("is_entry"):
                name_item.setText(f"🚪 {node['name']}")
            elif node.get("is_target"):
                name_item.setText(f"🎯 {node['name']}")
                
            type_item = QTableWidgetItem(node["type"].replace("_", " ").title())
            zone_item = QTableWidgetItem(node["zone"])
            
            crit = node["criticality"]
            crit_item = QTableWidgetItem(str(crit))
            if crit >= 8:
                crit_item.setForeground(QColor("#e74c3c"))
            elif crit >= 5:
                crit_item.setForeground(QColor("#f1c40f"))
            else:
                crit_item.setForeground(QColor("#27ae60"))
                
            vulns = node.get("vulns", [])
            vulns_item = QTableWidgetItem(str(len(vulns)) if vulns else "None")
            if vulns:
                vulns_item.setForeground(QColor("#e74c3c"))
                
            self.topology_table.setItem(i, 0, name_item)
            self.topology_table.setItem(i, 1, type_item)
            self.topology_table.setItem(i, 2, zone_item)
            self.topology_table.setItem(i, 3, crit_item)
            self.topology_table.setItem(i, 4, vulns_item)
            
    def filter_paths(self):
        """Filter paths by risk level"""
        filter_idx = self.risk_filter.currentIndex()
        
        min_risk = 0
        if filter_idx == 1:
            min_risk = 70
        elif filter_idx == 2:
            min_risk = 50
        elif filter_idx == 3:
            min_risk = 0  # Will filter for low risk below
            
        self.load_paths(min_risk)
        
    def on_path_selected(self, path_id: str):
        """Handle path selection"""
        details = self.analyzer.get_path_details(path_id)
        if not details:
            return
            
        self.selected_path = details
        
        # Update title and summary
        self.path_title.setText(f"🎯 {details['entry']} → {details['target']}")
        self.path_summary.setText(
            f"Risk Score: {details['risk_score']:.0f} | "
            f"Difficulty: {details['total_difficulty']:.0%} | "
            f"Detection Risk: {details['detection_risk']:.0%} | "
            f"Est. Time: {details['estimated_time']:.1f}h"
        )
        
        # Clear and load steps
        while self.steps_layout.count() > 1:
            item = self.steps_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        for step in details.get("steps", []):
            widget = PathStepWidget(step)
            self.steps_layout.insertWidget(self.steps_layout.count() - 1, widget)
            
        # Load recommendations
        self.recommendations_list.clear()
        for rec in details.get("recommendations", []):
            item = QListWidgetItem(f"💡 {rec}")
            self.recommendations_list.addItem(item)
            
        # Load MITRE techniques
        self.mitre_list.clear()
        for tech in details.get("mitre_techniques", []):
            item = QListWidgetItem(f"🎯 {tech}")
            self.mitre_list.addItem(item)
            
    def refresh_analysis(self):
        """Refresh the analysis"""
        self.load_analyzer()
        QMessageBox.information(
            self, "Analysis Complete",
            f"Attack path analysis refreshed!\n\n"
            f"Paths Found: {self.analyzer.stats['paths']}\n"
            f"High Risk: {self.analyzer.stats['high_risk']}"
        )
