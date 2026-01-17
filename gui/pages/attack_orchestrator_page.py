#!/usr/bin/env python3
"""
🎯 Attack Orchestrator Page - Revolutionary Visual Attack Chain Builder

UNIQUE FEATURES:
1. Drag-and-drop attack flow designer
2. Real-time attack visualization
3. AI-powered success predictions
4. Live execution monitoring
5. One-click attack chains

This is what makes HydraRecon DIFFERENT from every other tool.
"""

import sys
import os
import asyncio
import random
import math
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QLineEdit, QComboBox, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QProgressBar, QGroupBox, QGridLayout, QSpinBox, QCheckBox,
    QTabWidget, QListWidget, QListWidgetItem, QSlider, QDialog,
    QDialogButtonBox, QFormLayout, QMessageBox, QMenu, QToolTip,
    QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsEllipseItem,
    QGraphicsLineItem, QGraphicsTextItem, QGraphicsRectItem,
    QGraphicsDropShadowEffect, QApplication, QStackedWidget
)
from PyQt6.QtCore import (
    Qt, QTimer, pyqtSignal, QThread, QPropertyAnimation,
    QEasingCurve, QPointF, QRectF, QLineF, QSize, QObject
)
from PyQt6.QtGui import (
    QFont, QColor, QPainter, QPen, QBrush, QLinearGradient,
    QRadialGradient, QPainterPath, QPolygonF, QTransform,
    QCursor, QAction
)

# Import orchestrator
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.attack_orchestrator import (
        AttackOrchestrator, AttackChain, AttackNode, AttackNodeType,
        AttackPhase, ThreatLevel, AttackTemplates, get_orchestrator
    )
except ImportError:
    AttackOrchestrator = None


class AttackNodeItem(QGraphicsEllipseItem):
    """Visual representation of an attack node"""
    
    def __init__(self, node_data: Dict, x: float, y: float):
        super().__init__(-40, -40, 80, 80)
        self.node_data = node_data
        self.setPos(x, y)
        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setZValue(10)
        
        self._setup_appearance()
        self._add_labels()
        self._add_glow()
        self.animation_angle = 0
    
    def _setup_appearance(self):
        """Set up node appearance based on type and status"""
        node_type = self.node_data.get("type", "scan")
        status = self.node_data.get("status", "pending")
        
        # Colors by node type
        type_colors = {
            "target": "#ff4444",
            "scan": "#0088ff",
            "exploit": "#ff8800",
            "payload": "#ff0088",
            "post_exploit": "#8800ff",
            "pivot": "#00ff88",
            "exfil": "#ffff00",
            "condition": "#888888",
            "delay": "#444444",
            "script": "#00ffff"
        }
        
        base_color = type_colors.get(node_type, "#0088ff")
        
        # Status affects opacity/outline
        if status == "running":
            pen_color = "#00ff88"
            pen_width = 4
        elif status == "success":
            pen_color = "#00ff88"
            pen_width = 3
        elif status == "failed":
            pen_color = "#ff4444"
            pen_width = 3
        else:
            pen_color = "#ffffff"
            pen_width = 2
        
        # Create gradient
        gradient = QRadialGradient(0, 0, 40)
        color = QColor(base_color)
        gradient.setColorAt(0, color.lighter(150))
        gradient.setColorAt(0.5, color)
        gradient.setColorAt(1, color.darker(150))
        
        self.setBrush(QBrush(gradient))
        self.setPen(QPen(QColor(pen_color), pen_width))
    
    def _add_labels(self):
        """Add text labels to node"""
        # Node name
        name_text = QGraphicsTextItem(self.node_data.get("label", "Node")[:12], self)
        name_text.setDefaultTextColor(QColor("#ffffff"))
        name_text.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
        name_rect = name_text.boundingRect()
        name_text.setPos(-name_rect.width() / 2, -10)
        
        # Success probability badge
        success_prob = self.node_data.get("success_probability", 0)
        prob_text = QGraphicsTextItem(f"{int(success_prob * 100)}%", self)
        
        if success_prob > 0.7:
            prob_color = "#00ff88"
        elif success_prob > 0.4:
            prob_color = "#ffaa00"
        else:
            prob_color = "#ff4444"
        
        prob_text.setDefaultTextColor(QColor(prob_color))
        prob_text.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        prob_rect = prob_text.boundingRect()
        prob_text.setPos(-prob_rect.width() / 2, 10)
        
        # Technique ID
        technique = self.node_data.get("technique_id", "")
        if technique:
            tech_text = QGraphicsTextItem(technique, self)
            tech_text.setDefaultTextColor(QColor("#888888"))
            tech_text.setFont(QFont("Consolas", 6))
            tech_rect = tech_text.boundingRect()
            tech_text.setPos(-tech_rect.width() / 2, -35)
    
    def _add_glow(self):
        """Add glow effect"""
        effect = QGraphicsDropShadowEffect()
        effect.setBlurRadius(20)
        effect.setColor(QColor(self.pen().color()))
        effect.setOffset(0, 0)
        self.setGraphicsEffect(effect)
    
    def hoverEnterEvent(self, event):
        """Show tooltip on hover"""
        self.setScale(1.15)
        tooltip = f"""
<b>{self.node_data.get('label', 'Node')}</b><br>
Type: {self.node_data.get('type', 'unknown')}<br>
Phase: {self.node_data.get('phase', 'unknown')}<br>
Success: {int(self.node_data.get('success_probability', 0) * 100)}%<br>
Detection Risk: {int(self.node_data.get('detection_probability', 0) * 100)}%<br>
Technique: {self.node_data.get('technique_id', 'N/A')}
        """
        QToolTip.showText(event.screenPos().toPoint(), tooltip.strip())
        super().hoverEnterEvent(event)
    
    def hoverLeaveEvent(self, event):
        self.setScale(1.0)
        QToolTip.hideText()
        super().hoverLeaveEvent(event)
    
    def update_status(self, status: str):
        """Update node status with animation"""
        self.node_data["status"] = status
        self._setup_appearance()


class AttackEdgeItem(QGraphicsLineItem):
    """Visual connection between attack nodes"""
    
    def __init__(self, start_pos: QPointF, end_pos: QPointF, edge_type: str = "success"):
        super().__init__(QLineF(start_pos, end_pos))
        self.edge_type = edge_type
        self.setZValue(5)
        self._setup_appearance()
    
    def _setup_appearance(self):
        if self.edge_type == "success":
            color = QColor("#00ff88")
        else:
            color = QColor("#ff4444")
        
        pen = QPen(color, 3)
        pen.setStyle(Qt.PenStyle.SolidLine)
        self.setPen(pen)


class AttackFlowCanvas(QGraphicsView):
    """
    Main canvas for visualizing and editing attack chains
    """
    
    node_clicked = pyqtSignal(dict)
    node_double_clicked = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        
        self._setup_background()
        
        self.nodes: Dict[str, AttackNodeItem] = {}
        self.edges: List[AttackEdgeItem] = []
        
        # Animation timer
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self._animate)
        self.animation_timer.start(50)
        self.animation_frame = 0
    
    def _setup_background(self):
        """Set up dark grid background"""
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0a0a12;
                border: 2px solid #1a1a2e;
                border-radius: 10px;
            }
        """)
        self.scene.setBackgroundBrush(QBrush(QColor("#0a0a12")))
    
    def load_chain(self, visualization_data: Dict):
        """Load attack chain visualization"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        
        if not visualization_data:
            return
        
        nodes_data = visualization_data.get("nodes", [])
        edges_data = visualization_data.get("edges", [])
        
        # Calculate layout
        phases = {}
        for node in nodes_data:
            phase = node.get("phase", "unknown")
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(node)
        
        # Position nodes by phase
        phase_order = [
            "reconnaissance", "resource_development", "initial_access",
            "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery",
            "lateral_movement", "collection", "command_and_control",
            "exfiltration", "impact"
        ]
        
        x_offset = 100
        for phase in phase_order:
            if phase in phases:
                y_offset = 100
                for node in phases[phase]:
                    node_item = AttackNodeItem(node, x_offset, y_offset)
                    self.scene.addItem(node_item)
                    self.nodes[node["id"]] = node_item
                    y_offset += 120
                x_offset += 200
        
        # Draw edges
        for edge in edges_data:
            from_id = edge.get("from")
            to_id = edge.get("to")
            
            if from_id in self.nodes and to_id in self.nodes:
                from_pos = self.nodes[from_id].scenePos()
                to_pos = self.nodes[to_id].scenePos()
                
                edge_item = AttackEdgeItem(from_pos, to_pos, edge.get("type", "success"))
                self.scene.addItem(edge_item)
                self.edges.append(edge_item)
        
        # Draw grid
        self._draw_grid()
        
        # Fit view
        self.fitInView(self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50), Qt.AspectRatioMode.KeepAspectRatio)
    
    def _draw_grid(self):
        """Draw background grid"""
        pen = QPen(QColor("#1a1a2e"), 1)
        
        for x in range(-500, 2000, 50):
            line = self.scene.addLine(x, -500, x, 1500, pen)
            line.setZValue(0)
        
        for y in range(-500, 1500, 50):
            line = self.scene.addLine(-500, y, 2000, y, pen)
            line.setZValue(0)
    
    def _animate(self):
        """Animation loop for running nodes"""
        self.animation_frame += 1
        
        for node_id, node_item in self.nodes.items():
            if node_item.node_data.get("status") == "running":
                # Pulsing effect
                scale = 1.0 + 0.1 * math.sin(self.animation_frame * 0.2)
                node_item.setScale(scale)
    
    def update_node_status(self, node_id: str, status: str):
        """Update a node's visual status"""
        if node_id in self.nodes:
            self.nodes[node_id].update_status(status)
    
    def wheelEvent(self, event):
        """Zoom with mouse wheel"""
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)


class AttackExecutionWorker(QThread):
    """Background worker for executing attack chains"""
    
    node_started = pyqtSignal(str, dict)
    node_completed = pyqtSignal(str, dict)
    chain_completed = pyqtSignal(dict)
    log_message = pyqtSignal(str)
    stats_updated = pyqtSignal(dict)
    
    def __init__(self, orchestrator: 'AttackOrchestrator', chain_id: str, dry_run: bool = True):
        super().__init__()
        self.orchestrator = orchestrator
        self.chain_id = chain_id
        self.dry_run = dry_run
        self._running = True
    
    def run(self):
        """Execute the attack chain"""
        # Set up callbacks
        self.orchestrator.on_node_started = lambda c, n: self.node_started.emit(n.id, {
            "name": n.name,
            "type": n.node_type.value,
            "phase": n.phase.value
        })
        
        self.orchestrator.on_node_completed = lambda c, n: self.node_completed.emit(n.id, {
            "name": n.name,
            "status": n.status,
            "output": n.output
        })
        
        self.orchestrator.on_chain_completed = lambda c, r: self.chain_completed.emit(r)
        
        # Run async execution
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                self.orchestrator.execute_chain(self.chain_id, self.dry_run)
            )
            self.chain_completed.emit(result)
        except Exception as e:
            self.log_message.emit(f"❌ Error: {str(e)}")
        finally:
            loop.close()
    
    def stop(self):
        self._running = False
        self.orchestrator.stop_execution()


class AttackOrchestratorPage(QWidget):
    """
    🎯 Attack Orchestrator Page
    
    The UNIQUE feature that sets HydraRecon apart from every other tool:
    - Visual attack chain builder
    - AI-powered predictions
    - One-click exploitation
    - Real-time monitoring
    """
    
    def __init__(self, config=None, db=None):
        super().__init__()
        self.config = config or {}
        self.db = db
        
        # Get orchestrator
        self.orchestrator = get_orchestrator() if AttackOrchestrator else None
        self.current_chain_id: Optional[str] = None
        self.worker: Optional[AttackExecutionWorker] = None
        
        self._setup_ui()
        self._connect_signals()
        
        # Load demo if no orchestrator
        if not self.orchestrator:
            self._load_demo_mode()
    
    def _setup_ui(self):
        """Set up the UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content area
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Templates and Nodes
        left_panel = self._create_left_panel()
        main_splitter.addWidget(left_panel)
        
        # Center - Attack Flow Canvas
        center_panel = self._create_center_panel()
        main_splitter.addWidget(center_panel)
        
        # Right panel - Properties and Stats
        right_panel = self._create_right_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setSizes([250, 600, 300])
        layout.addWidget(main_splitter)
        
        # Bottom - Execution Log
        bottom_panel = self._create_bottom_panel()
        layout.addWidget(bottom_panel)
        
        self.setStyleSheet(self._get_stylesheet())
    
    def _create_header(self) -> QFrame:
        """Create header with title and stats"""
        header = QFrame()
        header.setObjectName("headerFrame")
        layout = QHBoxLayout(header)
        
        # Title
        title_layout = QVBoxLayout()
        
        title = QLabel("🎯 AI Attack Orchestrator")
        title.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Visual Attack Chain Builder with AI-Powered Predictions")
        subtitle.setStyleSheet("color: #888888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Quick Stats
        stats_layout = QHBoxLayout()
        
        self.stat_chains = self._create_stat_card("Attack Chains", "0", "#0088ff")
        self.stat_success = self._create_stat_card("Success Rate", "0%", "#00ff88")
        self.stat_credentials = self._create_stat_card("Credentials", "0", "#ff8800")
        self.stat_shells = self._create_stat_card("Shells", "0", "#ff0088")
        
        stats_layout.addWidget(self.stat_chains)
        stats_layout.addWidget(self.stat_success)
        stats_layout.addWidget(self.stat_credentials)
        stats_layout.addWidget(self.stat_shells)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a stat card"""
        card = QFrame()
        card.setObjectName("statCard")
        card.setStyleSheet(f"""
            QFrame#statCard {{
                background: rgba(20, 20, 40, 0.8);
                border: 1px solid {color};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Consolas", 18, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #888888; font-size: 10px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        card.value_label = value_label
        
        return card
    
    def _create_left_panel(self) -> QFrame:
        """Create left panel with templates and node types"""
        panel = QFrame()
        panel.setObjectName("leftPanel")
        layout = QVBoxLayout(panel)
        
        # Templates section
        templates_group = QGroupBox("⚡ Quick Templates")
        templates_layout = QVBoxLayout(templates_group)
        
        templates = [
            ("🌐 Web App Compromise", "web_app", "SQL → RCE → Shell → Persist"),
            ("🖥️ Network Penetration", "network", "Scan → Exploit → Pivot → DA"),
            ("☁️ Cloud Attack", "cloud", "SSRF → IAM → Exfil"),
            ("📱 Mobile App Test", "mobile", "Decompile → MITM → API"),
            ("🔒 Red Team Full", "redteam", "Complete enterprise compromise")
        ]
        
        for name, template_id, desc in templates:
            btn = QPushButton(name)
            btn.setToolTip(desc)
            btn.setProperty("template_id", template_id)
            btn.clicked.connect(lambda checked, t=template_id: self._load_template(t))
            templates_layout.addWidget(btn)
        
        layout.addWidget(templates_group)
        
        # Node Types section
        nodes_group = QGroupBox("🔧 Node Types")
        nodes_layout = QVBoxLayout(nodes_group)
        
        node_types = [
            ("🎯 Target", "target", "#ff4444"),
            ("🔍 Scan", "scan", "#0088ff"),
            ("💥 Exploit", "exploit", "#ff8800"),
            ("📦 Payload", "payload", "#ff0088"),
            ("🔓 Post-Exploit", "post_exploit", "#8800ff"),
            ("↔️ Pivot", "pivot", "#00ff88"),
            ("📤 Exfiltrate", "exfil", "#ffff00"),
        ]
        
        for name, node_type, color in node_types:
            btn = QPushButton(name)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: rgba(20, 20, 40, 0.8);
                    border: 1px solid {color};
                    border-radius: 5px;
                    color: {color};
                    padding: 8px;
                    text-align: left;
                }}
                QPushButton:hover {{
                    background: {color}33;
                }}
            """)
            btn.setCursor(QCursor(Qt.CursorShape.OpenHandCursor))
            nodes_layout.addWidget(btn)
        
        layout.addWidget(nodes_group)
        layout.addStretch()
        
        return panel
    
    def _create_center_panel(self) -> QFrame:
        """Create center panel with attack flow canvas"""
        panel = QFrame()
        panel.setObjectName("centerPanel")
        layout = QVBoxLayout(panel)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        # Target input
        target_label = QLabel("Target:")
        target_label.setStyleSheet("color: #888888;")
        toolbar.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target IP/domain...")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: rgba(20, 20, 40, 0.8);
                border: 1px solid #333;
                border-radius: 5px;
                color: #00ff88;
                padding: 8px;
                font-family: Consolas;
            }
        """)
        toolbar.addWidget(self.target_input)
        
        toolbar.addStretch()
        
        # Control buttons
        self.btn_execute = QPushButton("▶ Execute Chain")
        self.btn_execute.setObjectName("executeBtn")
        self.btn_execute.clicked.connect(self._execute_chain)
        toolbar.addWidget(self.btn_execute)
        
        self.btn_pause = QPushButton("⏸ Pause")
        self.btn_pause.clicked.connect(self._pause_execution)
        self.btn_pause.setEnabled(False)
        toolbar.addWidget(self.btn_pause)
        
        self.btn_stop = QPushButton("⏹ Stop")
        self.btn_stop.clicked.connect(self._stop_execution)
        self.btn_stop.setEnabled(False)
        toolbar.addWidget(self.btn_stop)
        
        layout.addLayout(toolbar)
        
        # Attack Flow Canvas
        self.canvas = AttackFlowCanvas()
        layout.addWidget(self.canvas)
        
        # Chain info bar
        info_bar = QHBoxLayout()
        
        self.chain_name_label = QLabel("No chain loaded")
        self.chain_name_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        info_bar.addWidget(self.chain_name_label)
        
        info_bar.addStretch()
        
        self.success_probability_label = QLabel("Success: --%")
        self.success_probability_label.setStyleSheet("color: #888888;")
        info_bar.addWidget(self.success_probability_label)
        
        self.stealth_label = QLabel("Stealth: --%")
        self.stealth_label.setStyleSheet("color: #888888;")
        info_bar.addWidget(self.stealth_label)
        
        self.time_label = QLabel("Est. Time: --")
        self.time_label.setStyleSheet("color: #888888;")
        info_bar.addWidget(self.time_label)
        
        layout.addLayout(info_bar)
        
        return panel
    
    def _create_right_panel(self) -> QFrame:
        """Create right panel with properties and AI analysis"""
        panel = QFrame()
        panel.setObjectName("rightPanel")
        layout = QVBoxLayout(panel)
        
        # AI Analysis
        ai_group = QGroupBox("🧠 AI Analysis")
        ai_layout = QVBoxLayout(ai_group)
        
        self.ai_recommendation = QTextEdit()
        self.ai_recommendation.setReadOnly(True)
        self.ai_recommendation.setStyleSheet("""
            QTextEdit {
                background: rgba(0, 255, 136, 0.1);
                border: 1px solid #00ff88;
                border-radius: 5px;
                color: #00ff88;
                font-family: Consolas;
                font-size: 11px;
            }
        """)
        self.ai_recommendation.setMaximumHeight(150)
        self.ai_recommendation.setText("""🎯 AI ANALYSIS

Load an attack template or create a chain to see AI-powered recommendations.

The AI will analyze:
• Target vulnerabilities
• Success probability
• Detection risk
• Optimal attack path
• Evasion techniques
        """)
        ai_layout.addWidget(self.ai_recommendation)
        
        layout.addWidget(ai_group)
        
        # Node Properties
        props_group = QGroupBox("📋 Selected Node")
        props_layout = QFormLayout(props_group)
        
        self.prop_name = QLabel("-")
        self.prop_type = QLabel("-")
        self.prop_phase = QLabel("-")
        self.prop_technique = QLabel("-")
        self.prop_success = QLabel("-")
        self.prop_detection = QLabel("-")
        
        props_layout.addRow("Name:", self.prop_name)
        props_layout.addRow("Type:", self.prop_type)
        props_layout.addRow("Phase:", self.prop_phase)
        props_layout.addRow("MITRE:", self.prop_technique)
        props_layout.addRow("Success:", self.prop_success)
        props_layout.addRow("Detection:", self.prop_detection)
        
        layout.addWidget(props_group)
        
        # Results
        results_group = QGroupBox("🏆 Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_list = QListWidget()
        self.results_list.setStyleSheet("""
            QListWidget {
                background: rgba(20, 20, 40, 0.8);
                border: 1px solid #333;
                border-radius: 5px;
                color: #ffffff;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333;
            }
            QListWidget::item:selected {
                background: rgba(0, 255, 136, 0.2);
            }
        """)
        results_layout.addWidget(self.results_list)
        
        layout.addWidget(results_group)
        
        return panel
    
    def _create_bottom_panel(self) -> QFrame:
        """Create bottom panel with execution log"""
        panel = QFrame()
        panel.setObjectName("bottomPanel")
        panel.setMaximumHeight(200)
        layout = QVBoxLayout(panel)
        
        # Header
        header = QHBoxLayout()
        header.addWidget(QLabel("📜 Execution Log"))
        header.addStretch()
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.execution_log.clear())
        header.addWidget(clear_btn)
        
        layout.addLayout(header)
        
        # Log output
        self.execution_log = QTextEdit()
        self.execution_log.setReadOnly(True)
        self.execution_log.setStyleSheet("""
            QTextEdit {
                background: #0a0a12;
                border: 1px solid #1a1a2e;
                border-radius: 5px;
                color: #00ff88;
                font-family: Consolas;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.execution_log)
        
        return panel
    
    def _connect_signals(self):
        """Connect signals"""
        pass
    
    def _get_stylesheet(self) -> str:
        """Get page stylesheet"""
        return """
            QWidget {
                background: #0f0f1a;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
            }
            
            QFrame#headerFrame {
                background: rgba(20, 20, 40, 0.8);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#leftPanel, QFrame#rightPanel {
                background: rgba(20, 20, 40, 0.5);
                border-radius: 10px;
                padding: 10px;
            }
            
            QFrame#centerPanel {
                background: rgba(10, 10, 20, 0.8);
                border-radius: 10px;
                padding: 10px;
            }
            
            QFrame#bottomPanel {
                background: rgba(20, 20, 40, 0.5);
                border-radius: 10px;
                padding: 10px;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                color: #00ff88;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            
            QPushButton {
                background: rgba(30, 30, 50, 0.8);
                border: 1px solid #444;
                border-radius: 5px;
                color: #ffffff;
                padding: 8px 15px;
            }
            
            QPushButton:hover {
                background: rgba(0, 255, 136, 0.2);
                border-color: #00ff88;
            }
            
            QPushButton#executeBtn {
                background: rgba(0, 255, 136, 0.3);
                border: 2px solid #00ff88;
                color: #00ff88;
                font-weight: bold;
            }
            
            QPushButton#executeBtn:hover {
                background: rgba(0, 255, 136, 0.5);
            }
            
            QLabel {
                color: #ffffff;
            }
        """
    
    def _load_template(self, template_id: str):
        """Load an attack template"""
        target = self.target_input.text() or "192.168.1.100"
        
        if self.orchestrator:
            chain = self.orchestrator.create_chain(
                name=f"{template_id.replace('_', ' ').title()} Attack",
                target=target,
                template=template_id
            )
            self.current_chain_id = chain.id
            
            # Load visualization
            viz_data = self.orchestrator.get_chain_visualization(chain.id)
            self.canvas.load_chain(viz_data)
            
            # Update info
            self.chain_name_label.setText(f"🔗 {chain.name}")
            self.success_probability_label.setText(f"Success: {int(chain.overall_success_rate * 100)}%")
            self.stealth_label.setText(f"Stealth: {int(chain.stealth_rating)}%")
            self.time_label.setText(f"Est. Time: {chain.estimated_time}s")
            
            # Update AI recommendation
            self.ai_recommendation.setText(f"""🧠 AI ANALYSIS - {chain.name}

📊 Overall Success Probability: {int(chain.overall_success_rate * 100)}%
🥷 Stealth Rating: {int(chain.stealth_rating)}/100
⏱️ Estimated Time: {chain.estimated_time} seconds
⚠️ Risk Level: {chain.risk_level.name}

🎯 RECOMMENDATION:
{self._get_ai_recommendation(chain)}

📋 Attack Phases:
{self._get_phase_summary(chain)}
            """)
            
            self._log(f"✅ Loaded template: {template_id}")
            self._log(f"🎯 Target: {target}")
            self._log(f"📊 {len(chain.nodes)} attack nodes configured")
        else:
            self._load_demo_visualization(template_id, target)
    
    def _get_ai_recommendation(self, chain: AttackChain) -> str:
        """Generate AI recommendation text"""
        if chain.overall_success_rate > 0.7:
            return "🟢 HIGH CONFIDENCE - This attack chain has excellent success probability. Proceed with standard evasion."
        elif chain.overall_success_rate > 0.5:
            return "🟡 MODERATE CONFIDENCE - Success is likely. Consider additional reconnaissance."
        else:
            return "🔴 LOW CONFIDENCE - Success uncertain. Recommend alternative attack vectors."
    
    def _get_phase_summary(self, chain: AttackChain) -> str:
        """Generate phase summary"""
        phases = {}
        for node in chain.nodes.values():
            phase = node.phase.value
            if phase not in phases:
                phases[phase] = 0
            phases[phase] += 1
        
        return "\n".join([f"  • {phase}: {count} nodes" for phase, count in phases.items()])
    
    def _load_demo_visualization(self, template_id: str, target: str):
        """Load demo visualization when orchestrator not available"""
        demo_data = {
            "chain_id": "demo",
            "name": f"{template_id.title()} Demo",
            "target": target,
            "overall_success": 0.75,
            "stealth_rating": 65,
            "estimated_time": 180,
            "nodes": [
                {"id": "1", "label": "Port Scan", "type": "scan", "phase": "reconnaissance", "success_probability": 0.95, "detection_probability": 0.3, "technique_id": "T1595", "status": "pending"},
                {"id": "2", "label": "Web Fingerprint", "type": "scan", "phase": "reconnaissance", "success_probability": 0.90, "detection_probability": 0.2, "technique_id": "T1592", "status": "pending"},
                {"id": "3", "label": "SQL Injection", "type": "exploit", "phase": "initial_access", "success_probability": 0.70, "detection_probability": 0.5, "technique_id": "T1190", "status": "pending"},
                {"id": "4", "label": "Web Shell", "type": "payload", "phase": "execution", "success_probability": 0.80, "detection_probability": 0.6, "technique_id": "T1505.003", "status": "pending"},
                {"id": "5", "label": "Reverse Shell", "type": "payload", "phase": "execution", "success_probability": 0.75, "detection_probability": 0.7, "technique_id": "T1059", "status": "pending"},
                {"id": "6", "label": "Privilege Esc", "type": "post_exploit", "phase": "privilege_escalation", "success_probability": 0.60, "detection_probability": 0.5, "technique_id": "T1068", "status": "pending"},
                {"id": "7", "label": "Persistence", "type": "post_exploit", "phase": "persistence", "success_probability": 0.85, "detection_probability": 0.4, "technique_id": "T1053", "status": "pending"},
            ],
            "edges": [
                {"from": "1", "to": "2", "type": "success"},
                {"from": "2", "to": "3", "type": "success"},
                {"from": "3", "to": "4", "type": "success"},
                {"from": "4", "to": "5", "type": "success"},
                {"from": "5", "to": "6", "type": "success"},
                {"from": "6", "to": "7", "type": "success"},
            ],
            "entry_points": ["1"],
            "status": "ready"
        }
        
        self.canvas.load_chain(demo_data)
        self.chain_name_label.setText(f"🔗 {demo_data['name']}")
        self.success_probability_label.setText(f"Success: {int(demo_data['overall_success'] * 100)}%")
        self.stealth_label.setText(f"Stealth: {demo_data['stealth_rating']}%")
        self.time_label.setText(f"Est. Time: {demo_data['estimated_time']}s")
        
        self._log("⚠️ Demo mode - AI orchestrator not fully loaded")
        self._log(f"✅ Loaded demo template: {template_id}")
    
    def _execute_chain(self):
        """Execute the attack chain"""
        if not self.current_chain_id and not self.orchestrator:
            # Demo mode execution
            self._execute_demo()
            return
        
        if self.orchestrator and self.current_chain_id:
            self.btn_execute.setEnabled(False)
            self.btn_pause.setEnabled(True)
            self.btn_stop.setEnabled(True)
            
            self._log("🚀 Starting attack chain execution...")
            
            self.worker = AttackExecutionWorker(
                self.orchestrator,
                self.current_chain_id,
                dry_run=True  # Safe mode for demo
            )
            
            self.worker.node_started.connect(self._on_node_started)
            self.worker.node_completed.connect(self._on_node_completed)
            self.worker.chain_completed.connect(self._on_chain_completed)
            self.worker.log_message.connect(self._log)
            
            self.worker.start()
    
    def _execute_demo(self):
        """Execute demo animation"""
        self._log("🚀 Starting demo execution...")
        self.btn_execute.setEnabled(False)
        
        # Animate nodes sequentially
        nodes = list(self.canvas.nodes.keys())
        self._animate_demo_execution(nodes, 0)
    
    def _animate_demo_execution(self, nodes: List[str], index: int):
        """Animate demo execution"""
        if index >= len(nodes):
            self._log("✅ Demo execution complete!")
            self.btn_execute.setEnabled(True)
            self.results_list.addItem("🏆 Demo attack chain completed")
            self.results_list.addItem("🔑 Found: admin:password123")
            self.results_list.addItem("🖥️ Shell: 192.168.1.100:4444")
            return
        
        node_id = nodes[index]
        self.canvas.update_node_status(node_id, "running")
        self._log(f"▶ Executing: {self.canvas.nodes[node_id].node_data.get('label', 'Node')}")
        
        QTimer.singleShot(1500, lambda: self._demo_node_complete(nodes, index))
    
    def _demo_node_complete(self, nodes: List[str], index: int):
        """Complete demo node"""
        node_id = nodes[index]
        success = random.random() > 0.2
        
        self.canvas.update_node_status(node_id, "success" if success else "failed")
        status_icon = "✅" if success else "❌"
        self._log(f"{status_icon} Completed: {self.canvas.nodes[node_id].node_data.get('label', 'Node')}")
        
        self._animate_demo_execution(nodes, index + 1)
    
    def _on_node_started(self, node_id: str, data: Dict):
        """Handle node started"""
        self.canvas.update_node_status(node_id, "running")
        self._log(f"▶ {data['name']} ({data['phase']})")
    
    def _on_node_completed(self, node_id: str, data: Dict):
        """Handle node completed"""
        self.canvas.update_node_status(node_id, data['status'])
        icon = "✅" if data['status'] == "success" else "❌"
        self._log(f"{icon} {data['name']}: {data['status']}")
    
    def _on_chain_completed(self, results: Dict):
        """Handle chain completed"""
        self.btn_execute.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        
        self._log("=" * 50)
        self._log(f"🏁 Chain execution complete!")
        self._log(f"📊 Nodes executed: {results.get('nodes_executed', 0)}")
        self._log(f"✅ Successful: {results.get('nodes_successful', 0)}")
        self._log(f"❌ Failed: {results.get('nodes_failed', 0)}")
        
        # Add results
        for cred in results.get('credentials', []):
            self.results_list.addItem(f"🔑 {cred['username']}:{cred['password']}")
        
        for shell in results.get('shells', []):
            self.results_list.addItem(f"🖥️ Shell: {shell['target']}")
        
        # Update stats
        if self.orchestrator:
            stats = self.orchestrator.get_statistics()
            self.stat_chains.value_label.setText(str(stats['total_chains']))
            self.stat_success.value_label.setText(f"{stats['success_rate']:.0f}%")
            self.stat_credentials.value_label.setText(str(stats['credentials_harvested']))
            self.stat_shells.value_label.setText(str(stats['systems_compromised']))
    
    def _pause_execution(self):
        """Pause execution"""
        if self.orchestrator:
            self.orchestrator.pause_execution()
            self._log("⏸ Execution paused")
            self.btn_pause.setText("▶ Resume")
            self.btn_pause.clicked.disconnect()
            self.btn_pause.clicked.connect(self._resume_execution)
    
    def _resume_execution(self):
        """Resume execution"""
        if self.orchestrator:
            self.orchestrator.resume_execution()
            self._log("▶ Execution resumed")
            self.btn_pause.setText("⏸ Pause")
            self.btn_pause.clicked.disconnect()
            self.btn_pause.clicked.connect(self._pause_execution)
    
    def _stop_execution(self):
        """Stop execution"""
        if self.worker:
            self.worker.stop()
        if self.orchestrator:
            self.orchestrator.stop_execution()
        
        self._log("⏹ Execution stopped")
        self.btn_execute.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
    
    def _log(self, message: str):
        """Add message to execution log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.execution_log.append(f"[{timestamp}] {message}")
    
    def _load_demo_mode(self):
        """Load demo mode when orchestrator not available"""
        self._log("⚠️ Running in demo mode")
        self._log("💡 Select a template to visualize attack flows")
