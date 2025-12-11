"""
HydraRecon Threat Modeling Page
Enterprise threat modeling and risk assessment interface
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QLineEdit, QTextEdit,
    QComboBox, QGroupBox, QFormLayout, QHeaderView, QSplitter,
    QTreeWidget, QTreeWidgetItem, QDialog, QDialogButtonBox,
    QSpinBox, QDoubleSpinBox, QListWidget, QListWidgetItem,
    QCheckBox, QProgressBar, QFrame, QScrollArea, QGridLayout,
    QMessageBox, QStackedWidget, QToolButton, QSlider
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon, QPainter, QPen, QBrush
from datetime import datetime
import asyncio

try:
    from core.threat_modeling import (
        ThreatModelingEngine, Asset, DataFlow, TrustBoundary,
        Threat, Mitigation, ThreatModel, AttackTree, DREADScore,
        ThreatCategory, AssetType, ThreatStatus, MitigationStatus,
        SeverityLevel, ModelType
    )
except ImportError:
    ThreatModelingEngine = None


class ThreatModelingPage(QWidget):
    """Threat Modeling Page"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = ThreatModelingEngine() if ThreatModelingEngine else None
        self.current_model = None
        self.setup_ui()
        self.load_data()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3a3a5a;
                background: #1a1a2e;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #252540;
                color: #8888aa;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #1a1a2e;
                color: #00d4ff;
            }
            QTabBar::tab:hover:!selected {
                background: #2a2a4a;
            }
        """)
        
        # Add tabs
        self.tabs.addTab(self.create_models_tab(), "📋 Threat Models")
        self.tabs.addTab(self.create_assets_tab(), "🏛️ Assets & Boundaries")
        self.tabs.addTab(self.create_dataflows_tab(), "🔀 Data Flows")
        self.tabs.addTab(self.create_threats_tab(), "⚠️ Threats")
        self.tabs.addTab(self.create_mitigations_tab(), "🛡️ Mitigations")
        self.tabs.addTab(self.create_analysis_tab(), "📊 Analysis")
        
        layout.addWidget(self.tabs)
    
    def create_header(self) -> QWidget:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:1 #2a2a4a);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_section = QVBoxLayout()
        
        title = QLabel("🎯 Threat Modeling Framework")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        title_section.addWidget(title)
        
        subtitle = QLabel("STRIDE-based threat identification and risk assessment")
        subtitle.setStyleSheet("color: #8888aa; font-size: 12px;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Model selector
        model_layout = QHBoxLayout()
        
        model_label = QLabel("Model:")
        model_label.setStyleSheet("color: #8888aa;")
        model_layout.addWidget(model_label)
        
        self.model_selector = QComboBox()
        self.model_selector.setMinimumWidth(200)
        self.model_selector.setStyleSheet(self.get_combo_style())
        self.model_selector.currentIndexChanged.connect(self.on_model_changed)
        model_layout.addWidget(self.model_selector)
        
        layout.addLayout(model_layout)
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        new_model_btn = QPushButton("📋 New Model")
        new_model_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        new_model_btn.clicked.connect(self.new_model_dialog)
        actions_layout.addWidget(new_model_btn)
        
        analyze_btn = QPushButton("🔍 Auto-Analyze")
        analyze_btn.setStyleSheet(self.get_action_button_style("#00ff88"))
        analyze_btn.clicked.connect(self.auto_analyze)
        actions_layout.addWidget(analyze_btn)
        
        export_btn = QPushButton("📤 Export")
        export_btn.setStyleSheet(self.get_action_button_style("#ff6b6b"))
        export_btn.clicked.connect(self.export_model)
        actions_layout.addWidget(export_btn)
        
        layout.addLayout(actions_layout)
        
        return header
    
    def create_models_tab(self) -> QWidget:
        """Create threat models tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Model cards grid
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        models_widget = QWidget()
        self.models_grid = QGridLayout(models_widget)
        self.models_grid.setSpacing(15)
        
        # Add sample model cards
        self.refresh_model_cards()
        
        scroll.setWidget(models_widget)
        layout.addWidget(scroll)
        
        return widget
    
    def refresh_model_cards(self):
        """Refresh model cards in grid"""
        # Clear existing
        while self.models_grid.count():
            item = self.models_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Add "New Model" card
        new_card = self.create_new_model_card()
        self.models_grid.addWidget(new_card, 0, 0)
        
        # Add existing models
        if self.engine:
            row, col = 0, 1
            for model in self.engine.models.values():
                card = self.create_model_card(model)
                self.models_grid.addWidget(card, row, col)
                col += 1
                if col >= 3:
                    col = 0
                    row += 1
    
    def create_new_model_card(self) -> QWidget:
        """Create new model card"""
        card = QFrame()
        card.setFixedSize(300, 200)
        card.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 2px dashed #3a3a5a;
                border-radius: 10px;
            }
            QFrame:hover {
                border-color: #00d4ff;
            }
        """)
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        
        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        icon = QLabel("➕")
        icon.setFont(QFont("Segoe UI", 36))
        icon.setStyleSheet("color: #3a3a5a;")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)
        
        text = QLabel("Create New Model")
        text.setStyleSheet("color: #8888aa; font-size: 14px;")
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text)
        
        card.mousePressEvent = lambda e: self.new_model_dialog()
        
        return card
    
    def create_model_card(self, model: ThreatModel) -> QWidget:
        """Create model card widget"""
        card = QFrame()
        card.setFixedSize(300, 200)
        card.setStyleSheet("""
            QFrame {
                background: #252540;
                border: 1px solid #3a3a5a;
                border-radius: 10px;
            }
            QFrame:hover {
                border-color: #00d4ff;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Header
        header = QHBoxLayout()
        
        type_label = QLabel(model.model_type.value.upper())
        type_label.setStyleSheet("""
            background: #00d4ff;
            color: #0a0a1a;
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
        """)
        header.addWidget(type_label)
        header.addStretch()
        
        version = QLabel(f"v{model.version}")
        version.setStyleSheet("color: #8888aa; font-size: 10px;")
        header.addWidget(version)
        
        layout.addLayout(header)
        
        # Title
        title = QLabel(model.name)
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: white;")
        title.setWordWrap(True)
        layout.addWidget(title)
        
        # Stats
        stats_layout = QGridLayout()
        
        stats = [
            ("Assets", len(model.assets)),
            ("Threats", len(model.threats)),
            ("Mitigations", len(model.mitigations)),
            ("Risk", f"{model.overall_risk_score:.0f}%")
        ]
        
        for i, (label, value) in enumerate(stats):
            l = QLabel(label)
            l.setStyleSheet("color: #8888aa; font-size: 10px;")
            stats_layout.addWidget(l, 0, i)
            
            v = QLabel(str(value))
            v.setStyleSheet("color: #00d4ff; font-weight: bold;")
            stats_layout.addWidget(v, 1, i)
        
        layout.addLayout(stats_layout)
        
        # Actions
        actions = QHBoxLayout()
        
        open_btn = QPushButton("Open")
        open_btn.setStyleSheet(self.get_button_style("#00d4ff"))
        actions.addWidget(open_btn)
        
        analyze_btn = QPushButton("Analyze")
        analyze_btn.setStyleSheet(self.get_button_style())
        actions.addWidget(analyze_btn)
        
        layout.addLayout(actions)
        
        return card
    
    def create_assets_tab(self) -> QWidget:
        """Create assets and boundaries tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_asset_btn = QPushButton("➕ Add Asset")
        add_asset_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        add_asset_btn.clicked.connect(self.new_asset_dialog)
        toolbar.addWidget(add_asset_btn)
        
        add_boundary_btn = QPushButton("🔲 Add Boundary")
        add_boundary_btn.setStyleSheet(self.get_action_button_style("#00ff88"))
        add_boundary_btn.clicked.connect(self.new_boundary_dialog)
        toolbar.addWidget(add_boundary_btn)
        
        toolbar.addStretch()
        
        self.asset_search = QLineEdit()
        self.asset_search.setPlaceholderText("🔍 Search assets...")
        self.asset_search.setStyleSheet(self.get_input_style())
        toolbar.addWidget(self.asset_search)
        
        layout.addLayout(toolbar)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Assets table
        assets_group = QGroupBox("System Assets")
        assets_group.setStyleSheet(self.get_group_style())
        assets_layout = QVBoxLayout(assets_group)
        
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(6)
        self.assets_table.setHorizontalHeaderLabels([
            "ID", "Name", "Type", "Classification", "Trust Level", "Owner"
        ])
        self.assets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.assets_table.setStyleSheet(self.get_table_style())
        self.assets_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.assets_table.currentItemChanged.connect(self.on_asset_selected)
        assets_layout.addWidget(self.assets_table)
        
        splitter.addWidget(assets_group)
        
        # Trust boundaries
        boundaries_group = QGroupBox("Trust Boundaries")
        boundaries_group.setStyleSheet(self.get_group_style())
        boundaries_layout = QVBoxLayout(boundaries_group)
        
        self.boundaries_tree = QTreeWidget()
        self.boundaries_tree.setHeaderLabels(["Boundary", "Trust Level", "Assets"])
        self.boundaries_tree.setStyleSheet(self.get_tree_style())
        boundaries_layout.addWidget(self.boundaries_tree)
        
        splitter.addWidget(boundaries_group)
        
        splitter.setSizes([600, 400])
        layout.addWidget(splitter)
        
        # Asset types summary
        summary_frame = QFrame()
        summary_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 10px;")
        summary_layout = QHBoxLayout(summary_frame)
        
        for asset_type in [AssetType.DATA, AssetType.PROCESS, AssetType.ACTOR, 
                           AssetType.DATASTORE, AssetType.EXTERNAL_ENTITY]:
            card = self.create_asset_type_card(asset_type)
            summary_layout.addWidget(card)
        
        layout.addWidget(summary_frame)
        
        return widget
    
    def create_asset_type_card(self, asset_type: AssetType) -> QWidget:
        """Create asset type summary card"""
        icons = {
            AssetType.DATA: "📄",
            AssetType.PROCESS: "⚙️",
            AssetType.ACTOR: "👤",
            AssetType.DATASTORE: "💾",
            AssetType.EXTERNAL_ENTITY: "🌐"
        }
        
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        icon = QLabel(icons.get(asset_type, "📦"))
        icon.setFont(QFont("Segoe UI", 20))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)
        
        name = QLabel(asset_type.value.replace("_", " ").title())
        name.setStyleSheet("color: #00d4ff; font-weight: bold; font-size: 11px;")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name)
        
        count = QLabel("0")
        count.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        count.setStyleSheet("color: white;")
        count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(count)
        
        return card
    
    def create_dataflows_tab(self) -> QWidget:
        """Create data flows tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_flow_btn = QPushButton("➕ Add Data Flow")
        add_flow_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        add_flow_btn.clicked.connect(self.new_dataflow_dialog)
        toolbar.addWidget(add_flow_btn)
        
        analyze_flows_btn = QPushButton("🔍 Analyze Flows")
        analyze_flows_btn.setStyleSheet(self.get_button_style())
        analyze_flows_btn.clicked.connect(self.analyze_dataflows)
        toolbar.addWidget(analyze_flows_btn)
        
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        
        # Data flows table
        self.flows_table = QTableWidget()
        self.flows_table.setColumnCount(8)
        self.flows_table.setHorizontalHeaderLabels([
            "ID", "Name", "Source", "Destination", "Protocol", 
            "Encrypted", "Authenticated", "Crosses Boundary"
        ])
        self.flows_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.flows_table.setStyleSheet(self.get_table_style())
        self.flows_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.flows_table)
        
        # Flow diagram placeholder
        diagram_frame = QFrame()
        diagram_frame.setMinimumHeight(200)
        diagram_frame.setStyleSheet("""
            background: #0a0a1a;
            border: 1px solid #3a3a5a;
            border-radius: 8px;
        """)
        
        diagram_layout = QVBoxLayout(diagram_frame)
        diagram_label = QLabel("📊 Data Flow Diagram\nSelect flows to visualize")
        diagram_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        diagram_label.setStyleSheet("color: #8888aa; font-size: 14px;")
        diagram_layout.addWidget(diagram_label)
        
        layout.addWidget(diagram_frame)
        
        return widget
    
    def create_threats_tab(self) -> QWidget:
        """Create threats tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_threat_btn = QPushButton("➕ Add Threat")
        add_threat_btn.setStyleSheet(self.get_action_button_style("#ff6b6b"))
        add_threat_btn.clicked.connect(self.new_threat_dialog)
        toolbar.addWidget(add_threat_btn)
        
        stride_btn = QPushButton("🎯 STRIDE Analysis")
        stride_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        stride_btn.clicked.connect(self.stride_analysis)
        toolbar.addWidget(stride_btn)
        
        dread_btn = QPushButton("📊 DREAD Scoring")
        dread_btn.setStyleSheet(self.get_button_style())
        dread_btn.clicked.connect(self.dread_scoring)
        toolbar.addWidget(dread_btn)
        
        toolbar.addStretch()
        
        self.threat_filter = QComboBox()
        self.threat_filter.addItem("All Categories", None)
        for cat in ThreatCategory:
            self.threat_filter.addItem(cat.value.replace("_", " ").title(), cat)
        self.threat_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.threat_filter)
        
        layout.addLayout(toolbar)
        
        # STRIDE categories bar
        stride_bar = QHBoxLayout()
        
        for cat in ThreatCategory:
            card = self.create_stride_card(cat)
            stride_bar.addWidget(card)
        
        layout.addLayout(stride_bar)
        
        # Threats table
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(8)
        self.threats_table.setHorizontalHeaderLabels([
            "ID", "Name", "Category", "Severity", "Status", 
            "Likelihood", "Impact", "Risk Score"
        ])
        self.threats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.threats_table.setStyleSheet(self.get_table_style())
        self.threats_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.threats_table.currentItemChanged.connect(self.on_threat_selected)
        layout.addWidget(self.threats_table)
        
        # Threat details
        details_group = QGroupBox("Threat Details")
        details_group.setStyleSheet(self.get_group_style())
        details_layout = QHBoxLayout(details_group)
        
        # Description
        desc_layout = QVBoxLayout()
        desc_label = QLabel("Description:")
        desc_label.setStyleSheet("color: #00d4ff; font-weight: bold;")
        desc_layout.addWidget(desc_label)
        
        self.threat_description = QTextEdit()
        self.threat_description.setReadOnly(True)
        self.threat_description.setStyleSheet(self.get_text_style())
        desc_layout.addWidget(self.threat_description)
        
        details_layout.addLayout(desc_layout)
        
        # Mitigations
        mit_layout = QVBoxLayout()
        mit_label = QLabel("Mitigations:")
        mit_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        mit_layout.addWidget(mit_label)
        
        self.threat_mitigations = QListWidget()
        self.threat_mitigations.setStyleSheet(self.get_list_style())
        mit_layout.addWidget(self.threat_mitigations)
        
        suggest_btn = QPushButton("💡 Suggest Mitigations")
        suggest_btn.setStyleSheet(self.get_button_style())
        suggest_btn.clicked.connect(self.suggest_mitigations)
        mit_layout.addWidget(suggest_btn)
        
        details_layout.addLayout(mit_layout)
        
        layout.addWidget(details_group)
        
        return widget
    
    def create_stride_card(self, category: ThreatCategory) -> QWidget:
        """Create STRIDE category card"""
        colors = {
            ThreatCategory.SPOOFING: "#ff6b6b",
            ThreatCategory.TAMPERING: "#ff8800",
            ThreatCategory.REPUDIATION: "#ffaa00",
            ThreatCategory.INFORMATION_DISCLOSURE: "#00d4ff",
            ThreatCategory.DENIAL_OF_SERVICE: "#ff00ff",
            ThreatCategory.ELEVATION_OF_PRIVILEGE: "#00ff88"
        }
        
        letter = category.value[0].upper()
        color = colors.get(category, "#3a3a5a")
        
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #1a1a2e;
                border: 2px solid {color};
                border-radius: 8px;
                padding: 5px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(5, 5, 5, 5)
        
        letter_label = QLabel(letter)
        letter_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        letter_label.setStyleSheet(f"color: {color};")
        letter_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(letter_label)
        
        name = QLabel(category.value.replace("_", "\n").title())
        name.setStyleSheet("color: #8888aa; font-size: 9px;")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name)
        
        count = QLabel("0")
        count.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        count.setStyleSheet("color: white;")
        count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(count)
        
        return card
    
    def create_mitigations_tab(self) -> QWidget:
        """Create mitigations tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_mit_btn = QPushButton("➕ Add Mitigation")
        add_mit_btn.setStyleSheet(self.get_action_button_style("#00ff88"))
        add_mit_btn.clicked.connect(self.new_mitigation_dialog)
        toolbar.addWidget(add_mit_btn)
        
        toolbar.addStretch()
        
        self.mit_status_filter = QComboBox()
        self.mit_status_filter.addItem("All Status", None)
        for status in MitigationStatus:
            self.mit_status_filter.addItem(status.value.replace("_", " ").title(), status)
        self.mit_status_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.mit_status_filter)
        
        layout.addLayout(toolbar)
        
        # Mitigations table
        self.mitigations_table = QTableWidget()
        self.mitigations_table.setColumnCount(7)
        self.mitigations_table.setHorizontalHeaderLabels([
            "ID", "Name", "Status", "Effectiveness", "Cost", "Owner", "Threats Addressed"
        ])
        self.mitigations_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.mitigations_table.setStyleSheet(self.get_table_style())
        self.mitigations_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.mitigations_table)
        
        # Mitigation details
        details_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Details
        details_group = QGroupBox("Mitigation Details")
        details_group.setStyleSheet(self.get_group_style())
        details_layout = QVBoxLayout(details_group)
        
        self.mit_details = QTextEdit()
        self.mit_details.setReadOnly(True)
        self.mit_details.setStyleSheet(self.get_text_style())
        details_layout.addWidget(self.mit_details)
        
        # Status update
        status_layout = QHBoxLayout()
        
        status_label = QLabel("Status:")
        status_label.setStyleSheet("color: #8888aa;")
        status_layout.addWidget(status_label)
        
        self.mit_status_combo = QComboBox()
        for status in MitigationStatus:
            self.mit_status_combo.addItem(status.value.replace("_", " ").title(), status)
        self.mit_status_combo.setStyleSheet(self.get_combo_style())
        status_layout.addWidget(self.mit_status_combo)
        
        update_btn = QPushButton("Update")
        update_btn.setStyleSheet(self.get_button_style())
        status_layout.addWidget(update_btn)
        
        details_layout.addLayout(status_layout)
        
        details_splitter.addWidget(details_group)
        
        # Addressed threats
        threats_group = QGroupBox("Addressed Threats")
        threats_group.setStyleSheet(self.get_group_style())
        threats_layout = QVBoxLayout(threats_group)
        
        self.addressed_threats = QListWidget()
        self.addressed_threats.setStyleSheet(self.get_list_style())
        threats_layout.addWidget(self.addressed_threats)
        
        details_splitter.addWidget(threats_group)
        
        layout.addWidget(details_splitter)
        
        # Coverage summary
        coverage_frame = QFrame()
        coverage_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 10px;")
        coverage_layout = QHBoxLayout(coverage_frame)
        
        coverage_layout.addWidget(QLabel("Mitigation Coverage:"))
        
        self.coverage_bar = QProgressBar()
        self.coverage_bar.setRange(0, 100)
        self.coverage_bar.setValue(0)
        self.coverage_bar.setFormat("%p%")
        self.coverage_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                background: #1a1a2e;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
                border-radius: 7px;
            }
        """)
        coverage_layout.addWidget(self.coverage_bar)
        
        for status, color in [
            ("Implemented", "#00ff88"),
            ("In Progress", "#ffaa00"),
            ("Not Started", "#ff6b6b")
        ]:
            label = QLabel(f"{status}: 0")
            label.setStyleSheet(f"color: {color}; font-weight: bold; margin-left: 15px;")
            coverage_layout.addWidget(label)
        
        layout.addWidget(coverage_frame)
        
        return widget
    
    def create_analysis_tab(self) -> QWidget:
        """Create analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Analysis options
        options_layout = QHBoxLayout()
        
        generate_report_btn = QPushButton("📊 Generate Report")
        generate_report_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        generate_report_btn.clicked.connect(self.generate_report)
        options_layout.addWidget(generate_report_btn)
        
        attack_tree_btn = QPushButton("🌳 Attack Trees")
        attack_tree_btn.setStyleSheet(self.get_button_style())
        attack_tree_btn.clicked.connect(self.attack_tree_analysis)
        options_layout.addWidget(attack_tree_btn)
        
        risk_matrix_btn = QPushButton("📈 Risk Matrix")
        risk_matrix_btn.setStyleSheet(self.get_button_style())
        risk_matrix_btn.clicked.connect(self.show_risk_matrix)
        options_layout.addWidget(risk_matrix_btn)
        
        options_layout.addStretch()
        
        layout.addLayout(options_layout)
        
        # Analysis dashboard
        dashboard_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Risk summary
        risk_group = QGroupBox("Risk Summary")
        risk_group.setStyleSheet(self.get_group_style())
        risk_layout = QVBoxLayout(risk_group)
        
        # Risk gauge placeholder
        risk_gauge = QFrame()
        risk_gauge.setMinimumHeight(150)
        risk_gauge.setStyleSheet("""
            background: #0a0a1a;
            border: 1px solid #3a3a5a;
            border-radius: 8px;
        """)
        
        gauge_layout = QVBoxLayout(risk_gauge)
        risk_label = QLabel("Overall Risk Score")
        risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        risk_label.setStyleSheet("color: #8888aa;")
        gauge_layout.addWidget(risk_label)
        
        risk_value = QLabel("0.0")
        risk_value.setFont(QFont("Segoe UI", 48, QFont.Weight.Bold))
        risk_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        risk_value.setStyleSheet("color: #00ff88;")
        gauge_layout.addWidget(risk_value)
        
        risk_layout.addWidget(risk_gauge)
        
        # Severity distribution
        dist_layout = QGridLayout()
        
        for i, (sev, color) in enumerate([
            (SeverityLevel.CRITICAL, "#ff4444"),
            (SeverityLevel.HIGH, "#ff8800"),
            (SeverityLevel.MEDIUM, "#ffaa00"),
            (SeverityLevel.LOW, "#00ff88")
        ]):
            label = QLabel(sev.value.title())
            label.setStyleSheet(f"color: {color}; font-weight: bold;")
            dist_layout.addWidget(label, i, 0)
            
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFormat("%v")
            bar.setStyleSheet(f"""
                QProgressBar {{
                    border: 1px solid #3a3a5a;
                    border-radius: 4px;
                    background: #1a1a2e;
                    text-align: right;
                    color: white;
                    padding-right: 5px;
                }}
                QProgressBar::chunk {{
                    background: {color};
                    border-radius: 3px;
                }}
            """)
            dist_layout.addWidget(bar, i, 1)
        
        risk_layout.addLayout(dist_layout)
        
        dashboard_splitter.addWidget(risk_group)
        
        # Threat trends
        trends_group = QGroupBox("Analysis Results")
        trends_group.setStyleSheet(self.get_group_style())
        trends_layout = QVBoxLayout(trends_group)
        
        self.analysis_results = QTextEdit()
        self.analysis_results.setReadOnly(True)
        self.analysis_results.setStyleSheet(self.get_text_style())
        self.analysis_results.setHtml("""
            <h3>Threat Model Analysis</h3>
            <p>Select a threat model and run analysis to see results here.</p>
            <h4>Available Analyses:</h4>
            <ul>
                <li>STRIDE Threat Identification</li>
                <li>DREAD Risk Scoring</li>
                <li>Attack Tree Analysis</li>
                <li>Mitigation Coverage</li>
            </ul>
        """)
        trends_layout.addWidget(self.analysis_results)
        
        dashboard_splitter.addWidget(trends_group)
        
        layout.addWidget(dashboard_splitter)
        
        return widget
    
    # Style methods
    def get_action_button_style(self, color: str = "#00d4ff") -> str:
        return f"""
            QPushButton {{
                background: {color};
                color: #0a0a1a;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: {color}cc;
            }}
            QPushButton:pressed {{
                background: {color}aa;
            }}
        """
    
    def get_button_style(self, color: str = "#3a3a5a") -> str:
        return f"""
            QPushButton {{
                background: {color};
                color: white;
                border: 1px solid #4a4a6a;
                border-radius: 6px;
                padding: 8px 15px;
            }}
            QPushButton:hover {{
                background: #4a4a6a;
                border-color: #00d4ff;
            }}
        """
    
    def get_input_style(self) -> str:
        return """
            QLineEdit {
                background: #252540;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
                padding: 8px 12px;
            }
            QLineEdit:focus {
                border-color: #00d4ff;
            }
        """
    
    def get_combo_style(self) -> str:
        return """
            QComboBox {
                background: #252540;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
                padding: 8px 12px;
                min-width: 150px;
            }
            QComboBox:hover {
                border-color: #00d4ff;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background: #252540;
                color: white;
                selection-background-color: #00d4ff;
            }
        """
    
    def get_table_style(self) -> str:
        return """
            QTableWidget {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                gridline-color: #2a2a4a;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #00d4ff33;
            }
            QHeaderView::section {
                background: #252540;
                color: #00d4ff;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #00d4ff;
            }
        """
    
    def get_tree_style(self) -> str:
        return """
            QTreeWidget {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background: #00d4ff33;
            }
            QHeaderView::section {
                background: #252540;
                color: #00d4ff;
                padding: 8px;
                border: none;
            }
        """
    
    def get_list_style(self) -> str:
        return """
            QListWidget {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 8px;
            }
            QListWidget::item:selected {
                background: #00d4ff33;
            }
        """
    
    def get_text_style(self) -> str:
        return """
            QTextEdit {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
                padding: 8px;
            }
        """
    
    def get_group_style(self) -> str:
        return """
            QGroupBox {
                font-weight: bold;
                color: #00d4ff;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """
    
    # Event handlers
    def load_data(self):
        """Load initial data"""
        self.refresh_model_cards()
    
    def on_model_changed(self, index):
        """Handle model selection change"""
        pass
    
    def on_asset_selected(self, current, previous):
        """Handle asset selection"""
        pass
    
    def on_threat_selected(self, current, previous):
        """Handle threat selection"""
        if not current:
            return
        row = current.row()
        threat_id = self.threats_table.item(row, 0)
        if threat_id:
            self.show_threat_details(threat_id.text())
    
    def show_threat_details(self, threat_id: str):
        """Show threat details"""
        if not self.engine:
            return
        
        threat = self.engine.threats.get(threat_id)
        if threat:
            self.threat_description.setPlainText(threat.description)
            
            self.threat_mitigations.clear()
            for mit_id in threat.mitigations:
                mit = self.engine.mitigations.get(mit_id)
                if mit:
                    self.threat_mitigations.addItem(f"✓ {mit.name}")
    
    # Dialog methods
    def new_model_dialog(self):
        """Show new model dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Threat Model")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        name_input = QLineEdit()
        name_input.setStyleSheet(self.get_input_style())
        form.addRow("Model Name:", name_input)
        
        version_input = QLineEdit()
        version_input.setText("1.0")
        version_input.setStyleSheet(self.get_input_style())
        form.addRow("Version:", version_input)
        
        type_combo = QComboBox()
        for mt in ModelType:
            type_combo.addItem(mt.value.upper(), mt)
        type_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Model Type:", type_combo)
        
        scope_input = QTextEdit()
        scope_input.setMaximumHeight(100)
        scope_input.setStyleSheet(self.get_text_style())
        form.addRow("Scope:", scope_input)
        
        creator_input = QLineEdit()
        creator_input.setStyleSheet(self.get_input_style())
        form.addRow("Created By:", creator_input)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.status_message.emit("Threat model created")
            self.refresh_model_cards()
    
    def new_asset_dialog(self):
        """Show new asset dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Asset")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        name_input = QLineEdit()
        name_input.setStyleSheet(self.get_input_style())
        form.addRow("Asset Name:", name_input)
        
        type_combo = QComboBox()
        for at in AssetType:
            type_combo.addItem(at.value.replace("_", " ").title(), at)
        type_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Asset Type:", type_combo)
        
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(80)
        desc_input.setStyleSheet(self.get_text_style())
        form.addRow("Description:", desc_input)
        
        classification_combo = QComboBox()
        classification_combo.addItems(["Public", "Internal", "Confidential", "Restricted"])
        classification_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Classification:", classification_combo)
        
        trust_spin = QSpinBox()
        trust_spin.setRange(0, 100)
        trust_spin.setValue(50)
        trust_spin.setStyleSheet("background: #252540; color: white;")
        form.addRow("Trust Level:", trust_spin)
        
        owner_input = QLineEdit()
        owner_input.setStyleSheet(self.get_input_style())
        form.addRow("Owner:", owner_input)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.status_message.emit("Asset added")
    
    def new_boundary_dialog(self):
        """Show new boundary dialog"""
        self.status_message.emit("New boundary dialog")
    
    def new_dataflow_dialog(self):
        """Show new data flow dialog"""
        self.status_message.emit("New data flow dialog")
    
    def new_threat_dialog(self):
        """Show new threat dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Threat")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        name_input = QLineEdit()
        name_input.setStyleSheet(self.get_input_style())
        form.addRow("Threat Name:", name_input)
        
        category_combo = QComboBox()
        for cat in ThreatCategory:
            category_combo.addItem(cat.value.replace("_", " ").title(), cat)
        category_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Category:", category_combo)
        
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(80)
        desc_input.setStyleSheet(self.get_text_style())
        form.addRow("Description:", desc_input)
        
        severity_combo = QComboBox()
        for sev in SeverityLevel:
            severity_combo.addItem(sev.value.title(), sev)
        severity_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Severity:", severity_combo)
        
        likelihood_slider = QSlider(Qt.Orientation.Horizontal)
        likelihood_slider.setRange(0, 100)
        likelihood_slider.setValue(50)
        form.addRow("Likelihood:", likelihood_slider)
        
        impact_slider = QSlider(Qt.Orientation.Horizontal)
        impact_slider.setRange(0, 100)
        impact_slider.setValue(50)
        form.addRow("Impact:", impact_slider)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.status_message.emit("Threat added")
    
    def new_mitigation_dialog(self):
        """Show new mitigation dialog"""
        self.status_message.emit("New mitigation dialog")
    
    # Action methods
    def auto_analyze(self):
        """Run automatic threat analysis"""
        self.status_message.emit("Running automatic threat analysis...")
    
    def analyze_dataflows(self):
        """Analyze data flows for threats"""
        self.status_message.emit("Analyzing data flows...")
    
    def stride_analysis(self):
        """Run STRIDE analysis"""
        self.status_message.emit("Running STRIDE analysis...")
    
    def dread_scoring(self):
        """Open DREAD scoring dialog"""
        self.status_message.emit("DREAD scoring...")
    
    def suggest_mitigations(self):
        """Suggest mitigations for selected threat"""
        self.status_message.emit("Generating mitigation suggestions...")
    
    def generate_report(self):
        """Generate threat model report"""
        self.status_message.emit("Generating report...")
    
    def attack_tree_analysis(self):
        """Open attack tree analysis"""
        self.status_message.emit("Attack tree analysis...")
    
    def show_risk_matrix(self):
        """Show risk matrix"""
        self.status_message.emit("Showing risk matrix...")
    
    def export_model(self):
        """Export threat model"""
        if self.engine:
            self.status_message.emit("Model exported")
