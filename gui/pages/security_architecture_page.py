"""
HydraRecon Security Architecture Review Page
Enterprise security architecture assessment and review interface
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QLineEdit, QTextEdit,
    QComboBox, QGroupBox, QFormLayout, QHeaderView, QSplitter,
    QTreeWidget, QTreeWidgetItem, QDialog, QDialogButtonBox,
    QSpinBox, QDoubleSpinBox, QListWidget, QListWidgetItem,
    QCheckBox, QProgressBar, QFrame, QScrollArea, QGridLayout,
    QMessageBox, QStackedWidget, QToolButton, QMenu
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon, QAction
from datetime import datetime
import asyncio

try:
    from core.security_architecture import (
        SecurityArchitectureEngine, SecurityControl, ArchitectureDiagram,
        ArchitectureReview, ThreatVector, ComplianceMapping, ArchitecturePattern,
        ArchitectureLayer, ControlType, ReviewStatus, RiskLevel, ComplianceStatus
    )
except ImportError:
    SecurityArchitectureEngine = None


class SecurityArchitecturePage(QWidget):
    """Security Architecture Review Page"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = SecurityArchitectureEngine() if SecurityArchitectureEngine else None
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
        self.tabs.addTab(self.create_controls_tab(), "🛡️ Security Controls")
        self.tabs.addTab(self.create_diagrams_tab(), "📊 Architecture Diagrams")
        self.tabs.addTab(self.create_reviews_tab(), "📋 Architecture Reviews")
        self.tabs.addTab(self.create_threats_tab(), "⚠️ Threat Vectors")
        self.tabs.addTab(self.create_compliance_tab(), "✅ Compliance Mapping")
        self.tabs.addTab(self.create_patterns_tab(), "🎯 Architecture Patterns")
        
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
        
        title = QLabel("🏛️ Security Architecture Review")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Enterprise security architecture assessment and design review framework")
        subtitle.setStyleSheet("color: #8888aa; font-size: 12px;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        new_review_btn = QPushButton("📋 New Review")
        new_review_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        new_review_btn.clicked.connect(self.new_review_dialog)
        actions_layout.addWidget(new_review_btn)
        
        new_control_btn = QPushButton("🛡️ Add Control")
        new_control_btn.setStyleSheet(self.get_action_button_style("#00ff88"))
        new_control_btn.clicked.connect(self.new_control_dialog)
        actions_layout.addWidget(new_control_btn)
        
        export_btn = QPushButton("📤 Export")
        export_btn.setStyleSheet(self.get_action_button_style("#ff6b6b"))
        export_btn.clicked.connect(self.export_architecture)
        actions_layout.addWidget(export_btn)
        
        layout.addLayout(actions_layout)
        
        return header
    
    def create_controls_tab(self) -> QWidget:
        """Create security controls tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.control_search = QLineEdit()
        self.control_search.setPlaceholderText("🔍 Search controls...")
        self.control_search.setStyleSheet(self.get_input_style())
        self.control_search.textChanged.connect(self.filter_controls)
        toolbar.addWidget(self.control_search)
        
        self.layer_filter = QComboBox()
        self.layer_filter.addItem("All Layers", None)
        for layer in ArchitectureLayer:
            self.layer_filter.addItem(layer.value.title(), layer)
        self.layer_filter.setStyleSheet(self.get_combo_style())
        self.layer_filter.currentIndexChanged.connect(self.filter_controls)
        toolbar.addWidget(self.layer_filter)
        
        self.type_filter = QComboBox()
        self.type_filter.addItem("All Types", None)
        for ctype in ControlType:
            self.type_filter.addItem(ctype.value.title(), ctype)
        self.type_filter.setStyleSheet(self.get_combo_style())
        self.type_filter.currentIndexChanged.connect(self.filter_controls)
        toolbar.addWidget(self.type_filter)
        
        layout.addLayout(toolbar)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Controls table
        controls_group = QGroupBox("Security Controls")
        controls_group.setStyleSheet(self.get_group_style())
        controls_layout = QVBoxLayout(controls_group)
        
        self.controls_table = QTableWidget()
        self.controls_table.setColumnCount(7)
        self.controls_table.setHorizontalHeaderLabels([
            "Control ID", "Name", "Layer", "Type", "Effectiveness", "Owner", "Status"
        ])
        self.controls_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.controls_table.setStyleSheet(self.get_table_style())
        self.controls_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.controls_table.currentItemChanged.connect(self.on_control_selected)
        controls_layout.addWidget(self.controls_table)
        
        splitter.addWidget(controls_group)
        
        # Control details
        details_group = QGroupBox("Control Details")
        details_group.setStyleSheet(self.get_group_style())
        details_layout = QVBoxLayout(details_group)
        
        self.control_details = QTextEdit()
        self.control_details.setReadOnly(True)
        self.control_details.setStyleSheet(self.get_text_style())
        details_layout.addWidget(self.control_details)
        
        # Control actions
        actions_layout = QHBoxLayout()
        
        edit_btn = QPushButton("✏️ Edit")
        edit_btn.setStyleSheet(self.get_button_style())
        edit_btn.clicked.connect(self.edit_control)
        actions_layout.addWidget(edit_btn)
        
        assess_btn = QPushButton("📊 Assess")
        assess_btn.setStyleSheet(self.get_button_style())
        assess_btn.clicked.connect(self.assess_control)
        actions_layout.addWidget(assess_btn)
        
        delete_btn = QPushButton("🗑️ Delete")
        delete_btn.setStyleSheet(self.get_button_style("#ff6b6b"))
        delete_btn.clicked.connect(self.delete_control)
        actions_layout.addWidget(delete_btn)
        
        details_layout.addLayout(actions_layout)
        
        splitter.addWidget(details_group)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        # Layer assessment cards
        assessment_frame = QFrame()
        assessment_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 10px;")
        assessment_layout = QHBoxLayout(assessment_frame)
        
        for layer in [ArchitectureLayer.NETWORK, ArchitectureLayer.APPLICATION, 
                      ArchitectureLayer.DATA, ArchitectureLayer.IDENTITY]:
            card = self.create_layer_card(layer)
            assessment_layout.addWidget(card)
        
        layout.addWidget(assessment_frame)
        
        return widget
    
    def create_layer_card(self, layer: ArchitectureLayer) -> QWidget:
        """Create layer assessment card"""
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
        
        title = QLabel(f"🏛️ {layer.value.title()}")
        title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        layout.addWidget(title)
        
        # Effectiveness bar
        effectiveness = QProgressBar()
        effectiveness.setRange(0, 100)
        effectiveness.setValue(75)  # Sample value
        effectiveness.setFormat("%p% Effective")
        effectiveness.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3a3a5a;
                border-radius: 4px;
                background: #252540;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
                border-radius: 3px;
            }
        """)
        layout.addWidget(effectiveness)
        
        controls_label = QLabel("Controls: 0")
        controls_label.setStyleSheet("color: #8888aa; font-size: 10px;")
        layout.addWidget(controls_label)
        
        return card
    
    def create_diagrams_tab(self) -> QWidget:
        """Create architecture diagrams tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        new_diagram_btn = QPushButton("➕ New Diagram")
        new_diagram_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        new_diagram_btn.clicked.connect(self.new_diagram_dialog)
        toolbar.addWidget(new_diagram_btn)
        
        import_btn = QPushButton("📥 Import")
        import_btn.setStyleSheet(self.get_button_style())
        toolbar.addWidget(import_btn)
        
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Diagrams list
        diagrams_group = QGroupBox("Architecture Diagrams")
        diagrams_group.setStyleSheet(self.get_group_style())
        diagrams_layout = QVBoxLayout(diagrams_group)
        
        self.diagrams_tree = QTreeWidget()
        self.diagrams_tree.setHeaderLabels(["Name", "Version", "Layer", "Updated"])
        self.diagrams_tree.setStyleSheet(self.get_tree_style())
        self.diagrams_tree.currentItemChanged.connect(self.on_diagram_selected)
        diagrams_layout.addWidget(self.diagrams_tree)
        
        splitter.addWidget(diagrams_group)
        
        # Diagram preview
        preview_group = QGroupBox("Diagram Preview")
        preview_group.setStyleSheet(self.get_group_style())
        preview_layout = QVBoxLayout(preview_group)
        
        self.diagram_preview = QLabel("Select a diagram to preview")
        self.diagram_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.diagram_preview.setStyleSheet("""
            background: #0a0a1a;
            border: 1px solid #3a3a5a;
            border-radius: 8px;
            padding: 50px;
            color: #8888aa;
            font-size: 14px;
        """)
        self.diagram_preview.setMinimumHeight(300)
        preview_layout.addWidget(self.diagram_preview)
        
        # Diagram info
        self.diagram_info = QTextEdit()
        self.diagram_info.setReadOnly(True)
        self.diagram_info.setMaximumHeight(150)
        self.diagram_info.setStyleSheet(self.get_text_style())
        preview_layout.addWidget(self.diagram_info)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        edit_diagram_btn = QPushButton("✏️ Edit")
        edit_diagram_btn.setStyleSheet(self.get_button_style())
        actions_layout.addWidget(edit_diagram_btn)
        
        validate_btn = QPushButton("✅ Validate")
        validate_btn.setStyleSheet(self.get_button_style("#00ff88"))
        validate_btn.clicked.connect(self.validate_diagram)
        actions_layout.addWidget(validate_btn)
        
        export_diagram_btn = QPushButton("📤 Export")
        export_diagram_btn.setStyleSheet(self.get_button_style())
        actions_layout.addWidget(export_diagram_btn)
        
        preview_layout.addLayout(actions_layout)
        
        splitter.addWidget(preview_group)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        return widget
    
    def create_reviews_tab(self) -> QWidget:
        """Create architecture reviews tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Status filter bar
        filter_bar = QHBoxLayout()
        
        for status in [None, ReviewStatus.PENDING, ReviewStatus.IN_PROGRESS, 
                       ReviewStatus.COMPLETED, ReviewStatus.APPROVED]:
            label = status.value.replace("_", " ").title() if status else "All"
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setStyleSheet("""
                QPushButton {
                    background: #252540;
                    color: #8888aa;
                    border: 1px solid #3a3a5a;
                    border-radius: 15px;
                    padding: 8px 15px;
                }
                QPushButton:checked {
                    background: #00d4ff;
                    color: #0a0a1a;
                }
                QPushButton:hover:!checked {
                    background: #2a2a4a;
                }
            """)
            filter_bar.addWidget(btn)
        
        filter_bar.addStretch()
        
        new_review_btn = QPushButton("➕ New Review")
        new_review_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        new_review_btn.clicked.connect(self.new_review_dialog)
        filter_bar.addWidget(new_review_btn)
        
        layout.addLayout(filter_bar)
        
        # Reviews table
        self.reviews_table = QTableWidget()
        self.reviews_table.setColumnCount(7)
        self.reviews_table.setHorizontalHeaderLabels([
            "Review ID", "Name", "Scope", "Status", "Reviewer", "Risk Score", "Compliance"
        ])
        self.reviews_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.reviews_table.setStyleSheet(self.get_table_style())
        self.reviews_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.reviews_table.currentItemChanged.connect(self.on_review_selected)
        layout.addWidget(self.reviews_table)
        
        # Review details section
        details_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Findings
        findings_group = QGroupBox("Findings")
        findings_group.setStyleSheet(self.get_group_style())
        findings_layout = QVBoxLayout(findings_group)
        
        self.findings_list = QListWidget()
        self.findings_list.setStyleSheet(self.get_list_style())
        findings_layout.addWidget(self.findings_list)
        
        add_finding_btn = QPushButton("➕ Add Finding")
        add_finding_btn.setStyleSheet(self.get_button_style())
        findings_layout.addWidget(add_finding_btn)
        
        details_splitter.addWidget(findings_group)
        
        # Recommendations
        recommendations_group = QGroupBox("Recommendations")
        recommendations_group.setStyleSheet(self.get_group_style())
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet(self.get_list_style())
        recommendations_layout.addWidget(self.recommendations_list)
        
        add_rec_btn = QPushButton("➕ Add Recommendation")
        add_rec_btn.setStyleSheet(self.get_button_style())
        recommendations_layout.addWidget(add_rec_btn)
        
        details_splitter.addWidget(recommendations_group)
        
        # Approval chain
        approval_group = QGroupBox("Approval Chain")
        approval_group.setStyleSheet(self.get_group_style())
        approval_layout = QVBoxLayout(approval_group)
        
        self.approval_list = QListWidget()
        self.approval_list.setStyleSheet(self.get_list_style())
        approval_layout.addWidget(self.approval_list)
        
        approval_actions = QHBoxLayout()
        
        approve_btn = QPushButton("✅ Approve")
        approve_btn.setStyleSheet(self.get_button_style("#00ff88"))
        approve_btn.clicked.connect(self.approve_review)
        approval_actions.addWidget(approve_btn)
        
        reject_btn = QPushButton("❌ Reject")
        reject_btn.setStyleSheet(self.get_button_style("#ff6b6b"))
        reject_btn.clicked.connect(self.reject_review)
        approval_actions.addWidget(reject_btn)
        
        approval_layout.addLayout(approval_actions)
        
        details_splitter.addWidget(approval_group)
        
        layout.addWidget(details_splitter)
        
        return widget
    
    def create_threats_tab(self) -> QWidget:
        """Create threat vectors tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_threat_btn = QPushButton("➕ Add Threat Vector")
        add_threat_btn.setStyleSheet(self.get_action_button_style("#ff6b6b"))
        add_threat_btn.clicked.connect(self.new_threat_dialog)
        toolbar.addWidget(add_threat_btn)
        
        analyze_btn = QPushButton("🔍 Analyze All")
        analyze_btn.setStyleSheet(self.get_button_style())
        toolbar.addWidget(analyze_btn)
        
        toolbar.addStretch()
        
        self.threat_search = QLineEdit()
        self.threat_search.setPlaceholderText("🔍 Search threats...")
        self.threat_search.setStyleSheet(self.get_input_style())
        toolbar.addWidget(self.threat_search)
        
        layout.addLayout(toolbar)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Threats list
        threats_group = QGroupBox("Threat Vectors")
        threats_group.setStyleSheet(self.get_group_style())
        threats_layout = QVBoxLayout(threats_group)
        
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(6)
        self.threats_table.setHorizontalHeaderLabels([
            "ID", "Name", "Attack Surface", "Risk Level", "Likelihood", "Impact"
        ])
        self.threats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.threats_table.setStyleSheet(self.get_table_style())
        self.threats_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.threats_table.currentItemChanged.connect(self.on_threat_selected)
        threats_layout.addWidget(self.threats_table)
        
        splitter.addWidget(threats_group)
        
        # Threat details
        details_group = QGroupBox("Threat Analysis")
        details_group.setStyleSheet(self.get_group_style())
        details_layout = QVBoxLayout(details_group)
        
        # Entry points
        entry_label = QLabel("Entry Points:")
        entry_label.setStyleSheet("color: #00d4ff; font-weight: bold;")
        details_layout.addWidget(entry_label)
        
        self.entry_points_list = QListWidget()
        self.entry_points_list.setMaximumHeight(100)
        self.entry_points_list.setStyleSheet(self.get_list_style())
        details_layout.addWidget(self.entry_points_list)
        
        # Mitigating controls
        controls_label = QLabel("Mitigating Controls:")
        controls_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        details_layout.addWidget(controls_label)
        
        self.mitigating_controls_list = QListWidget()
        self.mitigating_controls_list.setMaximumHeight(100)
        self.mitigating_controls_list.setStyleSheet(self.get_list_style())
        details_layout.addWidget(self.mitigating_controls_list)
        
        # Risk calculation
        risk_frame = QFrame()
        risk_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 10px;")
        risk_layout = QGridLayout(risk_frame)
        
        risk_layout.addWidget(QLabel("Calculated Risk:"), 0, 0)
        self.calc_risk_label = QLabel("0.00")
        self.calc_risk_label.setStyleSheet("color: #00d4ff; font-size: 18px; font-weight: bold;")
        risk_layout.addWidget(self.calc_risk_label, 0, 1)
        
        risk_layout.addWidget(QLabel("Residual Risk:"), 1, 0)
        self.residual_risk_label = QLabel("Medium")
        self.residual_risk_label.setStyleSheet("color: #ffaa00; font-weight: bold;")
        risk_layout.addWidget(self.residual_risk_label, 1, 1)
        
        details_layout.addWidget(risk_frame)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        calculate_btn = QPushButton("📊 Calculate Risk")
        calculate_btn.setStyleSheet(self.get_button_style())
        calculate_btn.clicked.connect(self.calculate_threat_risk)
        actions_layout.addWidget(calculate_btn)
        
        mitigate_btn = QPushButton("🛡️ Add Mitigation")
        mitigate_btn.setStyleSheet(self.get_button_style("#00ff88"))
        actions_layout.addWidget(mitigate_btn)
        
        details_layout.addLayout(actions_layout)
        
        splitter.addWidget(details_group)
        
        layout.addWidget(splitter)
        
        # Risk summary
        risk_summary = self.create_risk_summary()
        layout.addWidget(risk_summary)
        
        return widget
    
    def create_risk_summary(self) -> QWidget:
        """Create risk summary widget"""
        frame = QFrame()
        frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 10px;")
        layout = QHBoxLayout(frame)
        
        for level, color, count in [
            ("Critical", "#ff4444", 0),
            ("High", "#ff8800", 0),
            ("Medium", "#ffaa00", 0),
            ("Low", "#00ff88", 0)
        ]:
            card = QFrame()
            card.setStyleSheet(f"""
                background: #1a1a2e;
                border: 2px solid {color};
                border-radius: 8px;
                padding: 10px;
            """)
            card_layout = QVBoxLayout(card)
            
            level_label = QLabel(level)
            level_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            level_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(level_label)
            
            count_label = QLabel(str(count))
            count_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
            count_label.setStyleSheet(f"color: {color};")
            count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(count_label)
            
            layout.addWidget(card)
        
        return frame
    
    def create_compliance_tab(self) -> QWidget:
        """Create compliance mapping tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Framework selector
        framework_bar = QHBoxLayout()
        
        framework_label = QLabel("Framework:")
        framework_label.setStyleSheet("color: #00d4ff; font-weight: bold;")
        framework_bar.addWidget(framework_label)
        
        self.framework_combo = QComboBox()
        self.framework_combo.addItems([
            "NIST CSF", "ISO 27001", "CIS Controls", "SABSA", "TOGAF", "Zero Trust"
        ])
        self.framework_combo.setStyleSheet(self.get_combo_style())
        self.framework_combo.currentIndexChanged.connect(self.load_framework)
        framework_bar.addWidget(self.framework_combo)
        
        framework_bar.addStretch()
        
        add_mapping_btn = QPushButton("➕ Add Mapping")
        add_mapping_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        framework_bar.addWidget(add_mapping_btn)
        
        generate_report_btn = QPushButton("📊 Generate Report")
        generate_report_btn.setStyleSheet(self.get_button_style())
        framework_bar.addWidget(generate_report_btn)
        
        layout.addLayout(framework_bar)
        
        # Compliance score
        score_frame = QFrame()
        score_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 15px;")
        score_layout = QHBoxLayout(score_frame)
        
        score_layout.addWidget(QLabel("Compliance Score:"))
        
        self.compliance_score = QProgressBar()
        self.compliance_score.setRange(0, 100)
        self.compliance_score.setValue(78)
        self.compliance_score.setFormat("%p%")
        self.compliance_score.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                background: #1a1a2e;
                text-align: center;
                color: white;
                height: 25px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
                border-radius: 7px;
            }
        """)
        score_layout.addWidget(self.compliance_score)
        
        # Status counts
        for status, color in [
            ("Compliant", "#00ff88"),
            ("Partial", "#ffaa00"),
            ("Non-Compliant", "#ff6b6b")
        ]:
            status_label = QLabel(f"{status}: 0")
            status_label.setStyleSheet(f"color: {color}; font-weight: bold; margin-left: 15px;")
            score_layout.addWidget(status_label)
        
        layout.addWidget(score_frame)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Framework tree
        framework_group = QGroupBox("Framework Controls")
        framework_group.setStyleSheet(self.get_group_style())
        framework_layout = QVBoxLayout(framework_group)
        
        self.framework_tree = QTreeWidget()
        self.framework_tree.setHeaderLabels(["Control", "Status", "Evidence"])
        self.framework_tree.setStyleSheet(self.get_tree_style())
        self.framework_tree.currentItemChanged.connect(self.on_framework_control_selected)
        framework_layout.addWidget(self.framework_tree)
        
        splitter.addWidget(framework_group)
        
        # Mapping details
        mapping_group = QGroupBox("Control Mapping")
        mapping_group.setStyleSheet(self.get_group_style())
        mapping_layout = QVBoxLayout(mapping_group)
        
        form = QFormLayout()
        
        self.mapping_control = QLineEdit()
        self.mapping_control.setStyleSheet(self.get_input_style())
        self.mapping_control.setReadOnly(True)
        form.addRow("Control ID:", self.mapping_control)
        
        self.mapping_requirement = QTextEdit()
        self.mapping_requirement.setMaximumHeight(80)
        self.mapping_requirement.setStyleSheet(self.get_text_style())
        self.mapping_requirement.setReadOnly(True)
        form.addRow("Requirement:", self.mapping_requirement)
        
        self.mapping_status = QComboBox()
        for status in ComplianceStatus:
            self.mapping_status.addItem(status.value.replace("_", " ").title(), status)
        self.mapping_status.setStyleSheet(self.get_combo_style())
        form.addRow("Status:", self.mapping_status)
        
        mapping_layout.addLayout(form)
        
        # Evidence
        evidence_label = QLabel("Evidence:")
        evidence_label.setStyleSheet("color: #00d4ff; font-weight: bold;")
        mapping_layout.addWidget(evidence_label)
        
        self.evidence_list = QListWidget()
        self.evidence_list.setMaximumHeight(100)
        self.evidence_list.setStyleSheet(self.get_list_style())
        mapping_layout.addWidget(self.evidence_list)
        
        add_evidence_btn = QPushButton("➕ Add Evidence")
        add_evidence_btn.setStyleSheet(self.get_button_style())
        mapping_layout.addWidget(add_evidence_btn)
        
        # Gaps
        gaps_label = QLabel("Gaps:")
        gaps_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        mapping_layout.addWidget(gaps_label)
        
        self.gaps_text = QTextEdit()
        self.gaps_text.setMaximumHeight(80)
        self.gaps_text.setStyleSheet(self.get_text_style())
        mapping_layout.addWidget(self.gaps_text)
        
        save_mapping_btn = QPushButton("💾 Save Mapping")
        save_mapping_btn.setStyleSheet(self.get_action_button_style("#00ff88"))
        mapping_layout.addWidget(save_mapping_btn)
        
        splitter.addWidget(mapping_group)
        
        layout.addWidget(splitter)
        
        return widget
    
    def create_patterns_tab(self) -> QWidget:
        """Create architecture patterns tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.pattern_search = QLineEdit()
        self.pattern_search.setPlaceholderText("🔍 Search patterns...")
        self.pattern_search.setStyleSheet(self.get_input_style())
        toolbar.addWidget(self.pattern_search)
        
        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories", None)
        self.category_filter.addItems([
            "Perimeter", "Modern Security", "Application", "Data Security", "Operations"
        ])
        self.category_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.category_filter)
        
        toolbar.addStretch()
        
        recommend_btn = QPushButton("🎯 Recommend Patterns")
        recommend_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        recommend_btn.clicked.connect(self.recommend_patterns)
        toolbar.addWidget(recommend_btn)
        
        layout.addLayout(toolbar)
        
        # Patterns grid
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        patterns_widget = QWidget()
        self.patterns_grid = QGridLayout(patterns_widget)
        self.patterns_grid.setSpacing(15)
        
        scroll.setWidget(patterns_widget)
        layout.addWidget(scroll)
        
        # Load patterns
        self.load_patterns()
        
        return widget
    
    def create_pattern_card(self, pattern: ArchitecturePattern) -> QWidget:
        """Create pattern card widget"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #252540;
                border: 1px solid #3a3a5a;
                border-radius: 10px;
                padding: 15px;
            }
            QFrame:hover {
                border-color: #00d4ff;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Header
        header = QHBoxLayout()
        
        title = QLabel(pattern.name)
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        header.addWidget(title)
        
        category = QLabel(pattern.category)
        category.setStyleSheet("""
            background: #1a1a2e;
            color: #00ff88;
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 10px;
        """)
        header.addWidget(category)
        
        layout.addLayout(header)
        
        # Description
        desc = QLabel(pattern.description)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #aaaacc; font-size: 11px;")
        layout.addWidget(desc)
        
        # Layers
        layers_text = ", ".join([l.value.title() for l in pattern.layers])
        layers = QLabel(f"📊 Layers: {layers_text}")
        layers.setStyleSheet("color: #8888aa; font-size: 10px;")
        layout.addWidget(layers)
        
        # Benefits
        benefits_text = ", ".join(pattern.benefits[:2])
        benefits = QLabel(f"✅ {benefits_text}")
        benefits.setStyleSheet("color: #00ff88; font-size: 10px;")
        benefits.setWordWrap(True)
        layout.addWidget(benefits)
        
        # Action button
        apply_btn = QPushButton("Apply Pattern")
        apply_btn.setStyleSheet(self.get_button_style())
        layout.addWidget(apply_btn)
        
        return card
    
    def load_patterns(self):
        """Load architecture patterns into grid"""
        if not self.engine:
            return
        
        # Clear existing
        while self.patterns_grid.count():
            item = self.patterns_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Load patterns
        patterns = list(self.engine.patterns.values())
        
        row, col = 0, 0
        for pattern in patterns:
            card = self.create_pattern_card(pattern)
            self.patterns_grid.addWidget(card, row, col)
            col += 1
            if col >= 3:
                col = 0
                row += 1
    
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
        self.load_framework()
    
    def filter_controls(self):
        """Filter controls table"""
        pass
    
    def on_control_selected(self, current, previous):
        """Handle control selection"""
        if not current:
            return
        row = current.row()
        control_id = self.controls_table.item(row, 0)
        if control_id:
            self.show_control_details(control_id.text())
    
    def show_control_details(self, control_id: str):
        """Show control details"""
        if not self.engine:
            return
        
        control = self.engine.controls.get(control_id)
        if control:
            details = f"""
<h3>{control.name}</h3>
<p><b>ID:</b> {control.control_id}</p>
<p><b>Layer:</b> {control.layer.value.title()}</p>
<p><b>Type:</b> {control.control_type.value.title()}</p>
<p><b>Effectiveness:</b> {control.effectiveness * 100:.0f}%</p>
<p><b>Owner:</b> {control.owner}</p>
<p><b>Description:</b> {control.description}</p>
<h4>Dependencies:</h4>
<ul>{''.join(f'<li>{d}</li>' for d in control.dependencies) or '<li>None</li>'}</ul>
<h4>Gaps:</h4>
<ul>{''.join(f'<li>{g}</li>' for g in control.gaps) or '<li>None identified</li>'}</ul>
            """
            self.control_details.setHtml(details)
    
    def on_diagram_selected(self, current, previous):
        """Handle diagram selection"""
        pass
    
    def on_review_selected(self, current, previous):
        """Handle review selection"""
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
        
        threat = self.engine.threat_vectors.get(threat_id)
        if threat:
            self.entry_points_list.clear()
            for ep in threat.entry_points:
                self.entry_points_list.addItem(ep)
            
            self.mitigating_controls_list.clear()
            for mc in threat.mitigating_controls:
                self.mitigating_controls_list.addItem(mc)
            
            self.residual_risk_label.setText(threat.residual_risk.value.title())
    
    def on_framework_control_selected(self, current, previous):
        """Handle framework control selection"""
        pass
    
    def load_framework(self):
        """Load selected framework controls"""
        if not self.engine:
            return
        
        framework_name = self.framework_combo.currentText().replace(" ", "_").upper()
        controls = self.engine.compliance_frameworks.get(framework_name, {})
        
        self.framework_tree.clear()
        
        def add_items(parent, data, prefix=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        item = QTreeWidgetItem(parent, [key])
                        add_items(item, value, key)
                    elif isinstance(value, list):
                        item = QTreeWidgetItem(parent, [key])
                        for v in value:
                            QTreeWidgetItem(item, [str(v)])
                    else:
                        QTreeWidgetItem(parent, [f"{key}: {value}"])
        
        add_items(self.framework_tree, controls)
        self.framework_tree.expandAll()
    
    # Dialog methods
    def new_review_dialog(self):
        """Show new review dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("New Architecture Review")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        name_input = QLineEdit()
        name_input.setStyleSheet(self.get_input_style())
        form.addRow("Review Name:", name_input)
        
        scope_input = QTextEdit()
        scope_input.setMaximumHeight(100)
        scope_input.setStyleSheet(self.get_text_style())
        form.addRow("Scope:", scope_input)
        
        reviewer_input = QLineEdit()
        reviewer_input.setStyleSheet(self.get_input_style())
        form.addRow("Reviewer:", reviewer_input)
        
        layout.addLayout(form)
        
        # Layers selection
        layers_group = QGroupBox("Layers to Review")
        layers_group.setStyleSheet(self.get_group_style())
        layers_layout = QVBoxLayout(layers_group)
        
        for layer in ArchitectureLayer:
            cb = QCheckBox(layer.value.title())
            cb.setStyleSheet("color: white;")
            layers_layout.addWidget(cb)
        
        layout.addWidget(layers_group)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.status_message.emit("Architecture review created")
    
    def new_control_dialog(self):
        """Show new control dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Security Control")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        id_input = QLineEdit()
        id_input.setStyleSheet(self.get_input_style())
        form.addRow("Control ID:", id_input)
        
        name_input = QLineEdit()
        name_input.setStyleSheet(self.get_input_style())
        form.addRow("Name:", name_input)
        
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(80)
        desc_input.setStyleSheet(self.get_text_style())
        form.addRow("Description:", desc_input)
        
        layer_combo = QComboBox()
        for layer in ArchitectureLayer:
            layer_combo.addItem(layer.value.title(), layer)
        layer_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Layer:", layer_combo)
        
        type_combo = QComboBox()
        for ctype in ControlType:
            type_combo.addItem(ctype.value.title(), ctype)
        type_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Type:", type_combo)
        
        effectiveness_spin = QDoubleSpinBox()
        effectiveness_spin.setRange(0.0, 1.0)
        effectiveness_spin.setSingleStep(0.1)
        effectiveness_spin.setValue(0.8)
        effectiveness_spin.setStyleSheet("background: #252540; color: white;")
        form.addRow("Effectiveness:", effectiveness_spin)
        
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
            self.status_message.emit("Security control added")
    
    def new_diagram_dialog(self):
        """Show new diagram dialog"""
        self.status_message.emit("New diagram dialog opened")
    
    def new_threat_dialog(self):
        """Show new threat dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Threat Vector")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        name_input = QLineEdit()
        name_input.setStyleSheet(self.get_input_style())
        form.addRow("Name:", name_input)
        
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(80)
        desc_input.setStyleSheet(self.get_text_style())
        form.addRow("Description:", desc_input)
        
        surface_input = QLineEdit()
        surface_input.setStyleSheet(self.get_input_style())
        form.addRow("Attack Surface:", surface_input)
        
        likelihood_spin = QDoubleSpinBox()
        likelihood_spin.setRange(0.0, 1.0)
        likelihood_spin.setSingleStep(0.1)
        likelihood_spin.setValue(0.5)
        likelihood_spin.setStyleSheet("background: #252540; color: white;")
        form.addRow("Likelihood:", likelihood_spin)
        
        impact_spin = QDoubleSpinBox()
        impact_spin.setRange(0.0, 1.0)
        impact_spin.setSingleStep(0.1)
        impact_spin.setValue(0.5)
        impact_spin.setStyleSheet("background: #252540; color: white;")
        form.addRow("Impact:", impact_spin)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.status_message.emit("Threat vector added")
    
    # Action methods
    def edit_control(self):
        """Edit selected control"""
        self.status_message.emit("Edit control")
    
    def assess_control(self):
        """Assess selected control"""
        self.status_message.emit("Control assessment started")
    
    def delete_control(self):
        """Delete selected control"""
        reply = QMessageBox.question(
            self, "Confirm Delete",
            "Are you sure you want to delete this control?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.status_message.emit("Control deleted")
    
    def validate_diagram(self):
        """Validate selected diagram"""
        self.status_message.emit("Diagram validation started")
    
    def approve_review(self):
        """Approve selected review"""
        self.status_message.emit("Review approved")
    
    def reject_review(self):
        """Reject selected review"""
        self.status_message.emit("Review rejected")
    
    def calculate_threat_risk(self):
        """Calculate risk for selected threat"""
        self.status_message.emit("Risk calculated")
    
    def recommend_patterns(self):
        """Show pattern recommendations dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Pattern Recommendations")
        dialog.setMinimumWidth(600)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        # Requirements input
        req_label = QLabel("Enter your security requirements:")
        req_label.setStyleSheet("color: #00d4ff; font-weight: bold;")
        layout.addWidget(req_label)
        
        req_input = QTextEdit()
        req_input.setPlaceholderText("e.g., API security, network segmentation, zero trust...")
        req_input.setMaximumHeight(100)
        req_input.setStyleSheet(self.get_text_style())
        layout.addWidget(req_input)
        
        analyze_btn = QPushButton("🔍 Analyze Requirements")
        analyze_btn.setStyleSheet(self.get_action_button_style())
        layout.addWidget(analyze_btn)
        
        results_label = QLabel("Recommended Patterns:")
        results_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        layout.addWidget(results_label)
        
        results_list = QListWidget()
        results_list.setStyleSheet(self.get_list_style())
        layout.addWidget(results_list)
        
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(self.get_button_style())
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        
        dialog.exec()
    
    def export_architecture(self):
        """Export architecture data"""
        if self.engine:
            asyncio.get_event_loop().run_until_complete(self.engine.export_architecture())
            self.status_message.emit("Architecture data exported")
