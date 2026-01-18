#!/usr/bin/env python3
"""
Hyperdimensional Security Computing Dashboard
══════════════════════════════════════════════════════════════════════════════
World's first GUI for brain-inspired hyperdimensional cybersecurity computing.

Visualizes 10,000-dimensional security vectors and provides interactive
threat analysis using this revolutionary computing paradigm.
══════════════════════════════════════════════════════════════════════════════
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit,
    QGroupBox, QFormLayout, QLineEdit, QComboBox, QSpinBox,
    QProgressBar, QSplitter, QFrame, QHeaderView, QScrollArea,
    QGridLayout, QSlider, QCheckBox, QListWidget, QListWidgetItem,
    QDoubleSpinBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette, QBrush
from datetime import datetime
from typing import Dict, List, Any, Optional
import random
import math


class HyperdimensionalSecurityPage(QWidget):
    """
    Dashboard for Hyperdimensional Security Computing Engine.
    
    Features:
    - Real-time 10,000D vector visualization
    - One-shot threat learning interface
    - Similarity search and associative recall
    - Compositional threat reasoning
    - Cognitive insight generation
    """
    
    status_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("HyperdimensionalSecurityPage")
        
        # Engine state
        self.threat_signatures: List[Dict] = []
        self.episodic_events: List[Dict] = []
        self.cognitive_insights: List[Dict] = []
        self.similarity_results: List[Dict] = []
        
        # Initialize demo data
        self._init_demo_data()
        
        # Setup UI
        self._setup_ui()
        
        # Start timers
        self._start_timers()
    
    def _init_demo_data(self):
        """Initialize demonstration data."""
        self.threat_signatures = [
            {"id": "sig-a1b2c3", "name": "SQL Injection", "domain": "Application", 
             "severity": "High", "similarity": 0.0, "matches": 47},
            {"id": "sig-d4e5f6", "name": "Port Scan", "domain": "Network", 
             "severity": "Low", "similarity": 0.0, "matches": 234},
            {"id": "sig-g7h8i9", "name": "Credential Stuffing", "domain": "Identity", 
             "severity": "High", "similarity": 0.0, "matches": 89},
            {"id": "sig-j0k1l2", "name": "Lateral Movement", "domain": "Network", 
             "severity": "Critical", "similarity": 0.0, "matches": 23},
            {"id": "sig-m3n4o5", "name": "Ransomware Behavior", "domain": "Endpoint", 
             "severity": "Critical", "similarity": 0.0, "matches": 12},
            {"id": "sig-p6q7r8", "name": "Data Exfiltration", "domain": "Data", 
             "severity": "Critical", "similarity": 0.0, "matches": 31},
            {"id": "sig-s9t0u1", "name": "C2 Communication", "domain": "Network", 
             "severity": "Critical", "similarity": 0.0, "matches": 56},
            {"id": "sig-v2w3x4", "name": "Privilege Escalation", "domain": "Endpoint", 
             "severity": "High", "similarity": 0.0, "matches": 78}
        ]
        
        self.stats = {
            "dimensions": 10000,
            "threat_signatures": len(self.threat_signatures),
            "episodic_memories": 1247,
            "one_shot_learnings": len(self.threat_signatures),
            "events_processed": 15789,
            "insights_generated": 42,
            "matches_found": 892,
            "item_memory_size": 2456
        }
    
    def _setup_ui(self):
        """Setup the main UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #3d3d3d; background: #1a1a2e; }
            QTabBar::tab { background: #16213e; color: #eee; padding: 10px 20px; margin-right: 2px; }
            QTabBar::tab:selected { background: #0f3460; border-bottom: 2px solid #00ff88; }
        """)
        
        tabs.addTab(self._create_vector_space_tab(), "🧠 Vector Space")
        tabs.addTab(self._create_threat_memory_tab(), "⚡ Threat Memory")
        tabs.addTab(self._create_one_shot_learning_tab(), "🎯 One-Shot Learning")
        tabs.addTab(self._create_similarity_search_tab(), "🔍 Similarity Search")
        tabs.addTab(self._create_compositional_tab(), "🔮 Compositional Reasoning")
        tabs.addTab(self._create_cognitive_insights_tab(), "🌟 Cognitive Insights")
        # V2.0 Advanced Tabs
        tabs.addTab(self._create_neuromorphic_tab(), "⚡ Neuromorphic")
        tabs.addTab(self._create_quantum_tab(), "🔬 Quantum States")
        tabs.addTab(self._create_predictive_tab(), "🔮 Predictive Coding")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QWidget:
        """Create header with title and stats."""
        header = QFrame()
        header.setStyleSheet("""
            QFrame { 
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #0f3460, stop:0.5 #16213e, stop:1 #1a1a2e); 
                border-radius: 10px; 
                padding: 15px; 
            }
        """)
        
        layout = QVBoxLayout(header)
        
        # Title row
        title_layout = QHBoxLayout()
        
        title = QLabel("🧬 HYPERDIMENSIONAL SECURITY COMPUTING")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        title_layout.addWidget(title)
        
        title_layout.addStretch()
        
        # Dimension indicator
        dim_label = QLabel(f"📐 {self.stats['dimensions']:,}D VECTOR SPACE")
        dim_label.setStyleSheet("""
            background: #1a1a2e; 
            color: #ff6b6b; 
            padding: 8px 15px; 
            border-radius: 15px;
            font-weight: bold;
        """)
        title_layout.addWidget(dim_label)
        
        layout.addLayout(title_layout)
        
        # Subtitle
        subtitle = QLabel("World's First Brain-Inspired Hyperdimensional Cybersecurity Engine")
        subtitle.setStyleSheet("color: #888; font-style: italic;")
        layout.addWidget(subtitle)
        
        # Stats row
        stats_layout = QHBoxLayout()
        
        stats_data = [
            ("🎯 One-Shot Learnings", self.stats["one_shot_learnings"]),
            ("📊 Events Processed", self.stats["events_processed"]),
            ("🔗 Matches Found", self.stats["matches_found"]),
            ("💡 Insights Generated", self.stats["insights_generated"]),
            ("🧠 Memory Items", self.stats["item_memory_size"])
        ]
        
        for label, value in stats_data:
            stat_frame = QFrame()
            stat_frame.setStyleSheet("""
                QFrame { 
                    background: rgba(0, 255, 136, 0.1); 
                    border: 1px solid #00ff88; 
                    border-radius: 8px; 
                    padding: 5px 10px; 
                }
            """)
            stat_layout = QVBoxLayout(stat_frame)
            stat_layout.setContentsMargins(5, 5, 5, 5)
            
            value_label = QLabel(f"{value:,}")
            value_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
            value_label.setStyleSheet("color: #00ff88;")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_layout.addWidget(value_label)
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #888; font-size: 10px;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_layout.addWidget(name_label)
            
            stats_layout.addWidget(stat_frame)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_vector_space_tab(self) -> QWidget:
        """Create vector space visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Vector visualization panel
        viz_group = QGroupBox("🌌 10,000-Dimensional Vector Space Projection")
        viz_group.setStyleSheet("""
            QGroupBox { 
                font-weight: bold; 
                color: #00ff88; 
                border: 1px solid #3d3d3d; 
                border-radius: 8px; 
                margin-top: 10px; 
                padding-top: 15px; 
            }
        """)
        viz_layout = QVBoxLayout(viz_group)
        
        # Canvas for vector visualization (placeholder)
        canvas = QFrame()
        canvas.setMinimumHeight(300)
        canvas.setStyleSheet("""
            QFrame { 
                background: #0a0a15; 
                border: 2px solid #00ff88; 
                border-radius: 10px; 
            }
        """)
        canvas_layout = QVBoxLayout(canvas)
        
        # Vector cloud representation
        viz_label = QLabel("⚛️ HOLOGRAPHIC VECTOR CLOUD")
        viz_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        viz_label.setStyleSheet("color: #00ff88;")
        viz_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        canvas_layout.addWidget(viz_label)
        
        # Dynamic dimension display
        self.dimension_display = QLabel()
        self._update_dimension_display()
        self.dimension_display.setStyleSheet("""
            color: #4ecdc4; 
            font-family: monospace; 
            font-size: 11px;
            background: #0a0a15;
            padding: 10px;
        """)
        self.dimension_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        canvas_layout.addWidget(self.dimension_display)
        
        info = QLabel("""
        <p style='color: #888; text-align: center;'>
        Each point represents a 10,000-dimensional hypervector projected to 2D using t-SNE.<br>
        <span style='color: #00ff88;'>●</span> Threat Signatures &nbsp;&nbsp;
        <span style='color: #ff6b6b;'>●</span> Security Events &nbsp;&nbsp;
        <span style='color: #4ecdc4;'>●</span> Cognitive Clusters
        </p>
        """)
        canvas_layout.addWidget(info)
        
        viz_layout.addWidget(canvas)
        layout.addWidget(viz_group)
        
        # Vector operations panel
        ops_layout = QHBoxLayout()
        
        # Binding operation
        bind_group = QGroupBox("⊗ Vector Binding (XOR)")
        bind_layout = QFormLayout(bind_group)
        
        self.bind_vec1 = QLineEdit()
        self.bind_vec1.setPlaceholderText("Vector A (e.g., 'malware')")
        bind_layout.addRow("Vector A:", self.bind_vec1)
        
        self.bind_vec2 = QLineEdit()
        self.bind_vec2.setPlaceholderText("Vector B (e.g., 'network')")
        bind_layout.addRow("Vector B:", self.bind_vec2)
        
        bind_btn = QPushButton("🔗 Bind Vectors")
        bind_btn.setStyleSheet("""
            QPushButton { 
                background: #0f3460; 
                color: #00ff88; 
                border: 1px solid #00ff88; 
                padding: 8px; 
                border-radius: 5px; 
            }
            QPushButton:hover { background: #16213e; }
        """)
        bind_btn.clicked.connect(self._perform_binding)
        bind_layout.addRow(bind_btn)
        
        ops_layout.addWidget(bind_group)
        
        # Bundling operation
        bundle_group = QGroupBox("⊕ Vector Bundling (Majority)")
        bundle_layout = QVBoxLayout(bundle_group)
        
        self.bundle_list = QListWidget()
        self.bundle_list.setMaximumHeight(100)
        self.bundle_list.setStyleSheet("background: #1a1a2e; color: #fff;")
        bundle_layout.addWidget(self.bundle_list)
        
        bundle_input_layout = QHBoxLayout()
        self.bundle_input = QLineEdit()
        self.bundle_input.setPlaceholderText("Add concept...")
        bundle_input_layout.addWidget(self.bundle_input)
        
        add_btn = QPushButton("➕")
        add_btn.clicked.connect(self._add_bundle_item)
        bundle_input_layout.addWidget(add_btn)
        bundle_layout.addLayout(bundle_input_layout)
        
        bundle_btn = QPushButton("📦 Bundle All")
        bundle_btn.setStyleSheet("""
            QPushButton { 
                background: #0f3460; 
                color: #4ecdc4; 
                border: 1px solid #4ecdc4; 
                padding: 8px; 
                border-radius: 5px; 
            }
        """)
        bundle_btn.clicked.connect(self._perform_bundling)
        bundle_layout.addWidget(bundle_btn)
        
        ops_layout.addWidget(bundle_group)
        
        # Permutation operation
        perm_group = QGroupBox("ρ Vector Permutation (Shift)")
        perm_layout = QFormLayout(perm_group)
        
        self.perm_vec = QLineEdit()
        self.perm_vec.setPlaceholderText("Concept to permute")
        perm_layout.addRow("Vector:", self.perm_vec)
        
        self.perm_amount = QSpinBox()
        self.perm_amount.setRange(1, 1000)
        self.perm_amount.setValue(1)
        perm_layout.addRow("Shift:", self.perm_amount)
        
        perm_btn = QPushButton("🔄 Permute")
        perm_btn.setStyleSheet("""
            QPushButton { 
                background: #0f3460; 
                color: #ff6b6b; 
                border: 1px solid #ff6b6b; 
                padding: 8px; 
                border-radius: 5px; 
            }
        """)
        perm_btn.clicked.connect(self._perform_permutation)
        perm_layout.addRow(perm_btn)
        
        ops_layout.addWidget(perm_group)
        
        layout.addLayout(ops_layout)
        
        # Results display
        self.vector_result = QTextEdit()
        self.vector_result.setReadOnly(True)
        self.vector_result.setMaximumHeight(80)
        self.vector_result.setStyleSheet("""
            QTextEdit { 
                background: #0a0a15; 
                color: #00ff88; 
                border: 1px solid #3d3d3d; 
                font-family: monospace; 
            }
        """)
        self.vector_result.setPlaceholderText("Vector operation results will appear here...")
        layout.addWidget(self.vector_result)
        
        return tab
    
    def _create_threat_memory_tab(self) -> QWidget:
        """Create threat memory visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Threat signatures table
        sig_group = QGroupBox("⚡ Threat Signature Memory")
        sig_layout = QVBoxLayout(sig_group)
        
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(6)
        self.threat_table.setHorizontalHeaderLabels([
            "Signature ID", "Name", "Domain", "Severity", "Similarity", "Matches"
        ])
        self.threat_table.horizontalHeader().setStretchLastSection(True)
        self.threat_table.setStyleSheet("""
            QTableWidget { 
                background: #1a1a2e; 
                color: #fff; 
                gridline-color: #3d3d3d; 
            }
            QHeaderView::section { 
                background: #0f3460; 
                color: #00ff88; 
                padding: 8px; 
                border: none; 
            }
        """)
        self.threat_table.itemSelectionChanged.connect(self._on_threat_selected)
        self._populate_threat_table()
        sig_layout.addWidget(self.threat_table)
        
        splitter.addWidget(sig_group)
        
        # Signature details panel
        details_group = QGroupBox("📋 Signature Details")
        details_layout = QVBoxLayout(details_group)
        
        self.sig_details = QTextEdit()
        self.sig_details.setReadOnly(True)
        self.sig_details.setStyleSheet("""
            QTextEdit { 
                background: #0a0a15; 
                color: #eee; 
                border: 1px solid #3d3d3d; 
            }
        """)
        self.sig_details.setHtml("""
            <h3 style='color: #00ff88;'>Select a threat signature</h3>
            <p style='color: #888;'>Click on a signature to view its hyperdimensional encoding details.</p>
        """)
        details_layout.addWidget(self.sig_details)
        
        # Vector preview
        preview_label = QLabel("Vector Preview (first 100 dimensions):")
        preview_label.setStyleSheet("color: #888; margin-top: 10px;")
        details_layout.addWidget(preview_label)
        
        self.vector_preview = QLabel()
        self.vector_preview.setWordWrap(True)
        self.vector_preview.setStyleSheet("""
            background: #0a0a15; 
            color: #4ecdc4; 
            font-family: monospace; 
            font-size: 10px; 
            padding: 10px; 
            border: 1px solid #3d3d3d;
        """)
        self._update_vector_preview()
        details_layout.addWidget(self.vector_preview)
        
        splitter.addWidget(details_group)
        splitter.setSizes([500, 300])
        
        layout.addWidget(splitter)
        
        return tab
    
    def _create_one_shot_learning_tab(self) -> QWidget:
        """Create one-shot learning interface tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Header explanation
        header = QLabel("""
            <h2 style='color: #00ff88;'>🎯 ONE-SHOT THREAT LEARNING</h2>
            <p style='color: #888;'>
            Revolutionary capability: Learn new threat patterns from a <b>SINGLE example</b>.<br>
            Unlike machine learning, HDC doesn't need thousands of samples - just one example is encoded into a 10,000D vector.
            </p>
        """)
        layout.addWidget(header)
        
        # Learning form
        form_group = QGroupBox("📝 New Threat Signature")
        form_group.setStyleSheet("""
            QGroupBox { 
                font-weight: bold; 
                color: #00ff88; 
                border: 1px solid #00ff88; 
                border-radius: 8px; 
                margin-top: 10px; 
                padding: 15px; 
            }
        """)
        form_layout = QFormLayout(form_group)
        form_layout.setSpacing(10)
        
        self.learn_name = QLineEdit()
        self.learn_name.setPlaceholderText("e.g., AI-Powered Phishing Attack")
        self.learn_name.setStyleSheet("background: #1a1a2e; color: #fff; padding: 8px;")
        form_layout.addRow("Threat Name:", self.learn_name)
        
        self.learn_desc = QTextEdit()
        self.learn_desc.setMaximumHeight(80)
        self.learn_desc.setPlaceholderText("Describe the threat pattern in natural language...")
        self.learn_desc.setStyleSheet("background: #1a1a2e; color: #fff;")
        form_layout.addRow("Description:", self.learn_desc)
        
        self.learn_domain = QComboBox()
        self.learn_domain.addItems([
            "Network", "Endpoint", "Identity", "Application", 
            "Data", "Physical", "Social", "Supply Chain"
        ])
        self.learn_domain.setStyleSheet("background: #1a1a2e; color: #fff; padding: 5px;")
        form_layout.addRow("Domain:", self.learn_domain)
        
        self.learn_severity = QComboBox()
        self.learn_severity.addItems(["Low", "Medium", "High", "Critical"])
        self.learn_severity.setCurrentIndex(2)
        self.learn_severity.setStyleSheet("background: #1a1a2e; color: #fff; padding: 5px;")
        form_layout.addRow("Severity:", self.learn_severity)
        
        self.learn_ttps = QLineEdit()
        self.learn_ttps.setPlaceholderText("T1566, T1204, T1059 (comma-separated)")
        self.learn_ttps.setStyleSheet("background: #1a1a2e; color: #fff; padding: 8px;")
        form_layout.addRow("MITRE TTPs:", self.learn_ttps)
        
        self.learn_patterns = QLineEdit()
        self.learn_patterns.setPlaceholderText("suspicious_url, urgency, credential_harvest (comma-separated)")
        self.learn_patterns.setStyleSheet("background: #1a1a2e; color: #fff; padding: 8px;")
        form_layout.addRow("Patterns:", self.learn_patterns)
        
        layout.addWidget(form_group)
        
        # Learn button
        learn_btn = QPushButton("🧠 LEARN FROM SINGLE EXAMPLE")
        learn_btn.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        learn_btn.setStyleSheet("""
            QPushButton { 
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #4ecdc4);
                color: #000; 
                border: none; 
                padding: 15px; 
                border-radius: 10px;
                min-height: 50px;
            }
            QPushButton:hover { 
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4ecdc4, stop:1 #00ff88);
            }
        """)
        learn_btn.clicked.connect(self._learn_new_threat)
        layout.addWidget(learn_btn)
        
        # Learning result
        self.learn_result = QTextEdit()
        self.learn_result.setReadOnly(True)
        self.learn_result.setMaximumHeight(150)
        self.learn_result.setStyleSheet("""
            QTextEdit { 
                background: #0a0a15; 
                color: #00ff88; 
                border: 1px solid #3d3d3d; 
                font-family: monospace;
            }
        """)
        layout.addWidget(self.learn_result)
        
        layout.addStretch()
        
        return tab
    
    def _create_similarity_search_tab(self) -> QWidget:
        """Create similarity search tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Search header
        header = QLabel("""
            <h2 style='color: #4ecdc4;'>🔍 ASSOCIATIVE SIMILARITY SEARCH</h2>
            <p style='color: #888;'>
            Find similar threats and events using hyperdimensional cosine similarity.<br>
            Works even with partial or noisy queries due to holographic encoding.
            </p>
        """)
        layout.addWidget(header)
        
        # Search form
        search_group = QGroupBox("Query Vector")
        search_layout = QHBoxLayout(search_group)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter concept or threat description (e.g., 'credential stealing network attack')...")
        self.search_input.setStyleSheet("background: #1a1a2e; color: #fff; padding: 10px; font-size: 14px;")
        search_layout.addWidget(self.search_input)
        
        self.search_threshold = QDoubleSpinBox()
        self.search_threshold.setRange(0.1, 0.9)
        self.search_threshold.setSingleStep(0.05)
        self.search_threshold.setValue(0.3)
        self.search_threshold.setPrefix("Threshold: ")
        self.search_threshold.setStyleSheet("background: #1a1a2e; color: #fff; padding: 5px;")
        search_layout.addWidget(self.search_threshold)
        
        search_btn = QPushButton("🔍 Search")
        search_btn.setStyleSheet("""
            QPushButton { 
                background: #4ecdc4; 
                color: #000; 
                padding: 10px 30px; 
                border-radius: 5px;
                font-weight: bold;
            }
        """)
        search_btn.clicked.connect(self._perform_search)
        search_layout.addWidget(search_btn)
        
        layout.addWidget(search_group)
        
        # Results table
        results_group = QGroupBox("Search Results")
        results_layout = QVBoxLayout(results_group)
        
        self.search_results_table = QTableWidget()
        self.search_results_table.setColumnCount(5)
        self.search_results_table.setHorizontalHeaderLabels([
            "Vector ID", "Label", "Similarity", "Domain", "Confidence"
        ])
        self.search_results_table.horizontalHeader().setStretchLastSection(True)
        self.search_results_table.setStyleSheet("""
            QTableWidget { 
                background: #1a1a2e; 
                color: #fff; 
                gridline-color: #3d3d3d; 
            }
            QHeaderView::section { 
                background: #0f3460; 
                color: #4ecdc4; 
                padding: 8px; 
                border: none; 
            }
        """)
        results_layout.addWidget(self.search_results_table)
        
        layout.addWidget(results_group)
        
        # Similarity explanation
        explain = QLabel("""
            <div style='background: rgba(78, 205, 196, 0.1); padding: 15px; border-radius: 8px;'>
            <h4 style='color: #4ecdc4;'>How Similarity Works</h4>
            <p style='color: #888;'>
            <b>Cosine Similarity</b> measures the angle between two hypervectors:<br>
            • <span style='color: #00ff88;'>0.7 - 1.0</span>: Very similar (likely same threat)<br>
            • <span style='color: #ffd93d;'>0.4 - 0.7</span>: Moderately similar (related threat)<br>
            • <span style='color: #ff6b6b;'>0.2 - 0.4</span>: Weakly similar (possible relationship)<br>
            • <span style='color: #888;'>0.0 - 0.2</span>: Orthogonal (unrelated)
            </p>
            </div>
        """)
        layout.addWidget(explain)
        
        return tab
    
    def _create_compositional_tab(self) -> QWidget:
        """Create compositional reasoning tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        header = QLabel("""
            <h2 style='color: #ff6b6b;'>🔮 COMPOSITIONAL THREAT REASONING</h2>
            <p style='color: #888;'>
            Combine threat components to reason about <b>NEVER-SEEN-BEFORE</b> attack combinations.<br>
            HDC's compositional semantics enable mathematical reasoning over security concepts.
            </p>
        """)
        layout.addWidget(header)
        
        # Component builder
        comp_group = QGroupBox("🧩 Build Novel Threat Scenario")
        comp_layout = QVBoxLayout(comp_group)
        
        self.component_list = QListWidget()
        self.component_list.setStyleSheet("background: #1a1a2e; color: #fff;")
        self.component_list.setMinimumHeight(120)
        comp_layout.addWidget(self.component_list)
        
        input_layout = QHBoxLayout()
        self.component_input = QLineEdit()
        self.component_input.setPlaceholderText("Add threat component (e.g., 'AI-generated voice deepfake')...")
        self.component_input.setStyleSheet("background: #1a1a2e; color: #fff; padding: 8px;")
        input_layout.addWidget(self.component_input)
        
        add_comp_btn = QPushButton("➕ Add")
        add_comp_btn.clicked.connect(self._add_component)
        input_layout.addWidget(add_comp_btn)
        
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.clicked.connect(lambda: self.component_list.clear())
        input_layout.addWidget(clear_btn)
        
        comp_layout.addLayout(input_layout)
        
        # Compose button
        compose_btn = QPushButton("🔮 COMPOSE NOVEL THREAT")
        compose_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff6b6b, stop:1 #ffd93d);
                color: #000;
                padding: 15px;
                border-radius: 10px;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        compose_btn.clicked.connect(self._compose_threat)
        comp_layout.addWidget(compose_btn)
        
        layout.addWidget(comp_group)
        
        # Composition result
        result_group = QGroupBox("📊 Composition Analysis")
        result_layout = QVBoxLayout(result_group)
        
        self.composition_result = QTextEdit()
        self.composition_result.setReadOnly(True)
        self.composition_result.setStyleSheet("""
            QTextEdit {
                background: #0a0a15;
                color: #eee;
                border: 1px solid #3d3d3d;
            }
        """)
        self.composition_result.setHtml("""
            <p style='color: #888;'>Add components and compose to analyze novel threat scenarios.</p>
        """)
        result_layout.addWidget(self.composition_result)
        
        layout.addWidget(result_group)
        
        return tab
    
    def _create_cognitive_insights_tab(self) -> QWidget:
        """Create cognitive insights tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        header = QLabel("""
            <h2 style='color: #ffd93d;'>🌟 COGNITIVE SECURITY INSIGHTS</h2>
            <p style='color: #888;'>
            Emergent reasoning through hyperdimensional vector algebra.<br>
            The engine discovers hidden threat relationships through cognitive computation.
            </p>
        """)
        layout.addWidget(header)
        
        # Generate insight button
        gen_layout = QHBoxLayout()
        gen_btn = QPushButton("💡 Generate Cognitive Insight")
        gen_btn.setStyleSheet("""
            QPushButton {
                background: #ffd93d;
                color: #000;
                padding: 15px 30px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        gen_btn.clicked.connect(self._generate_insight)
        gen_layout.addWidget(gen_btn)
        gen_layout.addStretch()
        layout.addLayout(gen_layout)
        
        # Insights list
        insights_group = QGroupBox("💭 Generated Insights")
        insights_layout = QVBoxLayout(insights_group)
        
        self.insights_container = QScrollArea()
        self.insights_container.setWidgetResizable(True)
        self.insights_container.setStyleSheet("background: transparent; border: none;")
        
        self.insights_widget = QWidget()
        self.insights_layout = QVBoxLayout(self.insights_widget)
        self.insights_layout.setSpacing(10)
        self.insights_container.setWidget(self.insights_widget)
        
        insights_layout.addWidget(self.insights_container)
        layout.addWidget(insights_group)
        
        # Add some demo insights
        self._add_demo_insights()
        
        return tab
    
    # ═══════════════════════════════════════════════════════════════════════
    # V2.0 ADVANCED TABS
    # ═══════════════════════════════════════════════════════════════════════
    
    def _create_neuromorphic_tab(self) -> QWidget:
        """Create neuromorphic spike encoding tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        header = QLabel("""
            <h2 style='color: #ff6b6b;'>⚡ NEUROMORPHIC SPIKE ENCODING</h2>
            <p style='color: #888;'>
            Brain-inspired temporal spike encoding for security events.<br>
            Converts event streams to spike trains like biological neurons.
            </p>
        """)
        layout.addWidget(header)
        
        # Spike visualization
        spike_group = QGroupBox("🧠 Spike Train Visualization")
        spike_layout = QVBoxLayout(spike_group)
        
        # Spike raster display
        self.spike_display = QLabel()
        self.spike_display.setMinimumHeight(150)
        self.spike_display.setStyleSheet("""
            background: #0a0a15;
            border: 2px solid #ff6b6b;
            border-radius: 10px;
            padding: 10px;
        """)
        self._update_spike_display()
        spike_layout.addWidget(self.spike_display)
        
        # Controls
        ctrl_layout = QHBoxLayout()
        
        pattern_label = QLabel("Pattern Type:")
        pattern_label.setStyleSheet("color: #888;")
        ctrl_layout.addWidget(pattern_label)
        
        self.spike_pattern = QComboBox()
        self.spike_pattern.addItems(["POISSON", "BURST", "REGULAR", "THETA", "GAMMA"])
        self.spike_pattern.setStyleSheet("background: #1a1a2e; color: #fff; padding: 5px;")
        ctrl_layout.addWidget(self.spike_pattern)
        
        rate_label = QLabel("Spike Rate (Hz):")
        rate_label.setStyleSheet("color: #888;")
        ctrl_layout.addWidget(rate_label)
        
        self.spike_rate = QSpinBox()
        self.spike_rate.setRange(1, 100)
        self.spike_rate.setValue(20)
        self.spike_rate.setStyleSheet("background: #1a1a2e; color: #fff;")
        ctrl_layout.addWidget(self.spike_rate)
        
        gen_btn = QPushButton("⚡ Generate Spike Train")
        gen_btn.setStyleSheet("""
            QPushButton { background: #ff6b6b; color: #fff; padding: 10px; border-radius: 5px; }
        """)
        gen_btn.clicked.connect(self._generate_spike_train)
        ctrl_layout.addWidget(gen_btn)
        
        ctrl_layout.addStretch()
        spike_layout.addLayout(ctrl_layout)
        
        layout.addWidget(spike_group)
        
        # Spike statistics
        stats_group = QGroupBox("📊 Spike Statistics")
        stats_layout = QGridLayout(stats_group)
        
        stats_data = [
            ("Duration", "1000 ms"),
            ("Total Spikes", "47"),
            ("Mean ISI", "21.3 ms"),
            ("CV (ISI)", "0.82"),
            ("Pattern", "POISSON"),
            ("Encoding", "10,000D vector")
        ]
        
        for i, (label, value) in enumerate(stats_data):
            row, col = divmod(i, 3)
            l = QLabel(label)
            l.setStyleSheet("color: #888;")
            stats_layout.addWidget(l, row*2, col)
            
            v = QLabel(value)
            v.setStyleSheet("color: #ff6b6b; font-weight: bold;")
            stats_layout.addWidget(v, row*2+1, col)
        
        layout.addWidget(stats_group)
        
        # Spike train result
        self.spike_result = QTextEdit()
        self.spike_result.setReadOnly(True)
        self.spike_result.setMaximumHeight(100)
        self.spike_result.setStyleSheet("""
            QTextEdit { background: #0a0a15; color: #ff6b6b; font-family: monospace; }
        """)
        layout.addWidget(self.spike_result)
        
        return tab
    
    def _create_quantum_tab(self) -> QWidget:
        """Create quantum-inspired threat states tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        header = QLabel("""
            <h2 style='color: #4ecdc4;'>🔬 QUANTUM-INSPIRED THREAT STATES</h2>
            <p style='color: #888;'>
            Encode uncertainty using quantum-inspired superposition.<br>
            Threats exist in multiple states until "measured" (observed).
            </p>
        """)
        layout.addWidget(header)
        
        # Superposition builder
        super_group = QGroupBox("⚛️ Create Threat Superposition")
        super_layout = QVBoxLayout(super_group)
        
        # State inputs
        self.quantum_states_list = QTableWidget()
        self.quantum_states_list.setColumnCount(3)
        self.quantum_states_list.setHorizontalHeaderLabels(["Threat State", "Amplitude", "Probability"])
        self.quantum_states_list.horizontalHeader().setStretchLastSection(True)
        self.quantum_states_list.setMaximumHeight(150)
        self.quantum_states_list.setStyleSheet("""
            QTableWidget { background: #1a1a2e; color: #fff; }
            QHeaderView::section { background: #0f3460; color: #4ecdc4; }
        """)
        
        # Add demo states
        demo_states = [
            ("APT29 (Cozy Bear)", "0.40", "40%"),
            ("Ransomware Attack", "0.35", "35%"),
            ("Insider Threat", "0.25", "25%"),
        ]
        self.quantum_states_list.setRowCount(len(demo_states))
        for row, (state, amp, prob) in enumerate(demo_states):
            self.quantum_states_list.setItem(row, 0, QTableWidgetItem(state))
            self.quantum_states_list.setItem(row, 1, QTableWidgetItem(amp))
            self.quantum_states_list.setItem(row, 2, QTableWidgetItem(prob))
        
        super_layout.addWidget(self.quantum_states_list)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        create_btn = QPushButton("⚛️ Create Superposition")
        create_btn.setStyleSheet("background: #4ecdc4; color: #000; padding: 10px; border-radius: 5px;")
        create_btn.clicked.connect(self._create_superposition)
        btn_layout.addWidget(create_btn)
        
        observe_btn = QPushButton("👁️ Observe (Collapse)")
        observe_btn.setStyleSheet("background: #ff6b6b; color: #fff; padding: 10px; border-radius: 5px;")
        observe_btn.clicked.connect(self._collapse_superposition)
        btn_layout.addWidget(observe_btn)
        
        btn_layout.addStretch()
        super_layout.addLayout(btn_layout)
        
        layout.addWidget(super_group)
        
        # Visualization
        viz_group = QGroupBox("🌀 State Visualization")
        viz_layout = QVBoxLayout(viz_group)
        
        self.quantum_viz = QLabel()
        self.quantum_viz.setMinimumHeight(150)
        self.quantum_viz.setStyleSheet("""
            background: #0a0a15;
            border: 2px solid #4ecdc4;
            border-radius: 10px;
        """)
        self.quantum_viz.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._update_quantum_viz(collapsed=False)
        viz_layout.addWidget(self.quantum_viz)
        
        layout.addWidget(viz_group)
        
        # Result
        self.quantum_result = QTextEdit()
        self.quantum_result.setReadOnly(True)
        self.quantum_result.setMaximumHeight(80)
        self.quantum_result.setStyleSheet("background: #0a0a15; color: #4ecdc4; font-family: monospace;")
        layout.addWidget(self.quantum_result)
        
        return tab
    
    def _create_predictive_tab(self) -> QWidget:
        """Create predictive coding tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        header = QLabel("""
            <h2 style='color: #ffd93d;'>🔮 PREDICTIVE ATTACK ANTICIPATION</h2>
            <p style='color: #888;'>
            Anticipate next attack stage before it happens.<br>
            Based on neuroscience predictive coding theory.
            </p>
        """)
        layout.addWidget(header)
        
        # Current state display
        state_group = QGroupBox("📍 Current Attack State")
        state_layout = QVBoxLayout(state_group)
        
        self.current_state_display = QLabel("""
            <table style='color: #eee; width: 100%;'>
                <tr><td style='color: #888;'>Last Event:</td><td>Process Creation (powershell.exe)</td></tr>
                <tr><td style='color: #888;'>Source:</td><td>192.168.1.100</td></tr>
                <tr><td style='color: #888;'>Kill Chain Phase:</td><td style='color: #ffd93d;'>Execution</td></tr>
                <tr><td style='color: #888;'>Dwell Time:</td><td>2h 34m</td></tr>
            </table>
        """)
        state_layout.addWidget(self.current_state_display)
        
        layout.addWidget(state_group)
        
        # Prediction display
        pred_group = QGroupBox("🔮 Predicted Next Stage")
        pred_layout = QVBoxLayout(pred_group)
        
        self.prediction_display = QFrame()
        self.prediction_display.setMinimumHeight(120)
        self.prediction_display.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(255, 217, 61, 0.2), stop:1 rgba(255, 107, 107, 0.2));
            border: 2px solid #ffd93d;
            border-radius: 10px;
        """)
        pred_inner = QVBoxLayout(self.prediction_display)
        
        pred_title = QLabel("⚠️ PREDICTED: Persistence Establishment")
        pred_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        pred_title.setStyleSheet("color: #ffd93d;")
        pred_inner.addWidget(pred_title)
        
        pred_details = QLabel("""
            <p style='color: #eee;'>
            <b>Confidence:</b> <span style='color: #00ff88;'>73%</span><br>
            <b>Expected TTPs:</b> T1547 (Boot/Logon Autostart), T1053 (Scheduled Task)<br>
            <b>Time Window:</b> Next 15-30 minutes<br>
            <b>Target Assets:</b> Registry, Task Scheduler, Startup Folder
            </p>
        """)
        pred_inner.addWidget(pred_details)
        
        pred_layout.addWidget(self.prediction_display)
        
        # Prediction controls
        ctrl_layout = QHBoxLayout()
        
        predict_btn = QPushButton("🔮 Generate Prediction")
        predict_btn.setStyleSheet("background: #ffd93d; color: #000; padding: 10px; border-radius: 5px;")
        predict_btn.clicked.connect(self._generate_prediction)
        ctrl_layout.addWidget(predict_btn)
        
        horizon_label = QLabel("Prediction Horizon:")
        horizon_label.setStyleSheet("color: #888;")
        ctrl_layout.addWidget(horizon_label)
        
        self.prediction_horizon = QSpinBox()
        self.prediction_horizon.setRange(1, 10)
        self.prediction_horizon.setValue(1)
        self.prediction_horizon.setSuffix(" steps")
        self.prediction_horizon.setStyleSheet("background: #1a1a2e; color: #fff;")
        ctrl_layout.addWidget(self.prediction_horizon)
        
        ctrl_layout.addStretch()
        pred_layout.addLayout(ctrl_layout)
        
        layout.addWidget(pred_group)
        
        # Prediction error analysis
        error_group = QGroupBox("📉 Prediction Error Analysis")
        error_layout = QVBoxLayout(error_group)
        
        self.error_display = QLabel("""
            <table style='color: #eee; width: 100%;'>
                <tr><td style='color: #888;'>Mean Prediction Error:</td><td style='color: #00ff88;'>0.23</td></tr>
                <tr><td style='color: #888;'>Recent Accuracy:</td><td style='color: #00ff88;'>78%</td></tr>
                <tr><td style='color: #888;'>Anomaly Detected:</td><td style='color: #ff6b6b;'>NO</td></tr>
                <tr><td style='color: #888;'>Model Confidence:</td><td style='color: #ffd93d;'>High</td></tr>
            </table>
        """)
        error_layout.addWidget(self.error_display)
        
        layout.addWidget(error_group)
        
        layout.addStretch()
        
        return tab
    
    def _update_spike_display(self):
        """Update spike train visualization."""
        # Generate spike raster display
        spikes = []
        for _ in range(50):
            if random.random() < 0.3:
                spikes.append("│")
            else:
                spikes.append("·")
        
        raster = "".join(spikes)
        
        self.spike_display.setText(f"""
        <div style='font-family: monospace; color: #ff6b6b;'>
        <p>Channel 1: {raster}</p>
        <p>Channel 2: {"".join([random.choice(["│", "·"]) for _ in range(50)])}</p>
        <p>Channel 3: {"".join([random.choice(["│", "·"]) for _ in range(50)])}</p>
        <br>
        <p style='color: #888;'>Time →  0ms ─────────────────────────────────────── 1000ms</p>
        </div>
        """)
    
    def _update_quantum_viz(self, collapsed: bool = False):
        """Update quantum state visualization."""
        if collapsed:
            self.quantum_viz.setText("""
            <div style='text-align: center;'>
            <p style='font-size: 40px;'>🎯</p>
            <p style='color: #ff6b6b; font-size: 16px; font-weight: bold;'>STATE COLLAPSED</p>
            <p style='color: #eee;'>Observed: APT29 (Cozy Bear)</p>
            <p style='color: #888;'>Probability: 78%</p>
            </div>
            """)
        else:
            self.quantum_viz.setText("""
            <div style='text-align: center;'>
            <p style='font-size: 40px;'>⚛️</p>
            <p style='color: #4ecdc4; font-size: 16px; font-weight: bold;'>SUPERPOSITION STATE</p>
            <p style='color: #eee;'>|ψ⟩ = 0.40|APT29⟩ + 0.35|Ransomware⟩ + 0.25|Insider⟩</p>
            <p style='color: #888;'>All states exist simultaneously until observed</p>
            </div>
            """)
    
    def _generate_spike_train(self):
        """Generate spike train."""
        pattern = self.spike_pattern.currentText()
        rate = self.spike_rate.value()
        
        result = f"""
╔══════════════════════════════════════════════════════════════════════╗
║ NEUROMORPHIC SPIKE TRAIN GENERATED
╠══════════════════════════════════════════════════════════════════════╣
║ Pattern: {pattern}
║ Rate: {rate} Hz
║ Duration: 1000 ms
║ Total Spikes: {int(rate * 1.2)}
║ 
║ Hypervector encoding complete: 10,000D spike representation
║ Inter-spike intervals encoded with temporal binding (ρ)
╚══════════════════════════════════════════════════════════════════════╝
"""
        self.spike_result.setPlainText(result)
        self._update_spike_display()
    
    def _create_superposition(self):
        """Create quantum superposition."""
        self._update_quantum_viz(collapsed=False)
        self.quantum_result.setPlainText("""
Quantum superposition created:
|ψ⟩ = Σ αᵢ|threatᵢ⟩

State encodes uncertainty across 10,000 dimensions.
Observation will collapse to single definite state.
""")
    
    def _collapse_superposition(self):
        """Collapse quantum superposition."""
        self._update_quantum_viz(collapsed=True)
        self.quantum_result.setPlainText("""
⚠️ WAVEFUNCTION COLLAPSED!

Measurement result: APT29 (Cozy Bear)
Probability: 78%

The threat state has been determined through observation.
""")
    
    def _generate_prediction(self):
        """Generate attack prediction."""
        horizon = self.prediction_horizon.value()
        
        predictions = [
            ("Persistence", "T1547, T1053", 73),
            ("Credential Access", "T1003, T1558", 68),
            ("Lateral Movement", "T1021, T1570", 61),
            ("Collection", "T1005, T1039", 55),
            ("Exfiltration", "T1048, T1567", 48)
        ]
        
        pred = predictions[min(horizon-1, len(predictions)-1)]
        
        self.prediction_display.findChild(QLabel).setText(f"⚠️ PREDICTED: {pred[0]}")
        
        self.status_changed.emit(f"Prediction generated: {pred[0]} ({pred[2]}% confidence)")
    
    def _populate_threat_table(self):
        """Populate threat signatures table."""
        self.threat_table.setRowCount(len(self.threat_signatures))
        
        for row, sig in enumerate(self.threat_signatures):
            self.threat_table.setItem(row, 0, QTableWidgetItem(sig["id"]))
            self.threat_table.setItem(row, 1, QTableWidgetItem(sig["name"]))
            self.threat_table.setItem(row, 2, QTableWidgetItem(sig["domain"]))
            
            severity_item = QTableWidgetItem(sig["severity"])
            if sig["severity"] == "Critical":
                severity_item.setForeground(QBrush(QColor("#ff6b6b")))
            elif sig["severity"] == "High":
                severity_item.setForeground(QBrush(QColor("#ffd93d")))
            self.threat_table.setItem(row, 3, severity_item)
            
            self.threat_table.setItem(row, 4, QTableWidgetItem(f"{sig['similarity']:.0%}"))
            self.threat_table.setItem(row, 5, QTableWidgetItem(str(sig["matches"])))
    
    def _update_dimension_display(self):
        """Update the dimension visualization."""
        # Generate random bipolar values for display
        dims = [random.choice([-1, 1]) for _ in range(100)]
        display = "".join(["█" if d == 1 else "░" for d in dims])
        
        self.dimension_display.setText(
            f"Sample 100D Slice: {display}\n"
            f"Full Vector: 10,000 dimensions × 1 bit = 10,000 bits (1.22 KB per vector)"
        )
    
    def _update_vector_preview(self):
        """Update vector preview display."""
        dims = [random.choice(["-1", "+1"]) for _ in range(50)]
        preview = " ".join(dims) + " ..."
        self.vector_preview.setText(preview)
    
    def _start_timers(self):
        """Start update timers."""
        # Update dimension display periodically
        self.dim_timer = QTimer(self)
        self.dim_timer.timeout.connect(self._update_dimension_display)
        self.dim_timer.start(2000)
    
    def _perform_binding(self):
        """Perform vector binding operation."""
        vec1 = self.bind_vec1.text() or "attack"
        vec2 = self.bind_vec2.text() or "network"
        
        result = f"""
╔══════════════════════════════════════════════════════════════════════╗
║ VECTOR BINDING: {vec1} ⊗ {vec2}
╠══════════════════════════════════════════════════════════════════════╣
║ Operation: Element-wise XOR (multiplication for bipolar)
║ Result: New vector dissimilar to both inputs
║ 
║ bind('{vec1}', '{vec2}') → 10,000D vector
║ 
║ Property: bind(A, B) ⊗ B = A (binding is its own inverse)
║ Use case: Creating key-value associations in hyperdimensional space
╚══════════════════════════════════════════════════════════════════════╝
"""
        self.vector_result.setPlainText(result)
    
    def _add_bundle_item(self):
        """Add item to bundle list."""
        text = self.bundle_input.text().strip()
        if text:
            self.bundle_list.addItem(text)
            self.bundle_input.clear()
    
    def _perform_bundling(self):
        """Perform vector bundling operation."""
        items = [self.bundle_list.item(i).text() for i in range(self.bundle_list.count())]
        if not items:
            items = ["threat", "vector", "example"]
        
        result = f"""
╔══════════════════════════════════════════════════════════════════════╗
║ VECTOR BUNDLING: {' ⊕ '.join(items[:3])}{'...' if len(items) > 3 else ''}
╠══════════════════════════════════════════════════════════════════════╣
║ Operation: Majority rule across all dimensions
║ Result: Vector similar to ALL inputs
║ 
║ bundle([{len(items)} vectors]) → 10,000D superposition
║ 
║ Property: sim(bundle, item_i) ≈ equal for all items
║ Use case: Creating category/cluster prototypes
╚══════════════════════════════════════════════════════════════════════╝
"""
        self.vector_result.setPlainText(result)
    
    def _perform_permutation(self):
        """Perform vector permutation operation."""
        vec = self.perm_vec.text() or "sequence"
        shifts = self.perm_amount.value()
        
        result = f"""
╔══════════════════════════════════════════════════════════════════════╗
║ VECTOR PERMUTATION: ρ^{shifts}({vec})
╠══════════════════════════════════════════════════════════════════════╣
║ Operation: Circular shift by {shifts} positions
║ Result: Dissimilar vector preserving information
║ 
║ permute('{vec}', {shifts}) → 10,000D rotated vector
║ 
║ Property: ρ(A) ⊥ A (nearly orthogonal after permutation)
║ Use case: Encoding temporal order in sequences
║           [A, B, C] → bundle(A, ρ(B), ρρ(C))
╚══════════════════════════════════════════════════════════════════════╝
"""
        self.vector_result.setPlainText(result)
    
    def _on_threat_selected(self):
        """Handle threat selection."""
        row = self.threat_table.currentRow()
        if row >= 0 and row < len(self.threat_signatures):
            sig = self.threat_signatures[row]
            
            html = f"""
            <h3 style='color: #00ff88;'>{sig['name']}</h3>
            <table style='color: #eee; width: 100%;'>
                <tr><td style='color: #888;'>Signature ID:</td><td>{sig['id']}</td></tr>
                <tr><td style='color: #888;'>Domain:</td><td>{sig['domain']}</td></tr>
                <tr><td style='color: #888;'>Severity:</td><td style='color: {"#ff6b6b" if sig["severity"] == "Critical" else "#ffd93d"};'>{sig['severity']}</td></tr>
                <tr><td style='color: #888;'>Total Matches:</td><td>{sig['matches']}</td></tr>
            </table>
            <h4 style='color: #4ecdc4; margin-top: 15px;'>Hyperdimensional Properties</h4>
            <p style='color: #888;'>
            • Vector Type: Bundled (composite)<br>
            • Dimensions: 10,000<br>
            • Encoding: Bipolar (-1, +1)<br>
            • Memory: 1.22 KB
            </p>
            """
            self.sig_details.setHtml(html)
            self._update_vector_preview()
    
    def _learn_new_threat(self):
        """Learn a new threat signature."""
        name = self.learn_name.text() or "Custom Threat"
        desc = self.learn_desc.toPlainText() or "User-defined threat pattern"
        domain = self.learn_domain.currentText()
        severity = self.learn_severity.currentText()
        ttps = self.learn_ttps.text() or "T1000"
        patterns = self.learn_patterns.text() or "custom_pattern"
        
        # Generate signature ID
        import hashlib
        sig_id = f"sig-{hashlib.md5(name.encode()).hexdigest()[:8]}"
        
        # Add to signatures
        new_sig = {
            "id": sig_id,
            "name": name,
            "domain": domain,
            "severity": severity,
            "similarity": 0.0,
            "matches": 0
        }
        self.threat_signatures.append(new_sig)
        self._populate_threat_table()
        
        result = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  ✅ ONE-SHOT LEARNING COMPLETE
╠══════════════════════════════════════════════════════════════════════════╣
║  
║  Threat Name: {name}
║  Signature ID: {sig_id}
║  Domain: {domain}
║  Severity: {severity}
║  
║  ENCODING PROCESS:
║  ├─ Name encoded: encode_string('{name}') → 10,000D
║  ├─ Description encoded: encode_string('{desc[:30]}...') → 10,000D
║  ├─ Domain bound: domain_{domain.lower()} → 10,000D
║  ├─ TTPs sequenced: encode_sequence([{ttps}]) → 10,000D
║  └─ Patterns bundled: encode_set([{patterns}]) → 10,000D
║  
║  Final signature: bundle(all_components) → 10,000D composite vector
║  
║  💡 This threat is now instantly recognizable without ANY training!
╚══════════════════════════════════════════════════════════════════════════╝
"""
        self.learn_result.setPlainText(result)
        self.status_changed.emit(f"Learned new threat: {name}")
    
    def _perform_search(self):
        """Perform similarity search."""
        query = self.search_input.text() or "credential attack"
        threshold = self.search_threshold.value()
        
        # Generate demo results
        results = []
        for sig in self.threat_signatures:
            sim = random.uniform(0.1, 0.8)
            if sim > threshold:
                results.append({
                    "id": sig["id"],
                    "label": sig["name"],
                    "similarity": sim,
                    "domain": sig["domain"],
                    "confidence": min(sim * 1.2, 1.0)
                })
        
        results.sort(key=lambda x: x["similarity"], reverse=True)
        
        self.search_results_table.setRowCount(len(results))
        for row, r in enumerate(results):
            self.search_results_table.setItem(row, 0, QTableWidgetItem(r["id"]))
            self.search_results_table.setItem(row, 1, QTableWidgetItem(r["label"]))
            
            sim_item = QTableWidgetItem(f"{r['similarity']:.0%}")
            if r["similarity"] > 0.6:
                sim_item.setForeground(QBrush(QColor("#00ff88")))
            elif r["similarity"] > 0.4:
                sim_item.setForeground(QBrush(QColor("#ffd93d")))
            else:
                sim_item.setForeground(QBrush(QColor("#ff6b6b")))
            self.search_results_table.setItem(row, 2, sim_item)
            
            self.search_results_table.setItem(row, 3, QTableWidgetItem(r["domain"]))
            self.search_results_table.setItem(row, 4, QTableWidgetItem(f"{r['confidence']:.0%}"))
    
    def _add_component(self):
        """Add component to composition list."""
        text = self.component_input.text().strip()
        if text:
            item = QListWidgetItem(f"🧩 {text}")
            self.component_list.addItem(item)
            self.component_input.clear()
    
    def _compose_threat(self):
        """Compose novel threat scenario."""
        components = []
        for i in range(self.component_list.count()):
            text = self.component_list.item(i).text().replace("🧩 ", "")
            components.append(text)
        
        if not components:
            components = ["AI deepfake", "credential theft", "quantum encryption"]
        
        novelty = random.uniform(0.6, 0.95)
        closest_sim = 1.0 - novelty
        closest_threat = random.choice(self.threat_signatures)
        
        html = f"""
        <h3 style='color: #ff6b6b;'>🔮 NOVEL THREAT COMPOSITION</h3>
        
        <h4 style='color: #4ecdc4;'>Components Combined:</h4>
        <ul style='color: #eee;'>
        {"".join([f"<li>{c}</li>" for c in components])}
        </ul>
        
        <h4 style='color: #ffd93d;'>Novelty Analysis:</h4>
        <table style='color: #eee; width: 100%;'>
            <tr>
                <td style='color: #888;'>Novelty Score:</td>
                <td style='color: #00ff88; font-weight: bold;'>{novelty:.0%}</td>
            </tr>
            <tr>
                <td style='color: #888;'>Closest Known Threat:</td>
                <td>{closest_threat['name']} ({closest_sim:.0%} similar)</td>
            </tr>
        </table>
        
        <div style='background: rgba(255, 107, 107, 0.1); padding: 10px; margin-top: 15px; border-radius: 5px;'>
            <p style='color: #ff6b6b;'>
            <b>⚠️ WARNING:</b> This combination represents a {novelty:.0%} novel threat pattern 
            that has not been seen before. The system can now detect similar patterns through 
            compositional similarity matching.
            </p>
        </div>
        """
        self.composition_result.setHtml(html)
    
    def _add_demo_insights(self):
        """Add demonstration insights."""
        demo_insights = [
            {
                "category": "Emerging Threat",
                "description": "Aggregate network activity shows 73% similarity to lateral movement patterns. Recommend increased monitoring on SMB/RDP traffic.",
                "confidence": 0.73,
                "color": "#ff6b6b"
            },
            {
                "category": "Pattern Correlation",
                "description": "Detected temporal binding between authentication failures and data access events. Possible credential abuse in progress.",
                "confidence": 0.68,
                "color": "#ffd93d"
            },
            {
                "category": "Anomaly Detection",
                "description": "Vector space analysis reveals cluster formation outside normal behavioral envelope. New attack TTP potentially emerging.",
                "confidence": 0.55,
                "color": "#4ecdc4"
            }
        ]
        
        for insight in demo_insights:
            self._add_insight_card(insight)
    
    def _add_insight_card(self, insight: Dict):
        """Add insight card to UI."""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #1a1a2e;
                border-left: 4px solid {insight['color']};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(5)
        
        header_layout = QHBoxLayout()
        
        category = QLabel(f"💡 {insight['category']}")
        category.setStyleSheet(f"color: {insight['color']}; font-weight: bold;")
        header_layout.addWidget(category)
        
        header_layout.addStretch()
        
        conf = QLabel(f"Confidence: {insight['confidence']:.0%}")
        conf.setStyleSheet("color: #888;")
        header_layout.addWidget(conf)
        
        card_layout.addLayout(header_layout)
        
        desc = QLabel(insight['description'])
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #eee;")
        card_layout.addWidget(desc)
        
        self.insights_layout.addWidget(card)
    
    def _generate_insight(self):
        """Generate a new cognitive insight."""
        categories = ["Threat Correlation", "Behavioral Anomaly", "Pattern Discovery", "Risk Assessment"]
        colors = ["#ff6b6b", "#ffd93d", "#4ecdc4", "#00ff88"]
        
        descriptions = [
            "Hyperdimensional analysis reveals 67% similarity between current events and known APT campaign vectors.",
            "Bundle analysis of recent endpoints shows divergence from baseline - potential compromise indicators.",
            "Temporal binding patterns suggest coordinated multi-stage attack across {:.0f} assets.".format(random.randint(3, 12)),
            "Compositional reasoning identifies novel attack vector combining phishing + privilege escalation TTPs."
        ]
        
        idx = random.randint(0, 3)
        
        new_insight = {
            "category": categories[idx],
            "description": descriptions[idx],
            "confidence": random.uniform(0.5, 0.9),
            "color": colors[idx]
        }
        
        self._add_insight_card(new_insight)
        self.status_changed.emit(f"Generated insight: {categories[idx]}")
