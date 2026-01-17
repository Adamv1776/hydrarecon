"""
Adversarial Attack Simulator GUI Page
GAN-inspired attack pattern generation for defense testing.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QListWidget, QSlider, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class AttackGenerationWorker(QThread):
    """Worker for attack pattern generation"""
    progress = pyqtSignal(int)
    sample_generated = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    
    def __init__(self, category, count, techniques):
        super().__init__()
        self.category = category
        self.count = count
        self.techniques = techniques
    
    def run(self):
        try:
            samples = []
            for i in range(self.count):
                progress = int(((i + 1) / self.count) * 100)
                self.progress.emit(progress)
                
                sample = {
                    "id": f"ADV-{i+1:04d}",
                    "category": self.category,
                    "technique": self.techniques[i % len(self.techniques)] if self.techniques else "polymorphic",
                    "complexity": ["Low", "Medium", "High"][i % 3],
                    "evasion_score": 0.5 + (i % 5) * 0.1
                }
                samples.append(sample)
                self.sample_generated.emit(sample)
                
                self.msleep(100)
            
            self.finished.emit({
                "status": "completed",
                "samples": len(samples),
                "avg_evasion": sum(s["evasion_score"] for s in samples) / len(samples)
            })
        except Exception as e:
            self.finished.emit({"error": str(e)})


class AdversarialSimulatorPage(QWidget):
    """Adversarial Attack Simulator dashboard page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.simulator = None
        self.samples = []
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
        tabs.addTab(self.create_generator_tab(), "🧬 Pattern Generator")
        tabs.addTab(self.create_evasion_tab(), "🛡️ Evasion Testing")
        tabs.addTab(self.create_samples_tab(), "📦 Generated Samples")
        tabs.addTab(self.create_detection_tab(), "🔍 Detection Analysis")
        tabs.addTab(self.create_campaigns_tab(), "📋 Test Campaigns")
        
        layout.addWidget(tabs)
    
    def create_header(self) -> QFrame:
        """Create header section."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f2d1f, stop:0.5 #203d20, stop:1 #256025);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🧬 Adversarial Attack Simulator")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #88ff88;")
        
        subtitle = QLabel("GAN-Inspired Attack Pattern Generation for Defense Testing")
        subtitle.setStyleSheet("color: #888;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.samples_count = self.create_stat_card("Samples", "0", "#88ff88")
        self.patterns_count = self.create_stat_card("Patterns", "10", "#ffd93d")
        self.evasion_rate = self.create_stat_card("Avg Evasion", "0%", "#ff6b6b")
        self.campaigns_count = self.create_stat_card("Campaigns", "0", "#6c5ce7")
        
        stats_layout.addWidget(self.samples_count)
        stats_layout.addWidget(self.patterns_count)
        stats_layout.addWidget(self.evasion_rate)
        stats_layout.addWidget(self.campaigns_count)
        
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
    
    def create_generator_tab(self) -> QWidget:
        """Create pattern generator tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Generation form
        form_group = QGroupBox("Attack Pattern Generation")
        form_layout = QGridLayout(form_group)
        
        # Attack category
        form_layout.addWidget(QLabel("Attack Category:"), 0, 0)
        self.category_combo = QComboBox()
        self.category_combo.addItems([
            "Malware", "Phishing", "Ransomware", "APT",
            "Botnet", "Exploit Kit", "Web Attack", "Network Attack"
        ])
        form_layout.addWidget(self.category_combo, 0, 1)
        
        # Base pattern
        form_layout.addWidget(QLabel("Base Pattern:"), 0, 2)
        self.pattern_combo = QComboBox()
        self.pattern_combo.addItems([
            "Memory-resident", "File-based", "Script-based",
            "LOLBins", "Fileless", "Supply Chain"
        ])
        form_layout.addWidget(self.pattern_combo, 0, 3)
        
        # Number of samples
        form_layout.addWidget(QLabel("Samples to Generate:"), 1, 0)
        self.samples_spin = QSpinBox()
        self.samples_spin.setRange(1, 1000)
        self.samples_spin.setValue(50)
        form_layout.addWidget(self.samples_spin, 1, 1)
        
        # Complexity
        form_layout.addWidget(QLabel("Complexity:"), 1, 2)
        self.complexity_combo = QComboBox()
        self.complexity_combo.addItems(["Low", "Medium", "High", "Advanced"])
        self.complexity_combo.setCurrentIndex(1)
        form_layout.addWidget(self.complexity_combo, 1, 3)
        
        # Evasion techniques
        form_layout.addWidget(QLabel("Evasion Techniques:"), 2, 0)
        self.evasion_list = QListWidget()
        self.evasion_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.evasion_list.addItems([
            "Polymorphic Code",
            "Metamorphic Engine",
            "Code Obfuscation",
            "Anti-VM/Sandbox",
            "Living Off the Land",
            "Fileless Execution",
            "Process Injection",
            "Timestomping"
        ])
        self.evasion_list.setMaximumHeight(100)
        form_layout.addWidget(self.evasion_list, 2, 1, 1, 3)
        
        layout.addWidget(form_group)
        
        # Mutation options
        mutation_group = QGroupBox("Mutation Parameters")
        mutation_layout = QGridLayout(mutation_group)
        
        # Mutation rate
        mutation_layout.addWidget(QLabel("Mutation Rate:"), 0, 0)
        self.mutation_slider = QSlider(Qt.Orientation.Horizontal)
        self.mutation_slider.setRange(0, 100)
        self.mutation_slider.setValue(50)
        self.mutation_slider.valueChanged.connect(self.update_mutation_label)
        mutation_layout.addWidget(self.mutation_slider, 0, 1)
        self.mutation_label = QLabel("50%")
        mutation_layout.addWidget(self.mutation_label, 0, 2)
        
        # Diversity
        mutation_layout.addWidget(QLabel("Diversity:"), 1, 0)
        self.diversity_slider = QSlider(Qt.Orientation.Horizontal)
        self.diversity_slider.setRange(0, 100)
        self.diversity_slider.setValue(70)
        self.diversity_slider.valueChanged.connect(self.update_diversity_label)
        mutation_layout.addWidget(self.diversity_slider, 1, 1)
        self.diversity_label = QLabel("70%")
        mutation_layout.addWidget(self.diversity_label, 1, 2)
        
        layout.addWidget(mutation_group)
        
        # Generate button and progress
        buttons_layout = QHBoxLayout()
        
        generate_btn = QPushButton("🧬 Generate Attack Patterns")
        generate_btn.clicked.connect(self.generate_patterns)
        generate_btn.setStyleSheet("background: #88ff88; color: black; padding: 12px;")
        
        buttons_layout.addWidget(generate_btn)
        buttons_layout.addStretch()
        
        layout.addLayout(buttons_layout)
        
        self.generation_progress = QProgressBar()
        self.generation_progress.setVisible(False)
        layout.addWidget(self.generation_progress)
        
        # Generation log
        log_group = QGroupBox("Generation Log")
        log_layout = QVBoxLayout(log_group)
        
        self.generation_log = QTextEdit()
        self.generation_log.setReadOnly(True)
        self.generation_log.setMaximumHeight(150)
        self.generation_log.setStyleSheet("""
            QTextEdit {
                background: #0a0a1a;
                font-family: 'Consolas', monospace;
                color: #88ff88;
            }
        """)
        
        log_layout.addWidget(self.generation_log)
        layout.addWidget(log_group)
        
        return widget
    
    def create_evasion_tab(self) -> QWidget:
        """Create evasion testing tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Evasion techniques overview
        techniques_group = QGroupBox("Evasion Technique Library")
        techniques_layout = QVBoxLayout(techniques_group)
        
        self.evasion_table = QTableWidget()
        self.evasion_table.setColumnCount(5)
        self.evasion_table.setHorizontalHeaderLabels([
            "Technique", "Category", "Effectiveness", "Detection Difficulty", "Status"
        ])
        self.evasion_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Add sample techniques
        techniques = [
            ("Polymorphic Engine", "Code Mutation", "85%", "High", "Active"),
            ("Metamorphic Transformation", "Code Mutation", "92%", "Very High", "Active"),
            ("API Hashing", "Obfuscation", "75%", "Medium", "Active"),
            ("String Encryption", "Obfuscation", "70%", "Medium", "Active"),
            ("Anti-VM Detection", "Sandbox Evasion", "80%", "High", "Active"),
            ("Sleep Timers", "Sandbox Evasion", "65%", "Low", "Active"),
            ("Process Hollowing", "Injection", "88%", "High", "Active"),
            ("DLL Sideloading", "LOTL", "78%", "Medium", "Active"),
            ("Timestomping", "Anti-Forensics", "60%", "Medium", "Active")
        ]
        
        for i, (name, cat, eff, diff, status) in enumerate(techniques):
            self.evasion_table.insertRow(i)
            self.evasion_table.setItem(i, 0, QTableWidgetItem(name))
            self.evasion_table.setItem(i, 1, QTableWidgetItem(cat))
            
            eff_item = QTableWidgetItem(eff)
            eff_val = int(eff.replace("%", ""))
            eff_item.setForeground(QColor("#00ff88" if eff_val >= 80 else "#ffd93d" if eff_val >= 60 else "#ff6b6b"))
            self.evasion_table.setItem(i, 2, eff_item)
            
            diff_item = QTableWidgetItem(diff)
            diff_item.setForeground(QColor({
                "Very High": "#ff6b6b", "High": "#ff8844", "Medium": "#ffd93d", "Low": "#88ff88"
            }.get(diff, "#fff")))
            self.evasion_table.setItem(i, 3, diff_item)
            
            self.evasion_table.setItem(i, 4, QTableWidgetItem(status))
        
        techniques_layout.addWidget(self.evasion_table)
        layout.addWidget(techniques_group)
        
        # Test controls
        test_group = QGroupBox("Evasion Test")
        test_layout = QGridLayout(test_group)
        
        test_layout.addWidget(QLabel("Sample:"), 0, 0)
        self.test_sample_combo = QComboBox()
        self.test_sample_combo.addItem("Select sample...")
        test_layout.addWidget(self.test_sample_combo, 0, 1)
        
        test_layout.addWidget(QLabel("Target Detection:"), 0, 2)
        self.detection_combo = QComboBox()
        self.detection_combo.addItems([
            "All Detections",
            "Signature-based AV",
            "Heuristic Analysis",
            "Behavioral Detection",
            "Machine Learning",
            "Sandbox Analysis"
        ])
        test_layout.addWidget(self.detection_combo, 0, 3)
        
        test_btn = QPushButton("🧪 Run Evasion Test")
        test_btn.clicked.connect(self.run_evasion_test)
        test_btn.setStyleSheet("background: #6c5ce7; color: white;")
        test_layout.addWidget(test_btn, 1, 0, 1, 4)
        
        layout.addWidget(test_group)
        
        # Results
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout(results_group)
        
        self.evasion_results = QTextEdit()
        self.evasion_results.setReadOnly(True)
        self.evasion_results.setStyleSheet("background: #1a1a2e;")
        
        results_layout.addWidget(self.evasion_results)
        layout.addWidget(results_group)
        
        return widget
    
    def create_samples_tab(self) -> QWidget:
        """Create samples tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Category:"))
        self.filter_category = QComboBox()
        self.filter_category.addItems(["All", "Malware", "Phishing", "Ransomware", "APT"])
        filter_layout.addWidget(self.filter_category)
        
        filter_layout.addWidget(QLabel("Complexity:"))
        self.filter_complexity = QComboBox()
        self.filter_complexity.addItems(["All", "Low", "Medium", "High", "Advanced"])
        filter_layout.addWidget(self.filter_complexity)
        
        filter_layout.addStretch()
        
        export_btn = QPushButton("📤 Export Samples")
        filter_layout.addWidget(export_btn)
        
        layout.addLayout(filter_layout)
        
        # Samples table
        self.samples_table = QTableWidget()
        self.samples_table.setColumnCount(7)
        self.samples_table.setHorizontalHeaderLabels([
            "ID", "Category", "Technique", "Complexity", "Evasion Score", "Created", "Actions"
        ])
        self.samples_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.samples_table)
        
        return widget
    
    def create_detection_tab(self) -> QWidget:
        """Create detection analysis tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Detection stats
        stats_grid = QGridLayout()
        
        metrics = [
            ("Samples Tested", "0", "#88ff88"),
            ("Detected", "0", "#ff6b6b"),
            ("Evaded", "0", "#00d4ff"),
            ("Detection Rate", "0%", "#ffd93d")
        ]
        
        for i, (label, value, color) in enumerate(metrics):
            card = self.create_detection_card(label, value, color)
            stats_grid.addWidget(card, 0, i)
        
        layout.addLayout(stats_grid)
        
        # Detection matrix
        matrix_group = QGroupBox("Detection Matrix")
        matrix_layout = QVBoxLayout(matrix_group)
        
        self.detection_table = QTableWidget()
        self.detection_table.setColumnCount(6)
        self.detection_table.setHorizontalHeaderLabels([
            "Sample", "Signature AV", "Heuristic", "Behavioral", "ML", "Sandbox"
        ])
        self.detection_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        matrix_layout.addWidget(self.detection_table)
        layout.addWidget(matrix_group)
        
        # Recommendations
        rec_group = QGroupBox("Defense Recommendations")
        rec_layout = QVBoxLayout(rec_group)
        
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.recommendations_text.setText("""
Based on adversarial testing results:

1. 🔴 CRITICAL: Signature-based detection alone is insufficient
   - 85% of generated samples evade traditional AV signatures
   - Recommend: Implement behavioral detection

2. 🟠 HIGH: Machine Learning models need retraining
   - 60% evasion rate against current ML models
   - Recommend: Retrain with adversarial samples

3. 🟡 MEDIUM: Sandbox analysis timing attacks effective
   - Sleep-based evasion successful 40% of the time
   - Recommend: Implement accelerated sandbox execution

4. 🟢 INFO: Multi-layer detection most effective
   - Combination of 3+ detection methods reduces evasion to <15%
   - Recommend: Deploy defense-in-depth strategy
""")
        
        rec_layout.addWidget(self.recommendations_text)
        layout.addWidget(rec_group)
        
        return widget
    
    def create_detection_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a detection stat card."""
        card = QFrame()
        card.setFixedHeight(80)
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0,0,0,0.3);
                border: 1px solid {color};
                border-radius: 8px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setObjectName("value")
        
        text_label = QLabel(label)
        text_label.setStyleSheet("color: #888;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(text_label)
        
        return card
    
    def create_campaigns_tab(self) -> QWidget:
        """Create test campaigns tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # New campaign form
        form_group = QGroupBox("Create Test Campaign")
        form_layout = QGridLayout(form_group)
        
        form_layout.addWidget(QLabel("Campaign Name:"), 0, 0)
        self.campaign_name_input = QLineEdit()
        self.campaign_name_input.setPlaceholderText("e.g., Q4 2024 Defense Test")
        form_layout.addWidget(self.campaign_name_input, 0, 1)
        
        form_layout.addWidget(QLabel("Objective:"), 0, 2)
        self.campaign_objective = QComboBox()
        self.campaign_objective.addItems([
            "Test AV Evasion",
            "Validate EDR Detection",
            "Stress Test SIEM",
            "Full Defense Evaluation"
        ])
        form_layout.addWidget(self.campaign_objective, 0, 3)
        
        form_layout.addWidget(QLabel("Samples:"), 1, 0)
        self.campaign_samples_spin = QSpinBox()
        self.campaign_samples_spin.setRange(10, 500)
        self.campaign_samples_spin.setValue(100)
        form_layout.addWidget(self.campaign_samples_spin, 1, 1)
        
        form_layout.addWidget(QLabel("Duration:"), 1, 2)
        self.campaign_duration = QComboBox()
        self.campaign_duration.addItems(["1 hour", "4 hours", "24 hours", "7 days"])
        form_layout.addWidget(self.campaign_duration, 1, 3)
        
        create_btn = QPushButton("📋 Create Campaign")
        create_btn.clicked.connect(self.create_campaign)
        form_layout.addWidget(create_btn, 2, 0, 1, 4)
        
        layout.addWidget(form_group)
        
        # Campaigns table
        self.campaigns_table = QTableWidget()
        self.campaigns_table.setColumnCount(6)
        self.campaigns_table.setHorizontalHeaderLabels([
            "Name", "Objective", "Samples", "Progress", "Evasion Rate", "Status"
        ])
        self.campaigns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.campaigns_table)
        
        return widget
    
    def update_mutation_label(self, value: int):
        """Update mutation rate label."""
        self.mutation_label.setText(f"{value}%")
    
    def update_diversity_label(self, value: int):
        """Update diversity label."""
        self.diversity_label.setText(f"{value}%")
    
    def generate_patterns(self):
        """Generate attack patterns."""
        category = self.category_combo.currentText()
        count = self.samples_spin.value()
        techniques = [item.text() for item in self.evasion_list.selectedItems()]
        
        self.generation_progress.setVisible(True)
        self.generation_progress.setValue(0)
        self.generation_log.clear()
        
        self.log_generation(f"Starting generation of {count} {category} samples...")
        self.log_generation(f"Evasion techniques: {', '.join(techniques) if techniques else 'default'}")
        self.log_generation("")
        
        self.generation_worker = AttackGenerationWorker(category, count, techniques)
        self.generation_worker.progress.connect(self.generation_progress.setValue)
        self.generation_worker.sample_generated.connect(self.on_sample_generated)
        self.generation_worker.finished.connect(self.on_generation_complete)
        self.generation_worker.start()
    
    def on_sample_generated(self, sample: dict):
        """Handle generated sample."""
        self.log_generation(f"Generated: {sample['id']} [{sample['technique']}] (evasion: {sample['evasion_score']:.0%})")
        
        # Add to samples table
        row = self.samples_table.rowCount()
        self.samples_table.insertRow(row)
        
        items = [
            sample["id"],
            sample["category"],
            sample["technique"],
            sample["complexity"],
            f"{sample['evasion_score']:.0%}",
            datetime.now().strftime("%H:%M:%S")
        ]
        
        for col, item in enumerate(items):
            self.samples_table.setItem(row, col, QTableWidgetItem(str(item)))
        
        test_btn = QPushButton("Test")
        test_btn.setFixedWidth(50)
        self.samples_table.setCellWidget(row, 6, test_btn)
        
        # Update stats
        count = self.samples_table.rowCount()
        self.samples_count.findChild(QLabel, "value").setText(str(count))
    
    def on_generation_complete(self, result: dict):
        """Handle generation completion."""
        self.generation_progress.setVisible(False)
        
        if "error" in result:
            self.log_generation(f"ERROR: {result['error']}")
        else:
            self.log_generation("")
            self.log_generation("=" * 40)
            self.log_generation("GENERATION COMPLETE")
            self.log_generation(f"Samples: {result['samples']}")
            self.log_generation(f"Average Evasion: {result['avg_evasion']:.0%}")
            
            self.evasion_rate.findChild(QLabel, "value").setText(f"{result['avg_evasion']:.0%}")
    
    def log_generation(self, message: str):
        """Log generation message."""
        self.generation_log.append(message)
    
    def run_evasion_test(self):
        """Run evasion test."""
        self.evasion_results.setText(f"""
═══════════════════════════════════════════════════════════════════════════════
                         EVASION TEST RESULTS
═══════════════════════════════════════════════════════════════════════════════

Sample: {self.test_sample_combo.currentText() or "ADV-0001"}
Target: {self.detection_combo.currentText()}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

DETECTION RESULTS
─────────────────────────────────────────────────────────────────────────────

Signature-based AV:
  ✅ EVADED - No signature match found
  
Heuristic Analysis:
  ⚠️ PARTIAL - Suspicious API sequence detected (confidence: 45%)
  
Behavioral Detection:
  ✅ EVADED - No malicious behavior patterns matched
  
Machine Learning:
  ❌ DETECTED - Anomaly score: 0.78 (threshold: 0.65)
  
Sandbox Analysis:
  ✅ EVADED - Anti-sandbox techniques effective

SUMMARY
─────────────────────────────────────────────────────────────────────────────

Overall Evasion Rate: 80% (4/5 engines evaded)
Detection Confidence: LOW (only ML triggered)

RECOMMENDATIONS
─────────────────────────────────────────────────────────────────────────────

• Retrain ML model with similar adversarial samples
• Consider lowering ML anomaly threshold to 0.60
• Implement multi-engine correlation for better detection

═══════════════════════════════════════════════════════════════════════════════
""")
    
    def create_campaign(self):
        """Create a test campaign."""
        name = self.campaign_name_input.text()
        if not name:
            return
        
        row = self.campaigns_table.rowCount()
        self.campaigns_table.insertRow(row)
        
        items = [
            name,
            self.campaign_objective.currentText(),
            str(self.campaign_samples_spin.value()),
            "0%",
            "-",
            "Pending"
        ]
        
        for col, item in enumerate(items):
            self.campaigns_table.setItem(row, col, QTableWidgetItem(item))
        
        # Update stats
        count = self.campaigns_table.rowCount()
        self.campaigns_count.findChild(QLabel, "value").setText(str(count))
        
        # Clear input
        self.campaign_name_input.clear()
