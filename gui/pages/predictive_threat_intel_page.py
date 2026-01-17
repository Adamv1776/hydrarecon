"""
Predictive Threat Intelligence Page
GUI for AI-powered attack prediction engine
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox,
    QProgressBar, QSplitter, QFrame, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QComboBox, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio


class PredictionWorker(QThread):
    """Worker thread for running predictions"""
    progress = pyqtSignal(str)
    result = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, industry):
        super().__init__()
        self.industry = industry
        
    def run(self):
        try:
            from core.predictive_threat_intel import PredictiveThreatIntel
            
            async def predict():
                engine = PredictiveThreatIntel()
                await engine.run_prediction_cycle()
                return engine.get_predictions()
                
            result = asyncio.run(predict())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class PredictiveThreatIntelPage(QWidget):
    """Predictive Threat Intelligence Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.prediction_worker = None
        self.engine = None
        
        self._setup_ui()
        self._connect_signals()
        self._load_demo_data()
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #21262d;
                color: #8b949e;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #ff6b6b;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_predictions_tab(), "🔮 Predictions")
        self.tabs.addTab(self._create_timeline_tab(), "📅 Attack Timeline")
        self.tabs.addTab(self._create_indicators_tab(), "🎯 Threat Indicators")
        self.tabs.addTab(self._create_intel_sources_tab(), "📡 Intel Sources")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2d1f1f, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔮 Predictive Threat Intelligence")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("AI-Powered Attack Prediction Engine")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.predictions_count = self._create_stat_card("Active Predictions", "12", "#ff6b6b")
        self.threat_score = self._create_stat_card("Threat Score", "72/100", "#ffa500")
        self.confidence_avg = self._create_stat_card("Avg Confidence", "78%", "#00ff88")
        
        stats_layout.addWidget(self.predictions_count)
        stats_layout.addWidget(self.threat_score)
        stats_layout.addWidget(self.confidence_avg)
        
        layout.addLayout(stats_layout)
        
        # Run prediction button
        self.run_btn = QPushButton("🚀 Run Prediction")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff6b6b, stop:1 #ff8e53);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff8e53, stop:1 #ff6b6b);
            }
        """)
        layout.addWidget(self.run_btn)
        
        return header
    
    def _create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a statistics card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(4)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        return card
        
    def _create_predictions_tab(self) -> QWidget:
        """Create predictions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Predictions table
        self.predictions_table = QTableWidget()
        self.predictions_table.setColumnCount(6)
        self.predictions_table.setHorizontalHeaderLabels([
            "Threat Type", "Target", "Probability", "Timeframe", "Confidence", "Status"
        ])
        self.predictions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.predictions_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                border-bottom: 1px solid #30363d;
            }
        """)
        layout.addWidget(self.predictions_table)
        
        return widget
        
    def _create_timeline_tab(self) -> QWidget:
        """Create attack timeline tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Timeline tree
        self.timeline_tree = QTreeWidget()
        self.timeline_tree.setHeaderLabels(["Vulnerability", "Days to Exploit", "Risk Level", "Affected"])
        self.timeline_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.timeline_tree)
        
        return widget
        
    def _create_indicators_tab(self) -> QWidget:
        """Create threat indicators tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Indicators table
        self.indicators_table = QTableWidget()
        self.indicators_table.setColumnCount(5)
        self.indicators_table.setHorizontalHeaderLabels([
            "Indicator", "Type", "Severity", "Source", "Confidence"
        ])
        self.indicators_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.indicators_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.indicators_table)
        
        return widget
        
    def _create_intel_sources_tab(self) -> QWidget:
        """Create intel sources tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Sources list
        sources_group = QGroupBox("Intelligence Sources")
        sources_group.setStyleSheet("""
            QGroupBox {
                color: #e6e6e6;
                font-weight: bold;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        sources_layout = QGridLayout(sources_group)
        
        sources = [
            ("🌐 OSINT Feeds", "Dark web forums, paste sites, social media"),
            ("🔒 Threat Intel Platforms", "MISP, OpenCTI, TheHive"),
            ("📰 Security News", "CVE databases, security blogs"),
            ("🕵️ Underground Markets", "Exploit markets, credential shops"),
            ("📊 Vulnerability DBs", "NVD, Exploit-DB, VulnDB"),
            ("🛡️ ISAC Reports", "Industry-specific threat sharing"),
            ("🔬 Malware Analysis", "Sandbox reports, reverse engineering"),
            ("📡 Network Sensors", "Honeypots, sinkholes, sensors"),
        ]
        
        for i, (name, desc) in enumerate(sources):
            row, col = divmod(i, 2)
            source_card = self._create_source_card(name, desc)
            sources_layout.addWidget(source_card, row, col)
            
        layout.addWidget(sources_group)
        
        return widget
        
    def _create_source_card(self, name: str, desc: str) -> QFrame:
        """Create source info card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        name_label = QLabel(name)
        name_label.setStyleSheet("color: #ff6b6b; font-weight: bold; font-size: 14px;")
        layout.addWidget(name_label)
        
        desc_label = QLabel(desc)
        desc_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        return card
        
    def _connect_signals(self):
        """Connect signals and slots"""
        self.run_btn.clicked.connect(self._run_prediction)
        
    def _run_prediction(self):
        """Run prediction analysis"""
        self.run_btn.setEnabled(False)
        self.run_btn.setText("🔄 Analyzing...")
        
        # Simulate prediction
        QTimer.singleShot(2000, self._prediction_complete)
        
    def _prediction_complete(self):
        """Handle prediction completion"""
        self.run_btn.setEnabled(True)
        self.run_btn.setText("🚀 Run Prediction")
        self._load_demo_data()
        
    def _load_demo_data(self):
        """Load demonstration data"""
        # Predictions
        predictions = [
            ("Ransomware Attack", "file-server-01", "85%", "7-14 days", "High", "⚠️ Active"),
            ("Phishing Campaign", "email-gateway", "72%", "3-7 days", "Medium", "🔴 Imminent"),
            ("Supply Chain Attack", "ci-cd-pipeline", "45%", "30-60 days", "Medium", "🟡 Monitoring"),
            ("Zero-Day Exploit", "web-app-cluster", "38%", "14-30 days", "Low", "🟢 Watching"),
            ("Credential Stuffing", "auth-service", "68%", "1-3 days", "High", "🔴 Imminent"),
            ("DDoS Attack", "api-gateway", "55%", "7-14 days", "Medium", "🟡 Monitoring"),
        ]
        
        self.predictions_table.setRowCount(len(predictions))
        for row, pred in enumerate(predictions):
            for col, value in enumerate(pred):
                item = QTableWidgetItem(value)
                if col == 2:  # Probability
                    prob = int(value.replace('%', ''))
                    if prob >= 70:
                        item.setForeground(QColor("#ff6b6b"))
                    elif prob >= 50:
                        item.setForeground(QColor("#ffa500"))
                    else:
                        item.setForeground(QColor("#00ff88"))
                self.predictions_table.setItem(row, col, item)
                
        # Timeline
        timeline_data = [
            ("CVE-2024-1234", "15 days", "Critical", "12 systems"),
            ("CVE-2024-5678", "30 days", "High", "8 systems"),
            ("CVE-2024-9012", "45 days", "Medium", "3 systems"),
        ]
        
        self.timeline_tree.clear()
        for vuln, days, risk, affected in timeline_data:
            item = QTreeWidgetItem([vuln, days, risk, affected])
            self.timeline_tree.addTopLevelItem(item)
            
        # Indicators
        indicators = [
            ("APT29 TTP Pattern", "Behavior", "High", "MITRE ATT&CK", "82%"),
            ("Cobalt Strike Beacon", "Malware", "Critical", "Sandbox", "95%"),
            ("192.168.1.100", "IP Address", "Medium", "Threat Feed", "75%"),
            ("malware.evil.com", "Domain", "High", "OSINT", "88%"),
        ]
        
        self.indicators_table.setRowCount(len(indicators))
        for row, ind in enumerate(indicators):
            for col, value in enumerate(ind):
                item = QTableWidgetItem(value)
                self.indicators_table.setItem(row, col, item)
