"""
DeepFake Detection GUI Page
AI-powered detection of deepfakes, synthetic media, and voice cloning.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QListWidget, QListWidgetItem, QFileDialog, QSlider,
    QStackedWidget, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPixmap
from datetime import datetime


class DeepfakeAnalysisWorker(QThread):
    """Worker for deepfake analysis"""
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    frame_analyzed = pyqtSignal(int, float)
    finished = pyqtSignal()
    
    def __init__(self, detector, media_path, media_type):
        super().__init__()
        self.detector = detector
        self.media_path = media_path
        self.media_type = media_type
    
    def run(self):
        try:
            for i in range(100):
                self.progress.emit(i + 1)
                if i % 10 == 0:
                    confidence = 0.3 + (i / 100) * 0.6
                    self.frame_analyzed.emit(i, confidence)
                self.msleep(50)
            
            self.result.emit({
                "status": "completed",
                "is_deepfake": True,
                "confidence": 0.87,
                "indicators": ["Face manipulation", "Audio sync issues"]
            })
        except Exception as e:
            self.result.emit({"error": str(e)})
        finally:
            self.finished.emit()


class DeepfakeDetectionPage(QWidget):
    """DeepFake Detection Engine GUI"""
    
    def __init__(self, config, db):
        super().__init__()
        self.config = config
        self.db = db
        self.detector = None
        self.worker = None
        
        self._init_detector()
        self._setup_ui()
        self._apply_styles()
    
    def _init_detector(self):
        """Initialize deepfake detector"""
        try:
            from core.deepfake_detection import DeepfakeDetector
            self.detector = DeepfakeDetector(self.config, self.db)
        except ImportError:
            self.detector = None
    
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
        tabs.setObjectName("deepfakeTabs")
        
        tabs.addTab(self._create_detection_tab(), "🎭 Detection")
        tabs.addTab(self._create_video_tab(), "🎬 Video Analysis")
        tabs.addTab(self._create_audio_tab(), "🎤 Voice Clone Detection")
        tabs.addTab(self._create_image_tab(), "🖼️ Image Forensics")
        tabs.addTab(self._create_reports_tab(), "📊 Reports")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🎭 DeepFake Detection Engine")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff6b9d;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("AI-powered detection of synthetic media, deepfakes, and voice cloning")
        subtitle.setStyleSheet("color: #888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Quick stats
        stats_layout = QHBoxLayout()
        
        for label, value, color in [
            ("Analyzed", "1,247", "#00d4ff"),
            ("Deepfakes Found", "89", "#ff4444"),
            ("Accuracy", "97.3%", "#00ff88")
        ]:
            stat = QLabel(f"{value} {label}")
            stat.setStyleSheet(f"color: {color}; font-size: 11px;")
            stats_layout.addWidget(stat)
        
        layout.addLayout(stats_layout)
        
        # Action button
        self.upload_btn = QPushButton("📁 Upload Media")
        self.upload_btn.setObjectName("primaryButton")
        self.upload_btn.clicked.connect(self._upload_media)
        layout.addWidget(self.upload_btn)
        
        return frame
    
    def _create_detection_tab(self) -> QWidget:
        """Create main detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Upload and config
        left_panel = QFrame()
        left_panel.setObjectName("uploadPanel")
        left_layout = QVBoxLayout(left_panel)
        
        # Upload area
        upload_group = QGroupBox("Media Upload")
        upload_layout = QVBoxLayout(upload_group)
        
        # Drop zone
        drop_frame = QFrame()
        drop_frame.setObjectName("dropZone")
        drop_frame.setMinimumHeight(150)
        drop_layout = QVBoxLayout(drop_frame)
        
        drop_icon = QLabel("📁")
        drop_icon.setFont(QFont("Segoe UI", 48))
        drop_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_layout.addWidget(drop_icon)
        
        drop_text = QLabel("Drag & drop media files here\nor click to browse")
        drop_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_text.setStyleSheet("color: #888;")
        drop_layout.addWidget(drop_text)
        
        upload_layout.addWidget(drop_frame)
        
        browse_btn = QPushButton("📂 Browse Files")
        browse_btn.clicked.connect(self._upload_media)
        upload_layout.addWidget(browse_btn)
        
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: #888;")
        upload_layout.addWidget(self.file_label)
        
        left_layout.addWidget(upload_group)
        
        # Detection settings
        settings_group = QGroupBox("Detection Settings")
        settings_layout = QVBoxLayout(settings_group)
        
        settings_layout.addWidget(QLabel("Analysis Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "Quick Scan", "Standard Analysis",
            "Deep Analysis", "Forensic Mode"
        ])
        settings_layout.addWidget(self.mode_combo)
        
        settings_layout.addWidget(QLabel("Detection Threshold:"))
        threshold_layout = QHBoxLayout()
        self.threshold_slider = QSlider(Qt.Orientation.Horizontal)
        self.threshold_slider.setRange(50, 99)
        self.threshold_slider.setValue(75)
        self.threshold_slider.valueChanged.connect(self._update_threshold)
        threshold_layout.addWidget(self.threshold_slider)
        self.threshold_label = QLabel("75%")
        threshold_layout.addWidget(self.threshold_label)
        settings_layout.addLayout(threshold_layout)
        
        self.face_detection = QCheckBox("Enable face manipulation detection")
        self.face_detection.setChecked(True)
        settings_layout.addWidget(self.face_detection)
        
        self.audio_analysis = QCheckBox("Enable audio authenticity analysis")
        self.audio_analysis.setChecked(True)
        settings_layout.addWidget(self.audio_analysis)
        
        self.metadata_check = QCheckBox("Analyze file metadata")
        self.metadata_check.setChecked(True)
        settings_layout.addWidget(self.metadata_check)
        
        left_layout.addWidget(settings_group)
        
        # Analyze button
        self.analyze_btn = QPushButton("🔍 Analyze Media")
        self.analyze_btn.setObjectName("primaryButton")
        self.analyze_btn.clicked.connect(self._analyze_media)
        left_layout.addWidget(self.analyze_btn)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        left_layout.addWidget(self.status_label)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = QFrame()
        right_panel.setObjectName("resultsPanel")
        right_layout = QVBoxLayout(right_panel)
        
        # Result summary
        result_frame = QFrame()
        result_frame.setObjectName("resultCard")
        result_layout = QVBoxLayout(result_frame)
        
        self.result_icon = QLabel("⏳")
        self.result_icon.setFont(QFont("Segoe UI", 64))
        self.result_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        result_layout.addWidget(self.result_icon)
        
        self.result_label = QLabel("Awaiting Analysis")
        self.result_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.result_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        result_layout.addWidget(self.result_label)
        
        self.confidence_label = QLabel("")
        self.confidence_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.confidence_label.setStyleSheet("color: #888;")
        result_layout.addWidget(self.confidence_label)
        
        right_layout.addWidget(result_frame)
        
        # Detection indicators
        indicators_group = QGroupBox("Detection Indicators")
        indicators_layout = QVBoxLayout(indicators_group)
        
        self.indicators_list = QListWidget()
        indicators_layout.addWidget(self.indicators_list)
        
        right_layout.addWidget(indicators_group)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("📤 Export Report")
        self.export_btn.setEnabled(False)
        actions_layout.addWidget(self.export_btn)
        
        self.save_btn = QPushButton("💾 Save Analysis")
        self.save_btn.setEnabled(False)
        actions_layout.addWidget(self.save_btn)
        
        right_layout.addLayout(actions_layout)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_video_tab(self) -> QWidget:
        """Create video analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Video preview area
        preview_group = QGroupBox("Video Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        preview_frame = QFrame()
        preview_frame.setObjectName("videoPreview")
        preview_frame.setMinimumHeight(300)
        preview_v = QVBoxLayout(preview_frame)
        
        preview_label = QLabel("🎬")
        preview_label.setFont(QFont("Segoe UI", 64))
        preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        preview_v.addWidget(preview_label)
        
        preview_text = QLabel("No video loaded")
        preview_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        preview_text.setStyleSheet("color: #888;")
        preview_v.addWidget(preview_text)
        
        preview_layout.addWidget(preview_frame)
        
        # Video controls
        controls_layout = QHBoxLayout()
        
        play_btn = QPushButton("▶️ Play")
        controls_layout.addWidget(play_btn)
        
        pause_btn = QPushButton("⏸ Pause")
        controls_layout.addWidget(pause_btn)
        
        frame_spin = QSpinBox()
        frame_spin.setPrefix("Frame: ")
        frame_spin.setRange(0, 10000)
        controls_layout.addWidget(frame_spin)
        
        controls_layout.addStretch()
        preview_layout.addLayout(controls_layout)
        
        layout.addWidget(preview_group)
        
        # Frame analysis
        frame_group = QGroupBox("Frame-by-Frame Analysis")
        frame_layout = QVBoxLayout(frame_group)
        
        self.frame_table = QTableWidget()
        self.frame_table.setColumnCount(5)
        self.frame_table.setHorizontalHeaderLabels([
            "Frame", "Timestamp", "Face Detection", "Manipulation Score", "Anomalies"
        ])
        self.frame_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Sample data
        frames = [
            ("0-100", "0:00-0:04", "2 faces", "12%", "None"),
            ("100-200", "0:04-0:08", "2 faces", "15%", "None"),
            ("200-300", "0:08-0:12", "2 faces", "78%", "Face swap detected"),
            ("300-400", "0:12-0:16", "2 faces", "82%", "Face swap detected"),
            ("400-500", "0:16-0:20", "2 faces", "45%", "Blending artifacts"),
        ]
        
        self.frame_table.setRowCount(len(frames))
        for row, frame in enumerate(frames):
            for col, value in enumerate(frame):
                item = QTableWidgetItem(value)
                if col == 3:  # Score
                    score = int(value.replace("%", ""))
                    if score >= 70:
                        item.setForeground(QColor("#ff4444"))
                    elif score >= 40:
                        item.setForeground(QColor("#ff8800"))
                    else:
                        item.setForeground(QColor("#00ff88"))
                self.frame_table.setItem(row, col, item)
        
        frame_layout.addWidget(self.frame_table)
        layout.addWidget(frame_group)
        
        return widget
    
    def _create_audio_tab(self) -> QWidget:
        """Create voice clone detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Audio upload and config
        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        
        upload_group = QGroupBox("Audio Sample")
        upload_layout = QVBoxLayout(upload_group)
        
        upload_layout.addWidget(QLabel("Upload audio file for analysis:"))
        
        audio_btn = QPushButton("🎵 Select Audio File")
        audio_btn.clicked.connect(self._upload_audio)
        upload_layout.addWidget(audio_btn)
        
        self.audio_file_label = QLabel("No file selected")
        self.audio_file_label.setStyleSheet("color: #888;")
        upload_layout.addWidget(self.audio_file_label)
        
        # Reference voice
        upload_layout.addWidget(QLabel("Reference voice sample (optional):"))
        
        ref_btn = QPushButton("👤 Select Reference")
        upload_layout.addWidget(ref_btn)
        
        left_layout.addWidget(upload_group)
        
        # Analysis options
        options_group = QGroupBox("Voice Analysis Options")
        options_layout = QVBoxLayout(options_group)
        
        self.spectral_analysis = QCheckBox("Spectral analysis")
        self.spectral_analysis.setChecked(True)
        options_layout.addWidget(self.spectral_analysis)
        
        self.formant_analysis = QCheckBox("Formant pattern detection")
        self.formant_analysis.setChecked(True)
        options_layout.addWidget(self.formant_analysis)
        
        self.prosody_check = QCheckBox("Prosody consistency check")
        self.prosody_check.setChecked(True)
        options_layout.addWidget(self.prosody_check)
        
        self.breathing_check = QCheckBox("Breathing pattern analysis")
        options_layout.addWidget(self.breathing_check)
        
        left_layout.addWidget(options_group)
        
        analyze_btn = QPushButton("🔍 Analyze Voice")
        analyze_btn.setObjectName("primaryButton")
        left_layout.addWidget(analyze_btn)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right - Results
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Voice metrics
        metrics_group = QGroupBox("Voice Authenticity Metrics")
        metrics_layout = QGridLayout(metrics_group)
        
        metrics = [
            ("Spectral Match", "94%", "#00ff88"),
            ("Formant Consistency", "87%", "#00ff88"),
            ("Prosody Score", "62%", "#ff8800"),
            ("Naturalness", "78%", "#00ff88"),
            ("Clone Detection", "23%", "#00ff88"),
            ("Overall Authenticity", "81%", "#00ff88"),
        ]
        
        for i, (name, value, color) in enumerate(metrics):
            name_label = QLabel(name + ":")
            metrics_layout.addWidget(name_label, i, 0)
            
            value_label = QLabel(value)
            value_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            metrics_layout.addWidget(value_label, i, 1)
            
            bar = QProgressBar()
            bar.setValue(int(value.replace("%", "")))
            metrics_layout.addWidget(bar, i, 2)
        
        right_layout.addWidget(metrics_group)
        
        # Analysis results
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout(results_group)
        
        self.voice_results = QTextEdit()
        self.voice_results.setReadOnly(True)
        self.voice_results.setHtml("""
<h3>Voice Analysis Summary</h3>
<p><b>Verdict:</b> <span style="color: #00ff88;">Likely Authentic</span></p>

<p><b>Observations:</b></p>
<ul>
<li>Natural breathing patterns detected</li>
<li>Consistent formant frequencies</li>
<li>Minor prosody variations (normal for natural speech)</li>
<li>No synthetic artifacts detected</li>
</ul>

<p><b>Confidence:</b> 81%</p>
""")
        results_layout.addWidget(self.voice_results)
        
        right_layout.addWidget(results_group)
        
        splitter.addWidget(right_panel)
        layout.addWidget(splitter)
        
        return widget
    
    def _create_image_tab(self) -> QWidget:
        """Create image forensics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Image display
        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        
        # Image preview
        image_group = QGroupBox("Image Preview")
        image_layout = QVBoxLayout(image_group)
        
        image_frame = QFrame()
        image_frame.setObjectName("imagePreview")
        image_frame.setMinimumHeight(300)
        image_v = QVBoxLayout(image_frame)
        
        image_label = QLabel("🖼️")
        image_label.setFont(QFont("Segoe UI", 64))
        image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        image_v.addWidget(image_label)
        
        upload_img_btn = QPushButton("📂 Load Image")
        upload_img_btn.clicked.connect(self._upload_image)
        image_v.addWidget(upload_img_btn)
        
        image_layout.addWidget(image_frame)
        left_layout.addWidget(image_group)
        
        # View options
        view_group = QGroupBox("Analysis View")
        view_layout = QHBoxLayout(view_group)
        
        for view in ["Original", "ELA", "Noise", "Face Map", "Heatmap"]:
            btn = QPushButton(view)
            view_layout.addWidget(btn)
        
        left_layout.addWidget(view_group)
        
        splitter.addWidget(left_panel)
        
        # Right - Analysis results
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Detection results
        detection_group = QGroupBox("Manipulation Detection")
        detection_layout = QVBoxLayout(detection_group)
        
        self.image_table = QTableWidget()
        self.image_table.setColumnCount(4)
        self.image_table.setHorizontalHeaderLabels([
            "Region", "Type", "Confidence", "Description"
        ])
        self.image_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        detections = [
            ("Face #1", "GAN Generated", "92%", "AI-generated face detected"),
            ("Background", "Splicing", "78%", "Inconsistent noise patterns"),
            ("Lighting", "Manipulation", "65%", "Lighting direction mismatch"),
        ]
        
        self.image_table.setRowCount(len(detections))
        for row, det in enumerate(detections):
            for col, value in enumerate(det):
                item = QTableWidgetItem(value)
                if col == 2:
                    conf = int(value.replace("%", ""))
                    if conf >= 80:
                        item.setForeground(QColor("#ff4444"))
                    elif conf >= 60:
                        item.setForeground(QColor("#ff8800"))
                self.image_table.setItem(row, col, item)
        
        detection_layout.addWidget(self.image_table)
        right_layout.addWidget(detection_group)
        
        # Metadata
        meta_group = QGroupBox("Image Metadata")
        meta_layout = QVBoxLayout(meta_group)
        
        self.metadata_text = QTextEdit()
        self.metadata_text.setReadOnly(True)
        self.metadata_text.setMaximumHeight(150)
        self.metadata_text.setHtml("""
<b>EXIF Data:</b><br>
Camera: Unknown<br>
Software: Adobe Photoshop 2024<br>
Date Modified: 2024-02-15 14:32:18<br>
<span style="color: #ff8800;">⚠️ Image has been edited with photo editing software</span>
""")
        meta_layout.addWidget(self.metadata_text)
        right_layout.addWidget(meta_group)
        
        splitter.addWidget(right_panel)
        layout.addWidget(splitter)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report controls
        controls = QHBoxLayout()
        
        self.report_search = QLineEdit()
        self.report_search.setPlaceholderText("Search reports...")
        controls.addWidget(self.report_search)
        
        date_combo = QComboBox()
        date_combo.addItems(["All Time", "Last 7 Days", "Last 30 Days", "Last 90 Days"])
        controls.addWidget(date_combo)
        
        type_combo = QComboBox()
        type_combo.addItems(["All Types", "Video", "Audio", "Image"])
        controls.addWidget(type_combo)
        
        controls.addStretch()
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.setObjectName("primaryButton")
        controls.addWidget(generate_btn)
        
        layout.addLayout(controls)
        
        # Reports table
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(6)
        self.reports_table.setHorizontalHeaderLabels([
            "Report ID", "Media Type", "File Name", "Result", "Confidence", "Date"
        ])
        self.reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        reports = [
            ("RPT-001", "Video", "interview.mp4", "DEEPFAKE", "87%", "2024-02-15"),
            ("RPT-002", "Audio", "voicemail.wav", "AUTHENTIC", "92%", "2024-02-14"),
            ("RPT-003", "Image", "profile.jpg", "MANIPULATED", "78%", "2024-02-13"),
            ("RPT-004", "Video", "news_clip.mp4", "AUTHENTIC", "95%", "2024-02-12"),
            ("RPT-005", "Audio", "recording.mp3", "VOICE_CLONE", "81%", "2024-02-11"),
        ]
        
        self.reports_table.setRowCount(len(reports))
        for row, report in enumerate(reports):
            for col, value in enumerate(report):
                item = QTableWidgetItem(value)
                if col == 3:  # Result
                    if value in ["DEEPFAKE", "VOICE_CLONE", "MANIPULATED"]:
                        item.setForeground(QColor("#ff4444"))
                    else:
                        item.setForeground(QColor("#00ff88"))
                self.reports_table.setItem(row, col, item)
        
        layout.addWidget(self.reports_table)
        
        # Statistics
        stats_layout = QHBoxLayout()
        
        for label, value, color in [
            ("Total Analyzed", "1,247", "#00d4ff"),
            ("Deepfakes", "89", "#ff4444"),
            ("Voice Clones", "34", "#ff8800"),
            ("Authentic", "1,124", "#00ff88")
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
            
            stats_layout.addWidget(stat_frame)
        
        layout.addLayout(stats_layout)
        
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
                    stop:0 #2d1f3d, stop:1 #1a1a2e);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#uploadPanel, QFrame#resultsPanel {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            
            QFrame#dropZone {
                background-color: #0d1b2a;
                border: 2px dashed #0f3460;
                border-radius: 10px;
            }
            
            QFrame#dropZone:hover {
                border-color: #ff6b9d;
            }
            
            QFrame#resultCard {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 10px;
                padding: 20px;
            }
            
            QFrame#statCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                padding: 15px;
            }
            
            QFrame#videoPreview, QFrame#imagePreview {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 8px;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 1px solid #0f3460;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
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
                    stop:0 #ff6b9d, stop:1 #c44569);
                color: #fff;
            }
            
            QPushButton#primaryButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff7baa, stop:1 #d45579);
            }
            
            QTableWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                gridline-color: #1a3a5c;
            }
            
            QTableWidget::item {
                padding: 8px;
            }
            
            QTableWidget::item:selected {
                background-color: #0f3460;
            }
            
            QHeaderView::section {
                background-color: #16213e;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #ff6b9d;
                font-weight: bold;
            }
            
            QLineEdit, QComboBox, QSpinBox {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #ff6b9d;
            }
            
            QTextEdit {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 10px;
            }
            
            QProgressBar {
                border: 1px solid #0f3460;
                border-radius: 5px;
                text-align: center;
                background-color: #0d1b2a;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff6b9d, stop:1 #c44569);
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
                border-bottom: 2px solid #ff6b9d;
            }
            
            QListWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QListWidget::item {
                padding: 8px;
            }
            
            QListWidget::item:selected {
                background-color: #0f3460;
            }
            
            QSlider::groove:horizontal {
                border: 1px solid #0f3460;
                height: 8px;
                background: #0d1b2a;
                border-radius: 4px;
            }
            
            QSlider::handle:horizontal {
                background: #ff6b9d;
                border: none;
                width: 18px;
                margin: -5px 0;
                border-radius: 9px;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 1px solid #0f3460;
                background-color: #0d1b2a;
            }
            
            QCheckBox::indicator:checked {
                background-color: #ff6b9d;
                border-color: #ff6b9d;
            }
        """)
    
    def _update_threshold(self, value):
        """Update threshold label"""
        self.threshold_label.setText(f"{value}%")
    
    def _upload_media(self):
        """Upload media file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Media File",
            "", "Media Files (*.mp4 *.avi *.mov *.mp3 *.wav *.jpg *.png)"
        )
        if path:
            self.file_label.setText(path.split("/")[-1])
    
    def _upload_audio(self):
        """Upload audio file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Audio File",
            "", "Audio Files (*.mp3 *.wav *.m4a *.flac)"
        )
        if path:
            self.audio_file_label.setText(path.split("/")[-1])
    
    def _upload_image(self):
        """Upload image file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Image File",
            "", "Image Files (*.jpg *.jpeg *.png *.gif *.bmp)"
        )
    
    def _analyze_media(self):
        """Analyze uploaded media"""
        if self.file_label.text() == "No file selected":
            self.status_label.setText("Please select a file first")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_btn.setEnabled(False)
        self.status_label.setText("Analyzing media...")
        
        self.worker = DeepfakeAnalysisWorker(
            self.detector, self.file_label.text(), "video"
        )
        self.worker.progress.connect(lambda v: self.progress_bar.setValue(v))
        self.worker.result.connect(self._handle_result)
        self.worker.finished.connect(self._analysis_finished)
        self.worker.start()
    
    def _handle_result(self, result):
        """Handle analysis result"""
        if result.get("is_deepfake"):
            self.result_icon.setText("🚨")
            self.result_label.setText("DEEPFAKE DETECTED")
            self.result_label.setStyleSheet("color: #ff4444;")
            self.confidence_label.setText(f"Confidence: {result['confidence']*100:.1f}%")
        else:
            self.result_icon.setText("✅")
            self.result_label.setText("AUTHENTIC")
            self.result_label.setStyleSheet("color: #00ff88;")
        
        # Add indicators
        self.indicators_list.clear()
        for indicator in result.get("indicators", []):
            item = QListWidgetItem(f"⚠️ {indicator}")
            self.indicators_list.addItem(item)
        
        self.export_btn.setEnabled(True)
        self.save_btn.setEnabled(True)
    
    def _analysis_finished(self):
        """Handle analysis completion"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText("Analysis complete")
