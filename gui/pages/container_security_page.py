"""
Container Security Page - GUI for Docker and Kubernetes security scanning
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit,
    QGroupBox, QFormLayout, QLineEdit, QComboBox, QCheckBox,
    QProgressBar, QSplitter, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor
from datetime import datetime
from typing import Optional
import json


class ScanWorker(QThread):
    """Background worker for container scans"""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    log = pyqtSignal(str, str)
    
    def __init__(self, scanner, scan_type: str, target: str = ""):
        super().__init__()
        self.scanner = scanner
        self.scan_type = scan_type
        self.target = target
    
    def run(self):
        try:
            import asyncio
            
            self.scanner.progress_callback = lambda p, s: self.progress.emit(p, s)
            self.scanner.log_callback = lambda m, l: self.log.emit(m, l)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            if self.scan_type == "docker":
                result = loop.run_until_complete(self.scanner.scan_docker_environment())
            elif self.scan_type == "image":
                result = loop.run_until_complete(self.scanner.scan_image(self.target))
            elif self.scan_type == "kubernetes":
                result = loop.run_until_complete(self.scanner.scan_kubernetes_cluster())
            else:
                result = None
            
            loop.close()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class ContainerSecurityPage(QWidget):
    """Container Security Scanner GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.scanner = None
        self.current_report = None
        self.scan_worker = None
        self._init_scanner()
        self._init_ui()
    
    def _init_scanner(self):
        """Initialize the container security scanner"""
        try:
            from core.container_security import ContainerSecurityScanner
            self.scanner = ContainerSecurityScanner()
        except ImportError as e:
            print(f"Could not import container security scanner: {e}")
    
    def _init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🐳 Container Security Scanner")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff;")
        layout.addWidget(header)
        
        subtitle = QLabel("Docker and Kubernetes security analysis, vulnerability scanning, and escape detection")
        subtitle.setStyleSheet("color: #888; font-size: 12px; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Controls
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        # Scan type selection
        scan_group = QGroupBox("🔍 Scan Type")
        scan_layout = QVBoxLayout(scan_group)
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "Docker Environment Scan",
            "Single Image Scan",
            "Kubernetes Cluster Scan"
        ])
        self.scan_type_combo.setStyleSheet("""
            QComboBox {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #1a1a2e;
                border: 1px solid #333;
                selection-background-color: #00d4ff;
            }
        """)
        self.scan_type_combo.currentIndexChanged.connect(self._on_scan_type_changed)
        scan_layout.addWidget(self.scan_type_combo)
        
        # Image name input (for single image scan)
        self.image_input_widget = QWidget()
        image_layout = QVBoxLayout(self.image_input_widget)
        image_layout.setContentsMargins(0, 10, 0, 0)
        
        image_label = QLabel("Image Name:")
        image_label.setStyleSheet("color: #888;")
        image_layout.addWidget(image_label)
        
        self.image_input = QLineEdit()
        self.image_input.setPlaceholderText("e.g., nginx:latest, ubuntu:22.04")
        self.image_input.setStyleSheet("""
            QLineEdit {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        image_layout.addWidget(self.image_input)
        
        self.image_input_widget.hide()
        scan_layout.addWidget(self.image_input_widget)
        
        # Kubeconfig input (for K8s scan)
        self.k8s_input_widget = QWidget()
        k8s_layout = QVBoxLayout(self.k8s_input_widget)
        k8s_layout.setContentsMargins(0, 10, 0, 0)
        
        k8s_label = QLabel("Kubeconfig Path (optional):")
        k8s_label.setStyleSheet("color: #888;")
        k8s_layout.addWidget(k8s_label)
        
        k8s_row = QHBoxLayout()
        self.kubeconfig_input = QLineEdit()
        self.kubeconfig_input.setPlaceholderText("~/.kube/config")
        self.kubeconfig_input.setStyleSheet("""
            QLineEdit {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        k8s_row.addWidget(self.kubeconfig_input)
        
        browse_btn = QPushButton("...")
        browse_btn.setFixedWidth(40)
        browse_btn.setStyleSheet("""
            QPushButton {
                background: #00d4ff;
                color: black;
                border: none;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        browse_btn.clicked.connect(self._browse_kubeconfig)
        k8s_row.addWidget(browse_btn)
        k8s_layout.addLayout(k8s_row)
        
        self.k8s_input_widget.hide()
        scan_layout.addWidget(self.k8s_input_widget)
        
        left_layout.addWidget(scan_group)
        
        # Scan options
        options_group = QGroupBox("⚙️ Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        self.vuln_scan_check = QCheckBox("Vulnerability Scanning")
        self.vuln_scan_check.setChecked(True)
        self.vuln_scan_check.setStyleSheet("color: white;")
        options_layout.addWidget(self.vuln_scan_check)
        
        self.secret_scan_check = QCheckBox("Secret Detection")
        self.secret_scan_check.setChecked(True)
        self.secret_scan_check.setStyleSheet("color: white;")
        options_layout.addWidget(self.secret_scan_check)
        
        self.misconfig_check = QCheckBox("Misconfiguration Check")
        self.misconfig_check.setChecked(True)
        self.misconfig_check.setStyleSheet("color: white;")
        options_layout.addWidget(self.misconfig_check)
        
        self.escape_check = QCheckBox("Escape Vector Detection")
        self.escape_check.setChecked(True)
        self.escape_check.setStyleSheet("color: white;")
        options_layout.addWidget(self.escape_check)
        
        self.compliance_check = QCheckBox("CIS Benchmark Compliance")
        self.compliance_check.setChecked(True)
        self.compliance_check.setStyleSheet("color: white;")
        options_layout.addWidget(self.compliance_check)
        
        left_layout.addWidget(options_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #00d4ff;
                color: black;
                border: none;
                border-radius: 5px;
                padding: 12px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #00b8e6;
            }
            QPushButton:disabled {
                background: #555;
                color: #888;
            }
        """)
        self.scan_btn.clicked.connect(self._start_scan)
        btn_layout.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #ff4444;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #cc3333;
            }
            QPushButton:disabled {
                background: #555;
                color: #888;
            }
        """)
        self.stop_btn.clicked.connect(self._stop_scan)
        btn_layout.addWidget(self.stop_btn)
        
        left_layout.addLayout(btn_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                height: 25px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
                border-radius: 4px;
            }
        """)
        left_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        left_layout.addWidget(self.status_label)
        
        # Quick stats
        stats_group = QGroupBox("📊 Scan Statistics")
        stats_layout = QFormLayout(stats_group)
        
        self.stat_images = QLabel("-")
        self.stat_images.setStyleSheet("color: #00d4ff; font-weight: bold;")
        stats_layout.addRow("Images Scanned:", self.stat_images)
        
        self.stat_containers = QLabel("-")
        self.stat_containers.setStyleSheet("color: #00ff88;")
        stats_layout.addRow("Containers:", self.stat_containers)
        
        self.stat_vulns = QLabel("-")
        self.stat_vulns.setStyleSheet("color: #ff4444; font-weight: bold;")
        stats_layout.addRow("Vulnerabilities:", self.stat_vulns)
        
        self.stat_escapes = QLabel("-")
        self.stat_escapes.setStyleSheet("color: #ff8800;")
        stats_layout.addRow("Escape Vectors:", self.stat_escapes)
        
        self.stat_compliance = QLabel("-")
        self.stat_compliance.setStyleSheet("color: #aa88ff;")
        stats_layout.addRow("Compliance:", self.stat_compliance)
        
        left_layout.addWidget(stats_group)
        
        left_layout.addStretch()
        
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 0, 0, 0)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                background: #16213e;
                border-radius: 5px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 8px 15px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #16213e;
                color: #00d4ff;
            }
        """)
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setStyleSheet("""
            QTextEdit {
                background: #1a1a2e;
                border: none;
                color: white;
                font-family: 'Consolas', 'Monaco', monospace;
            }
        """)
        overview_layout.addWidget(self.overview_text)
        
        self.results_tabs.addTab(overview_tab, "📋 Overview")
        
        # Containers tab
        containers_tab = QWidget()
        containers_layout = QVBoxLayout(containers_tab)
        
        self.containers_table = QTableWidget()
        self.containers_table.setColumnCount(6)
        self.containers_table.setHorizontalHeaderLabels([
            "Name", "Image", "Status", "Ports", "Privileged", "Capabilities"
        ])
        self.containers_table.horizontalHeader().setStretchLastSection(True)
        self.containers_table.setStyleSheet("""
            QTableWidget {
                background: #1a1a2e;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
                color: white;
            }
            QHeaderView::section {
                background: #16213e;
                color: #00d4ff;
                padding: 8px;
                border: none;
            }
        """)
        containers_layout.addWidget(self.containers_table)
        
        self.results_tabs.addTab(containers_tab, "🐳 Containers")
        
        # Images tab
        images_tab = QWidget()
        images_layout = QVBoxLayout(images_tab)
        
        self.images_tree = QTreeWidget()
        self.images_tree.setHeaderLabels(["Image", "Vulns", "Secrets", "Misconfigs"])
        self.images_tree.setStyleSheet("""
            QTreeWidget {
                background: #1a1a2e;
                border: none;
                color: white;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background: #00d4ff;
                color: black;
            }
            QHeaderView::section {
                background: #16213e;
                color: #00d4ff;
                padding: 8px;
                border: none;
            }
        """)
        images_layout.addWidget(self.images_tree)
        
        self.results_tabs.addTab(images_tab, "📦 Images")
        
        # Vulnerabilities tab
        vulns_tab = QWidget()
        vulns_layout = QVBoxLayout(vulns_tab)
        
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(6)
        self.vulns_table.setHorizontalHeaderLabels([
            "CVE ID", "Package", "Version", "Fixed", "Severity", "CVSS"
        ])
        self.vulns_table.horizontalHeader().setStretchLastSection(True)
        self.vulns_table.setStyleSheet("""
            QTableWidget {
                background: #1a1a2e;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
                color: white;
            }
            QHeaderView::section {
                background: #16213e;
                color: #00d4ff;
                padding: 8px;
                border: none;
            }
        """)
        vulns_layout.addWidget(self.vulns_table)
        
        self.results_tabs.addTab(vulns_tab, "🔓 Vulnerabilities")
        
        # Escape Vectors tab
        escape_tab = QWidget()
        escape_layout = QVBoxLayout(escape_tab)
        
        self.escape_table = QTableWidget()
        self.escape_table.setColumnCount(5)
        self.escape_table.setHorizontalHeaderLabels([
            "Vector", "Severity", "MITRE ID", "Requirements", "Description"
        ])
        self.escape_table.horizontalHeader().setStretchLastSection(True)
        self.escape_table.setStyleSheet("""
            QTableWidget {
                background: #1a1a2e;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
                color: white;
            }
            QHeaderView::section {
                background: #16213e;
                color: #00d4ff;
                padding: 8px;
                border: none;
            }
        """)
        escape_layout.addWidget(self.escape_table)
        
        self.results_tabs.addTab(escape_tab, "🚪 Escape Vectors")
        
        # K8s Findings tab
        k8s_tab = QWidget()
        k8s_layout_tab = QVBoxLayout(k8s_tab)
        
        self.k8s_table = QTableWidget()
        self.k8s_table.setColumnCount(6)
        self.k8s_table.setHorizontalHeaderLabels([
            "Resource", "Name", "Namespace", "Finding", "Severity", "CIS"
        ])
        self.k8s_table.horizontalHeader().setStretchLastSection(True)
        self.k8s_table.setStyleSheet("""
            QTableWidget {
                background: #1a1a2e;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
                color: white;
            }
            QHeaderView::section {
                background: #16213e;
                color: #00d4ff;
                padding: 8px;
                border: none;
            }
        """)
        k8s_layout_tab.addWidget(self.k8s_table)
        
        self.results_tabs.addTab(k8s_tab, "☸️ Kubernetes")
        
        # Log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("""
            QTextEdit {
                background: #0f0f1a;
                border: none;
                color: #00d4ff;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }
        """)
        log_layout.addWidget(self.log_output)
        
        self.results_tabs.addTab(log_tab, "📜 Log")
        
        right_layout.addWidget(self.results_tabs)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("📄 Export JSON")
        export_json_btn.setStyleSheet("""
            QPushButton {
                background: #16213e;
                color: #00d4ff;
                border: 1px solid #00d4ff;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background: #00d4ff;
                color: black;
            }
        """)
        export_json_btn.clicked.connect(lambda: self._export_report("json"))
        export_layout.addWidget(export_json_btn)
        
        export_md_btn = QPushButton("📝 Export Markdown")
        export_md_btn.setStyleSheet("""
            QPushButton {
                background: #16213e;
                color: #ff8800;
                border: 1px solid #ff8800;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background: #ff8800;
                color: black;
            }
        """)
        export_md_btn.clicked.connect(lambda: self._export_report("markdown"))
        export_layout.addWidget(export_md_btn)
        
        right_layout.addLayout(export_layout)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([350, 700])
        
        layout.addWidget(splitter)
    
    def _on_scan_type_changed(self, index: int):
        """Handle scan type change"""
        self.image_input_widget.hide()
        self.k8s_input_widget.hide()
        
        if index == 1:  # Single image
            self.image_input_widget.show()
        elif index == 2:  # Kubernetes
            self.k8s_input_widget.show()
    
    def _browse_kubeconfig(self):
        """Browse for kubeconfig file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Kubeconfig",
            "",
            "All Files (*)"
        )
        if file_path:
            self.kubeconfig_input.setText(file_path)
    
    def _start_scan(self):
        """Start container security scan"""
        if not self.scanner:
            self._log("Container security scanner not available", "error")
            return
        
        scan_index = self.scan_type_combo.currentIndex()
        
        if scan_index == 0:
            scan_type = "docker"
            target = ""
        elif scan_index == 1:
            scan_type = "image"
            target = self.image_input.text().strip()
            if not target:
                QMessageBox.warning(self, "Error", "Please enter an image name")
                return
        else:
            scan_type = "kubernetes"
            target = self.kubeconfig_input.text().strip()
        
        # Clear previous results
        self._clear_results()
        
        # Start worker
        self.scan_worker = ScanWorker(self.scanner, scan_type, target)
        self.scan_worker.progress.connect(self._update_progress)
        self.scan_worker.finished.connect(self._scan_complete)
        self.scan_worker.error.connect(self._scan_error)
        self.scan_worker.log.connect(self._log)
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Starting scan...")
        
        self.scan_worker.start()
    
    def _stop_scan(self):
        """Stop running scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
            self._log("Scan stopped by user", "warning")
        
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Scan stopped")
    
    def _update_progress(self, value: int, status: str):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        self.status_label.setText(status)
    
    def _scan_complete(self, report):
        """Handle scan completion"""
        self.current_report = report
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if report:
            self.status_label.setText(f"Scan complete in {report.scan_duration:.2f}s")
            self._display_results(report)
        else:
            self.status_label.setText("Scan complete (no results)")
    
    def _scan_error(self, error: str):
        """Handle scan error"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Scan failed")
        self._log(f"Error: {error}", "error")
        QMessageBox.critical(self, "Scan Error", error)
    
    def _clear_results(self):
        """Clear all result displays"""
        self.overview_text.clear()
        self.containers_table.setRowCount(0)
        self.images_tree.clear()
        self.vulns_table.setRowCount(0)
        self.escape_table.setRowCount(0)
        self.k8s_table.setRowCount(0)
        self.log_output.clear()
        
        self.stat_images.setText("-")
        self.stat_containers.setText("-")
        self.stat_vulns.setText("-")
        self.stat_escapes.setText("-")
        self.stat_compliance.setText("-")
    
    def _display_results(self, report):
        """Display scan results"""
        # Update quick stats
        self.stat_images.setText(str(len(report.images)))
        self.stat_containers.setText(str(len(report.containers)))
        
        vuln_text = f"{report.total_vulns} ({report.critical_vulns} critical, {report.high_vulns} high)"
        self.stat_vulns.setText(vuln_text)
        
        self.stat_escapes.setText(str(len(report.escape_vectors)))
        
        if report.compliance_score > 0:
            compliance_color = "#00ff00" if report.compliance_score >= 80 else "#ffaa00" if report.compliance_score >= 50 else "#ff4444"
            self.stat_compliance.setText(f"{report.compliance_score:.1f}%")
            self.stat_compliance.setStyleSheet(f"color: {compliance_color}; font-weight: bold;")
        
        # Overview
        overview = f"""
╔══════════════════════════════════════════════════════════════════╗
║  CONTAINER SECURITY SCAN REPORT                                   ║
╚══════════════════════════════════════════════════════════════════╝

📋 SCAN INFO:
   Scan ID:   {report.scan_id}
   Platform:  {report.platform.value}
   Target:    {report.target}
   Duration:  {report.scan_duration:.2f} seconds

📊 STATISTICS:
   Images Scanned:     {len(report.images)}
   Containers Found:   {len(report.containers)}
   Vulnerabilities:    {report.total_vulns}
     • Critical:       {report.critical_vulns}
     • High:           {report.high_vulns}
   Escape Vectors:     {len(report.escape_vectors)}
   K8s Findings:       {len(report.k8s_findings)}
   Compliance Score:   {report.compliance_score:.1f}%

"""
        
        if report.escape_vectors:
            overview += "⚠️  CRITICAL: Container escape vectors detected!\n"
            for ev in report.escape_vectors:
                overview += f"   • {ev.name}: {ev.description}\n"
        
        self.overview_text.setPlainText(overview)
        
        # Containers table
        self.containers_table.setRowCount(len(report.containers))
        for i, container in enumerate(report.containers):
            self.containers_table.setItem(i, 0, QTableWidgetItem(container.name))
            self.containers_table.setItem(i, 1, QTableWidgetItem(container.image))
            self.containers_table.setItem(i, 2, QTableWidgetItem(container.status))
            self.containers_table.setItem(i, 3, QTableWidgetItem(", ".join(container.ports[:3])))
            
            priv_item = QTableWidgetItem("Yes" if container.privileged else "No")
            if container.privileged:
                priv_item.setForeground(QColor("#ff4444"))
            self.containers_table.setItem(i, 4, priv_item)
            
            self.containers_table.setItem(i, 5, QTableWidgetItem(", ".join(container.capabilities[:3])))
        
        # Images tree
        for image in report.images:
            vuln_count = len(image.vulnerabilities)
            secret_count = len(image.secrets)
            misconfig_count = len(image.misconfigurations)
            
            parent = QTreeWidgetItem([
                image.image_name,
                str(vuln_count),
                str(secret_count),
                str(misconfig_count)
            ])
            
            # Add layers
            if image.layers:
                layers_item = QTreeWidgetItem(parent, ["Layers", str(len(image.layers)), "", ""])
                for layer in image.layers[:5]:
                    QTreeWidgetItem(layers_item, ["", layer.layer_id, f"{layer.size / 1024 / 1024:.1f}MB", layer.created_by[:50]])
            
            # Add vulnerabilities
            if image.vulnerabilities:
                vulns_item = QTreeWidgetItem(parent, ["Vulnerabilities", str(vuln_count), "", ""])
                for vuln in image.vulnerabilities[:10]:
                    QTreeWidgetItem(vulns_item, ["", vuln.vuln_id, vuln.severity.value, vuln.package])
            
            self.images_tree.addTopLevelItem(parent)
        
        # Vulnerabilities table
        all_vulns = []
        for image in report.images:
            all_vulns.extend(image.vulnerabilities)
        
        self.vulns_table.setRowCount(len(all_vulns))
        for i, vuln in enumerate(all_vulns):
            self.vulns_table.setItem(i, 0, QTableWidgetItem(vuln.vuln_id))
            self.vulns_table.setItem(i, 1, QTableWidgetItem(vuln.package))
            self.vulns_table.setItem(i, 2, QTableWidgetItem(vuln.version))
            self.vulns_table.setItem(i, 3, QTableWidgetItem(vuln.fixed_version))
            
            severity_item = QTableWidgetItem(vuln.severity.value.upper())
            severity_colors = {
                "critical": "#ff0000",
                "high": "#ff4500",
                "medium": "#ffa500",
                "low": "#ffff00",
                "negligible": "#00ff00"
            }
            severity_item.setForeground(QColor(severity_colors.get(vuln.severity.value, "#fff")))
            self.vulns_table.setItem(i, 4, severity_item)
            
            self.vulns_table.setItem(i, 5, QTableWidgetItem(f"{vuln.cvss_score:.1f}"))
        
        # Escape vectors table
        self.escape_table.setRowCount(len(report.escape_vectors))
        for i, ev in enumerate(report.escape_vectors):
            self.escape_table.setItem(i, 0, QTableWidgetItem(ev.name))
            
            severity_item = QTableWidgetItem(ev.severity.value.upper())
            severity_item.setForeground(QColor("#ff0000"))
            self.escape_table.setItem(i, 1, severity_item)
            
            self.escape_table.setItem(i, 2, QTableWidgetItem(ev.mitre_id))
            self.escape_table.setItem(i, 3, QTableWidgetItem(", ".join(ev.requirements)))
            self.escape_table.setItem(i, 4, QTableWidgetItem(ev.description))
        
        # K8s findings table
        self.k8s_table.setRowCount(len(report.k8s_findings))
        for i, finding in enumerate(report.k8s_findings):
            self.k8s_table.setItem(i, 0, QTableWidgetItem(finding.resource_type))
            self.k8s_table.setItem(i, 1, QTableWidgetItem(finding.resource_name))
            self.k8s_table.setItem(i, 2, QTableWidgetItem(finding.namespace))
            self.k8s_table.setItem(i, 3, QTableWidgetItem(finding.finding_type))
            
            severity_item = QTableWidgetItem(finding.severity.value.upper())
            severity_colors = {
                "critical": "#ff0000",
                "high": "#ff4500",
                "medium": "#ffa500",
                "low": "#ffff00"
            }
            severity_item.setForeground(QColor(severity_colors.get(finding.severity.value, "#fff")))
            self.k8s_table.setItem(i, 4, severity_item)
            
            self.k8s_table.setItem(i, 5, QTableWidgetItem(finding.cis_benchmark))
    
    def _log(self, message: str, level: str = "info"):
        """Add log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "info": "#00d4ff",
            "warning": "#ffaa00",
            "error": "#ff4444",
            "debug": "#888888"
        }
        color = colors.get(level, "#ffffff")
        self.log_output.append(f'<span style="color: #888;">[{timestamp}]</span> <span style="color: {color};">[{level.upper()}]</span> {message}')
    
    def _export_report(self, format: str):
        """Export scan report"""
        if not self.current_report:
            QMessageBox.warning(self, "Export Error", "No scan report to export")
            return
        
        extensions = {"json": "JSON Files (*.json)", "markdown": "Markdown Files (*.md)"}
        ext_map = {"json": ".json", "markdown": ".md"}
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export Report as {format.upper()}",
            f"container_security_report{ext_map[format]}",
            extensions[format]
        )
        
        if file_path:
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                content = loop.run_until_complete(self.scanner.generate_report(self.current_report, format))
                loop.close()
                
                with open(file_path, "w") as f:
                    f.write(content)
                
                self._log(f"Report exported to {file_path}", "info")
                QMessageBox.information(self, "Export Complete", f"Report saved to:\n{file_path}")
            except Exception as e:
                self._log(f"Export error: {e}", "error")
                QMessageBox.critical(self, "Export Error", str(e))
