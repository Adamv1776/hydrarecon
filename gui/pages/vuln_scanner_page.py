"""
Vulnerability Scanner Page
Advanced CVE detection and vulnerability assessment interface
"""

import asyncio
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont, QBrush

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.vuln_scanner import (
    VulnerabilityScanner, Vulnerability, ScanTarget, CVE,
    Severity, VulnType
)


class ScanWorker(QThread):
    """Background worker for vulnerability scanning"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str, int)
    error = pyqtSignal(str)
    
    def __init__(self, scanner, targets):
        super().__init__()
        self.scanner = scanner
        self.targets = targets
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            all_vulns = []
            for i, target in enumerate(self.targets):
                self.progress.emit(f"Scanning {target.host}:{target.port}", int((i / len(self.targets)) * 100))
                vulns = loop.run_until_complete(self.scanner.scan_target(target))
                all_vulns.extend(vulns)
            
            self.result_ready.emit(all_vulns)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class CVEWorker(QThread):
    """Background worker for CVE lookups"""
    result_ready = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, scanner, operation, *args):
        super().__init__()
        self.scanner = scanner
        self.operation = operation
        self.args = args
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.operation(*self.args))
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class VulnScannerPage(QWidget):
    """Vulnerability Scanner GUI Page"""
    
    SEVERITY_COLORS = {
        Severity.CRITICAL: QColor("#ff0000"),
        Severity.HIGH: QColor("#ff6b00"),
        Severity.MEDIUM: QColor("#ffaa00"),
        Severity.LOW: QColor("#00d4ff"),
        Severity.INFO: QColor("#888888"),
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = VulnerabilityScanner()
        self.vulnerabilities: list = []
        self.workers = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🔍 Vulnerability Scanner")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff4444;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #333;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #ff4444;
                color: #fff;
            }
        """)
        
        tabs.addTab(self.create_scanner_tab(), "🎯 Scanner")
        tabs.addTab(self.create_results_tab(), "📋 Results")
        tabs.addTab(self.create_cve_tab(), "🔎 CVE Lookup")
        tabs.addTab(self.create_reports_tab(), "📊 Reports")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QLabel("Ready to scan")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #00ff88;
        """)
        layout.addWidget(self.status_bar)
    
    def create_scanner_tab(self):
        """Create scanner tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ff4444;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #ff4444;
            }
        """)
        target_layout = QVBoxLayout(target_group)
        
        # Host input
        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("Target Host:"))
        self.target_host = QLineEdit()
        self.target_host.setPlaceholderText("192.168.1.1 or target.com")
        host_layout.addWidget(self.target_host)
        target_layout.addLayout(host_layout)
        
        # Port input
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Ports:"))
        self.target_ports = QLineEdit()
        self.target_ports.setPlaceholderText("22,80,443,3306 or 1-1000")
        self.target_ports.setText("21,22,23,25,80,443,445,3306,5432,6379,8080,27017")
        port_layout.addWidget(self.target_ports)
        target_layout.addLayout(port_layout)
        
        # Service info (optional)
        service_layout = QHBoxLayout()
        service_layout.addWidget(QLabel("Service:"))
        self.service_info = QLineEdit()
        self.service_info.setPlaceholderText("Optional: apache, nginx, mysql...")
        service_layout.addWidget(self.service_info)
        
        service_layout.addWidget(QLabel("Version:"))
        self.version_info = QLineEdit()
        self.version_info.setPlaceholderText("Optional: 2.4.49")
        service_layout.addWidget(self.version_info)
        target_layout.addLayout(service_layout)
        
        # Import from Nmap
        import_layout = QHBoxLayout()
        self.import_nmap_btn = QPushButton("📥 Import from Nmap")
        self.import_nmap_btn.clicked.connect(self.import_nmap_results)
        import_layout.addWidget(self.import_nmap_btn)
        
        self.add_target_btn = QPushButton("➕ Add Target")
        self.add_target_btn.clicked.connect(self.add_target)
        import_layout.addWidget(self.add_target_btn)
        
        self.clear_targets_btn = QPushButton("🗑️ Clear")
        self.clear_targets_btn.clicked.connect(self.clear_targets)
        import_layout.addWidget(self.clear_targets_btn)
        import_layout.addStretch()
        target_layout.addLayout(import_layout)
        
        layout.addWidget(target_group)
        
        # Targets list
        targets_group = QGroupBox("Scan Targets")
        targets_layout = QVBoxLayout(targets_group)
        
        self.targets_table = QTableWidget()
        self.targets_table.setColumnCount(5)
        self.targets_table.setHorizontalHeaderLabels([
            "Host", "Port", "Service", "Version", "Status"
        ])
        self.targets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        targets_layout.addWidget(self.targets_table)
        
        layout.addWidget(targets_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QHBoxLayout(options_group)
        
        self.check_versions = QCheckBox("Version Vulnerabilities")
        self.check_versions.setChecked(True)
        options_layout.addWidget(self.check_versions)
        
        self.check_services = QCheckBox("Service Vulnerabilities")
        self.check_services.setChecked(True)
        options_layout.addWidget(self.check_services)
        
        self.check_creds = QCheckBox("Default Credentials")
        self.check_creds.setChecked(True)
        options_layout.addWidget(self.check_creds)
        
        self.check_misconfig = QCheckBox("Misconfigurations")
        self.check_misconfig.setChecked(True)
        options_layout.addWidget(self.check_misconfig)
        
        options_layout.addStretch()
        layout.addWidget(options_group)
        
        # Progress
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        layout.addWidget(self.scan_progress)
        
        # Scan buttons
        button_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🚀 Start Vulnerability Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff4444, #ff6b00);
                color: white;
                font-size: 16px;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #ff6666, #ff8533);
            }
        """)
        button_layout.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        layout.addStretch()
        
        return widget
    
    def create_results_tab(self):
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Summary
        summary_group = QGroupBox("Scan Summary")
        summary_layout = QHBoxLayout(summary_group)
        
        self.total_vulns = self.create_stat_label("Total", "0", "#ffffff")
        self.critical_vulns = self.create_stat_label("Critical", "0", "#ff0000")
        self.high_vulns = self.create_stat_label("High", "0", "#ff6b00")
        self.medium_vulns = self.create_stat_label("Medium", "0", "#ffaa00")
        self.low_vulns = self.create_stat_label("Low", "0", "#00d4ff")
        self.info_vulns = self.create_stat_label("Info", "0", "#888888")
        
        for label in [self.total_vulns, self.critical_vulns, self.high_vulns,
                      self.medium_vulns, self.low_vulns, self.info_vulns]:
            summary_layout.addWidget(label)
        
        summary_layout.addStretch()
        layout.addWidget(summary_group)
        
        # Splitter for tree and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Vulnerability tree
        tree_widget = QWidget()
        tree_layout = QVBoxLayout(tree_widget)
        tree_layout.setContentsMargins(0, 0, 0, 0)
        
        tree_filter = QHBoxLayout()
        tree_filter.addWidget(QLabel("Filter:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.currentTextChanged.connect(self.filter_results)
        tree_filter.addWidget(self.severity_filter)
        tree_filter.addStretch()
        tree_layout.addLayout(tree_filter)
        
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setHeaderLabels(["Vulnerability", "Severity", "CVSS", "Target"])
        self.vuln_tree.setColumnWidth(0, 300)
        self.vuln_tree.itemClicked.connect(self.on_vuln_selected)
        self.vuln_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d0d1a;
                border: 1px solid #333;
            }
            QTreeWidget::item:selected {
                background: #ff4444;
            }
        """)
        tree_layout.addWidget(self.vuln_tree)
        
        splitter.addWidget(tree_widget)
        
        # Details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 0, 0, 0)
        
        details_group = QGroupBox("Vulnerability Details")
        details_inner = QVBoxLayout(details_group)
        
        self.vuln_title = QLabel("Select a vulnerability")
        self.vuln_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff4444;")
        details_inner.addWidget(self.vuln_title)
        
        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                color: #00ff88;
                border: 1px solid #333;
                font-family: 'Consolas', monospace;
            }
        """)
        details_inner.addWidget(self.vuln_details)
        
        details_layout.addWidget(details_group)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        verify_btn = QPushButton("✅ Verify")
        verify_btn.clicked.connect(self.verify_vuln)
        actions_layout.addWidget(verify_btn)
        
        false_positive_btn = QPushButton("❌ Mark False Positive")
        false_positive_btn.clicked.connect(self.mark_false_positive)
        actions_layout.addWidget(false_positive_btn)
        
        exploit_btn = QPushButton("💀 Find Exploits")
        exploit_btn.clicked.connect(self.find_exploits)
        actions_layout.addWidget(exploit_btn)
        
        actions_layout.addStretch()
        details_layout.addLayout(actions_layout)
        
        splitter.addWidget(details_widget)
        splitter.setSizes([500, 500])
        
        layout.addWidget(splitter)
        
        return widget
    
    def create_cve_tab(self):
        """Create CVE lookup tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Search
        search_group = QGroupBox("CVE Search")
        search_layout = QVBoxLayout(search_group)
        
        cve_search_layout = QHBoxLayout()
        cve_search_layout.addWidget(QLabel("CVE ID:"))
        self.cve_id_input = QLineEdit()
        self.cve_id_input.setPlaceholderText("CVE-2021-44228")
        cve_search_layout.addWidget(self.cve_id_input)
        
        self.lookup_btn = QPushButton("🔍 Lookup")
        self.lookup_btn.clicked.connect(self.lookup_cve)
        cve_search_layout.addWidget(self.lookup_btn)
        search_layout.addLayout(cve_search_layout)
        
        keyword_layout = QHBoxLayout()
        keyword_layout.addWidget(QLabel("Keyword:"))
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("apache, log4j, spring...")
        keyword_layout.addWidget(self.keyword_input)
        
        self.search_btn = QPushButton("🔎 Search")
        self.search_btn.clicked.connect(self.search_cves)
        keyword_layout.addWidget(self.search_btn)
        search_layout.addLayout(keyword_layout)
        
        layout.addWidget(search_group)
        
        # Results
        self.cve_table = QTableWidget()
        self.cve_table.setColumnCount(5)
        self.cve_table.setHorizontalHeaderLabels([
            "CVE ID", "CVSS", "Severity", "Published", "Description"
        ])
        self.cve_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.cve_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.cve_table.itemDoubleClicked.connect(self.show_cve_details)
        layout.addWidget(self.cve_table)
        
        # CVE Details
        cve_details_group = QGroupBox("CVE Details")
        cve_details_layout = QVBoxLayout(cve_details_group)
        
        self.cve_details = QTextEdit()
        self.cve_details.setReadOnly(True)
        self.cve_details.setMaximumHeight(200)
        self.cve_details.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                color: #00d4ff;
                border: 1px solid #333;
            }
        """)
        cve_details_layout.addWidget(self.cve_details)
        
        layout.addWidget(cve_details_group)
        
        return widget
    
    def create_reports_tab(self):
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Export options
        export_group = QGroupBox("Export Report")
        export_layout = QHBoxLayout(export_group)
        
        export_layout.addWidget(QLabel("Format:"))
        self.export_format = QComboBox()
        self.export_format.addItems(["JSON", "CSV", "HTML", "PDF"])
        export_layout.addWidget(self.export_format)
        
        self.export_btn = QPushButton("📤 Export")
        self.export_btn.clicked.connect(self.export_report)
        export_layout.addWidget(self.export_btn)
        
        export_layout.addStretch()
        layout.addWidget(export_group)
        
        # Preview
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                color: #ffffff;
                border: 1px solid #333;
                font-family: 'Consolas', monospace;
            }
        """)
        preview_layout.addWidget(self.report_preview)
        
        layout.addWidget(preview_group)
        
        self.refresh_report_btn = QPushButton("🔄 Refresh Preview")
        self.refresh_report_btn.clicked.connect(self.refresh_report)
        layout.addWidget(self.refresh_report_btn)
        
        return widget
    
    def create_stat_label(self, title: str, value: str, color: str) -> QFrame:
        """Create a statistics label"""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: #1a1a2e;
                border: 2px solid {color};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 5, 10, 5)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {color}; font-size: 12px;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setObjectName(f"value_{title.lower()}")
        value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        return frame
    
    def add_target(self):
        """Add target to scan list"""
        host = self.target_host.text().strip()
        ports_text = self.target_ports.text().strip()
        service = self.service_info.text().strip()
        version = self.version_info.text().strip()
        
        if not host:
            QMessageBox.warning(self, "Error", "Enter a target host")
            return
        
        # Parse ports
        ports = []
        for part in ports_text.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                ports.append(int(part))
        
        if not ports:
            ports = [80]
        
        # Add to table
        for port in ports:
            row = self.targets_table.rowCount()
            self.targets_table.insertRow(row)
            self.targets_table.setItem(row, 0, QTableWidgetItem(host))
            self.targets_table.setItem(row, 1, QTableWidgetItem(str(port)))
            self.targets_table.setItem(row, 2, QTableWidgetItem(service))
            self.targets_table.setItem(row, 3, QTableWidgetItem(version))
            self.targets_table.setItem(row, 4, QTableWidgetItem("Pending"))
        
        self.status_bar.setText(f"Added {len(ports)} targets")
    
    def clear_targets(self):
        """Clear all targets"""
        self.targets_table.setRowCount(0)
    
    def import_nmap_results(self):
        """Import targets from Nmap scan"""
        # This would integrate with the Nmap page
        QMessageBox.information(
            self, "Import",
            "Run an Nmap scan first, then targets will be available for import."
        )
    
    def start_scan(self):
        """Start vulnerability scan"""
        if self.targets_table.rowCount() == 0:
            QMessageBox.warning(self, "Error", "Add targets first")
            return
        
        # Build target list
        targets = []
        for row in range(self.targets_table.rowCount()):
            target = ScanTarget(
                host=self.targets_table.item(row, 0).text(),
                port=int(self.targets_table.item(row, 1).text()),
                service=self.targets_table.item(row, 2).text() if self.targets_table.item(row, 2) else "",
                version=self.targets_table.item(row, 3).text() if self.targets_table.item(row, 3) else ""
            )
            targets.append(target)
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        
        self.status_bar.setText(f"Scanning {len(targets)} targets...")
        
        worker = ScanWorker(self.scanner, targets)
        worker.result_ready.connect(self.on_scan_complete)
        worker.progress.connect(self.on_scan_progress)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def stop_scan(self):
        """Stop scanning"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.scan_progress.setVisible(False)
    
    def on_scan_progress(self, message: str, percent: int):
        """Update scan progress"""
        self.status_bar.setText(message)
        self.scan_progress.setValue(percent)
    
    def on_scan_complete(self, vulns: list):
        """Handle scan completion"""
        self.stop_scan()
        self.vulnerabilities = vulns
        
        # Update summary
        summary = self.scanner.get_summary()
        self.update_stat_value(self.total_vulns, str(summary['total']))
        self.update_stat_value(self.critical_vulns, str(summary['by_severity']['critical']))
        self.update_stat_value(self.high_vulns, str(summary['by_severity']['high']))
        self.update_stat_value(self.medium_vulns, str(summary['by_severity']['medium']))
        self.update_stat_value(self.low_vulns, str(summary['by_severity']['low']))
        self.update_stat_value(self.info_vulns, str(summary['by_severity']['informational']))
        
        # Populate tree
        self.populate_vuln_tree(vulns)
        
        # Update target status
        for row in range(self.targets_table.rowCount()):
            status_item = QTableWidgetItem("Scanned")
            status_item.setBackground(QColor("#00ff88"))
            self.targets_table.setItem(row, 4, status_item)
        
        self.status_bar.setText(f"Scan complete: {len(vulns)} vulnerabilities found")
        
        # Refresh report preview
        self.refresh_report()
    
    def update_stat_value(self, frame: QFrame, value: str):
        """Update statistic value"""
        for child in frame.findChildren(QLabel):
            if child.objectName().startswith("value_"):
                child.setText(value)
    
    def populate_vuln_tree(self, vulns: list):
        """Populate vulnerability tree"""
        self.vuln_tree.clear()
        
        # Group by severity
        by_severity = {}
        for vuln in vulns:
            sev = vuln.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(vuln)
        
        # Add to tree
        severity_order = ['critical', 'high', 'medium', 'low', 'informational']
        for sev in severity_order:
            if sev in by_severity:
                parent = QTreeWidgetItem(self.vuln_tree)
                parent.setText(0, f"{sev.upper()} ({len(by_severity[sev])})")
                parent.setForeground(0, QBrush(self.SEVERITY_COLORS.get(
                    Severity(sev), QColor("#ffffff")
                )))
                
                for vuln in by_severity[sev]:
                    child = QTreeWidgetItem(parent)
                    child.setText(0, vuln.title[:50])
                    child.setText(1, vuln.severity.value.upper())
                    child.setText(2, str(vuln.cvss_score))
                    child.setText(3, f"{vuln.target}:{vuln.port}")
                    child.setData(0, Qt.ItemDataRole.UserRole, vuln)
                    child.setForeground(1, QBrush(self.SEVERITY_COLORS.get(
                        vuln.severity, QColor("#ffffff")
                    )))
        
        self.vuln_tree.expandAll()
    
    def filter_results(self, severity: str):
        """Filter results by severity"""
        if severity == "All":
            self.populate_vuln_tree(self.vulnerabilities)
        else:
            filtered = [v for v in self.vulnerabilities if v.severity.value == severity.lower()]
            self.populate_vuln_tree(filtered)
    
    def on_vuln_selected(self, item: QTreeWidgetItem):
        """Handle vulnerability selection"""
        vuln = item.data(0, Qt.ItemDataRole.UserRole)
        if not vuln:
            return
        
        self.vuln_title.setText(vuln.title)
        
        details = f"""
<b>Type:</b> {vuln.vuln_type.value}<br>
<b>Severity:</b> {vuln.severity.value.upper()}<br>
<b>CVSS Score:</b> {vuln.cvss_score}<br>
<b>Target:</b> {vuln.target}:{vuln.port}<br>
<b>Service:</b> {vuln.service}<br><br>

<b>Description:</b><br>
{vuln.description}<br><br>

<b>Evidence:</b><br>
{vuln.evidence}<br><br>

<b>Remediation:</b><br>
{vuln.remediation}<br><br>
"""
        
        if vuln.cve:
            details += f"""
<b>CVE:</b> {vuln.cve.cve_id}<br>
<b>CVE Description:</b> {vuln.cve.description[:300]}...<br>
"""
        
        if vuln.references:
            details += "<b>References:</b><br>"
            for ref in vuln.references[:5]:
                details += f"• {ref}<br>"
        
        self.vuln_details.setHtml(details)
    
    def verify_vuln(self):
        """Verify selected vulnerability"""
        item = self.vuln_tree.currentItem()
        if item:
            vuln = item.data(0, Qt.ItemDataRole.UserRole)
            if vuln:
                vuln.verified = True
                item.setForeground(0, QBrush(QColor("#00ff88")))
                self.status_bar.setText(f"Verified: {vuln.title}")
    
    def mark_false_positive(self):
        """Mark as false positive"""
        item = self.vuln_tree.currentItem()
        if item:
            vuln = item.data(0, Qt.ItemDataRole.UserRole)
            if vuln:
                vuln.false_positive = True
                item.setForeground(0, QBrush(QColor("#666666")))
                self.status_bar.setText(f"Marked as false positive: {vuln.title}")
    
    def find_exploits(self):
        """Find exploits for vulnerability"""
        item = self.vuln_tree.currentItem()
        if item:
            vuln = item.data(0, Qt.ItemDataRole.UserRole)
            if vuln and vuln.cve:
                # Would integrate with exploit browser
                QMessageBox.information(
                    self, "Find Exploits",
                    f"Search for exploits:\n\n"
                    f"• ExploitDB: searchsploit {vuln.cve.cve_id}\n"
                    f"• GitHub: site:github.com {vuln.cve.cve_id}\n"
                    f"• Metasploit: search {vuln.cve.cve_id}"
                )
    
    def lookup_cve(self):
        """Lookup specific CVE"""
        cve_id = self.cve_id_input.text().strip()
        if not cve_id:
            return
        
        self.status_bar.setText(f"Looking up {cve_id}...")
        
        worker = CVEWorker(self.scanner, self.scanner.lookup_cve, cve_id)
        worker.result_ready.connect(self.on_cve_lookup)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_cve_lookup(self, cve):
        """Handle CVE lookup result"""
        if cve:
            self.cve_table.setRowCount(1)
            self.add_cve_to_table(0, cve)
            
            self.cve_details.setHtml(f"""
<b>{cve.cve_id}</b><br><br>
<b>CVSS:</b> {cve.cvss_score}<br>
<b>Severity:</b> {cve.severity.value.upper()}<br>
<b>Published:</b> {cve.published.strftime('%Y-%m-%d')}<br>
<b>Modified:</b> {cve.modified.strftime('%Y-%m-%d')}<br><br>
<b>Description:</b><br>
{cve.description}<br><br>
<b>References:</b><br>
{'<br>'.join('• ' + r for r in cve.references[:10])}
""")
            self.status_bar.setText(f"Found: {cve.cve_id}")
        else:
            self.status_bar.setText("CVE not found")
    
    def search_cves(self):
        """Search CVEs by keyword"""
        keyword = self.keyword_input.text().strip()
        if not keyword:
            return
        
        self.status_bar.setText(f"Searching for '{keyword}'...")
        
        worker = CVEWorker(self.scanner, self.scanner.search_cves, keyword)
        worker.result_ready.connect(self.on_cve_search)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_cve_search(self, cves: list):
        """Handle CVE search results"""
        self.cve_table.setRowCount(len(cves))
        
        for row, cve in enumerate(cves):
            self.add_cve_to_table(row, cve)
        
        self.status_bar.setText(f"Found {len(cves)} CVEs")
    
    def add_cve_to_table(self, row: int, cve):
        """Add CVE to table"""
        self.cve_table.setItem(row, 0, QTableWidgetItem(cve.cve_id))
        
        cvss_item = QTableWidgetItem(str(cve.cvss_score))
        self.cve_table.setItem(row, 1, cvss_item)
        
        sev_item = QTableWidgetItem(cve.severity.value.upper())
        sev_item.setBackground(self.SEVERITY_COLORS.get(cve.severity, QColor("#888")))
        self.cve_table.setItem(row, 2, sev_item)
        
        self.cve_table.setItem(row, 3, QTableWidgetItem(cve.published.strftime('%Y-%m-%d')))
        self.cve_table.setItem(row, 4, QTableWidgetItem(cve.description[:100] + "..."))
        
        # Store full CVE object
        self.cve_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, cve)
    
    def show_cve_details(self, item: QTableWidgetItem):
        """Show CVE details on double click"""
        row = item.row()
        cve = self.cve_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if cve:
            self.cve_details.setHtml(f"""
<b>{cve.cve_id}</b><br><br>
<b>CVSS:</b> {cve.cvss_score}<br>
<b>Severity:</b> {cve.severity.value.upper()}<br>
<b>Published:</b> {cve.published.strftime('%Y-%m-%d')}<br><br>
<b>Description:</b><br>
{cve.description}
""")
    
    def export_report(self):
        """Export vulnerability report"""
        format_type = self.export_format.currentText().lower()
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Report", f"vuln_report.{format_type}",
            f"{format_type.upper()} Files (*.{format_type})"
        )
        
        if filepath:
            report = self.scanner.export_report(format_type)
            
            if format_type == 'html':
                report = self.generate_html_report()
            
            with open(filepath, 'w') as f:
                f.write(report)
            
            self.status_bar.setText(f"Report exported to {filepath}")
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        summary = self.scanner.get_summary()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #fff; }}
        h1 {{ color: #ff4444; }}
        h2 {{ color: #00d4ff; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #0d0d1a; padding: 20px; border-radius: 8px; text-align: center; }}
        .critical {{ border: 2px solid #ff0000; }}
        .high {{ border: 2px solid #ff6b00; }}
        .medium {{ border: 2px solid #ffaa00; }}
        .low {{ border: 2px solid #00d4ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; border: 1px solid #333; text-align: left; }}
        th {{ background: #333; }}
        .severity-critical {{ background: #ff0000; color: #fff; }}
        .severity-high {{ background: #ff6b00; }}
        .severity-medium {{ background: #ffaa00; }}
        .severity-low {{ background: #00d4ff; }}
    </style>
</head>
<body>
    <h1>🔍 Vulnerability Scan Report</h1>
    <p>Generated: {self.scanner.vulnerabilities[0].detected_at.strftime('%Y-%m-%d %H:%M:%S') if self.scanner.vulnerabilities else 'N/A'}</p>
    
    <h2>Summary</h2>
    <div class="summary">
        <div class="stat">Total<br><b>{summary['total']}</b></div>
        <div class="stat critical">Critical<br><b>{summary['by_severity']['critical']}</b></div>
        <div class="stat high">High<br><b>{summary['by_severity']['high']}</b></div>
        <div class="stat medium">Medium<br><b>{summary['by_severity']['medium']}</b></div>
        <div class="stat low">Low<br><b>{summary['by_severity']['low']}</b></div>
    </div>
    
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Target</th>
            <th>CVE</th>
        </tr>
"""
        
        for vuln in self.scanner.vulnerabilities:
            cve_id = vuln.cve.cve_id if vuln.cve else '-'
            html += f"""
        <tr>
            <td>{vuln.title}</td>
            <td class="severity-{vuln.severity.value}">{vuln.severity.value.upper()}</td>
            <td>{vuln.cvss_score}</td>
            <td>{vuln.target}:{vuln.port}</td>
            <td>{cve_id}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        return html
    
    def refresh_report(self):
        """Refresh report preview"""
        report = self.scanner.export_report('json')
        self.report_preview.setPlainText(report)
    
    def on_error(self, error: str):
        """Handle errors"""
        self.stop_scan()
        self.status_bar.setText(f"Error: {error}")
        QMessageBox.critical(self, "Error", error)
