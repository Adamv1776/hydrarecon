#!/usr/bin/env python3
"""
Subdomain Takeover Scanner GUI Page
Detect vulnerable subdomains that can be claimed.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QGroupBox, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QProgressBar, QHeaderView, QFrame, QMessageBox,
    QSpinBox, QCheckBox, QSplitter
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor


class TakeoverScanWorker(QThread):
    """Worker thread for subdomain takeover scanning."""
    progress = pyqtSignal(str)
    finding = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    
    def __init__(self, domain, subdomains=None):
        super().__init__()
        self.domain = domain
        self.subdomains = subdomains
    
    def run(self):
        import asyncio
        from core.subdomain_takeover import SubdomainTakeoverScanner
        
        async def scan():
            scanner = SubdomainTakeoverScanner()
            await scanner.initialize()
            
            if self.subdomains:
                findings = await scanner.scan_subdomains(self.subdomains)
            else:
                results = await scanner.enumerate_and_scan(self.domain)
                return results
            
            return {
                'domain': self.domain,
                'findings': [{
                    'subdomain': f.subdomain,
                    'type': f.takeover_type.value,
                    'severity': f.severity.value,
                    'cname': f.cname_record,
                    'evidence': f.evidence,
                    'confidence': f.confidence,
                    'poc': f.poc,
                    'remediation': f.remediation
                } for f in findings],
                'summary': scanner.get_summary()
            }
        
        try:
            results = asyncio.run(scan())
            self.finished.emit(results)
        except Exception as e:
            self.finished.emit({'error': str(e)})


class SubdomainTakeoverPage(QWidget):
    """Subdomain Takeover Scanner Page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🌐 Subdomain Takeover Scanner")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ff88;")
        layout.addWidget(header)
        
        subtitle = QLabel("Detect dangling DNS records and vulnerable cloud services")
        subtitle.setStyleSheet("color: #888; font-size: 14px;")
        layout.addWidget(subtitle)
        
        # Input section
        input_group = QGroupBox("🎯 Target Domain")
        input_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                background: #1a1a2e;
            }
            QGroupBox::title {
                color: #00ff88;
            }
        """)
        input_layout = QVBoxLayout(input_group)
        
        # Domain input
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        domain_layout.addWidget(self.domain_input)
        input_layout.addLayout(domain_layout)
        
        # Custom subdomains
        subdomain_layout = QHBoxLayout()
        subdomain_layout.addWidget(QLabel("Custom Subdomains (one per line):"))
        input_layout.addLayout(subdomain_layout)
        
        self.subdomains_input = QPlainTextEdit()
        self.subdomains_input.setPlaceholderText("www.example.com\napi.example.com\napp.example.com")
        self.subdomains_input.setMaximumHeight(100)
        input_layout.addWidget(self.subdomains_input)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.auto_enumerate = QCheckBox("Auto-enumerate common subdomains")
        self.auto_enumerate.setChecked(True)
        options_layout.addWidget(self.auto_enumerate)
        
        options_layout.addWidget(QLabel("Concurrent:"))
        self.concurrent = QSpinBox()
        self.concurrent.setRange(1, 50)
        self.concurrent.setValue(10)
        options_layout.addWidget(self.concurrent)
        
        options_layout.addStretch()
        
        self.scan_btn = QPushButton("🔍 Scan for Takeovers")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #00ff88;
                color: #000;
                border: none;
                padding: 12px 30px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00ffaa;
            }
        """)
        self.scan_btn.clicked.connect(self.start_scan)
        options_layout.addWidget(self.scan_btn)
        
        input_layout.addLayout(options_layout)
        layout.addWidget(input_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #333;
                border-radius: 4px;
                text-align: center;
                background: #1a1a2e;
            }
            QProgressBar::chunk {
                background: #00ff88;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #888;")
        layout.addWidget(self.status_label)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.checked_card = self.create_stat_card("🔍 Checked", "0", "#00d4ff")
        self.vulnerable_card = self.create_stat_card("⚠️ Vulnerable", "0", "#ff4444")
        self.critical_card = self.create_stat_card("🔴 Critical", "0", "#ff4444")
        self.high_card = self.create_stat_card("🟠 High", "0", "#ff8844")
        
        stats_layout.addWidget(self.checked_card)
        stats_layout.addWidget(self.vulnerable_card)
        stats_layout.addWidget(self.critical_card)
        stats_layout.addWidget(self.high_card)
        
        layout.addLayout(stats_layout)
        
        # Results splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Findings table
        findings_group = QGroupBox("🎯 Vulnerable Subdomains")
        findings_group.setStyleSheet(input_group.styleSheet())
        findings_layout = QVBoxLayout(findings_group)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels([
            "Subdomain", "Service", "Severity", "CNAME", "Confidence"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.itemClicked.connect(self.show_details)
        self.findings_table.setStyleSheet("""
            QTableWidget {
                background: #1e1e2e;
                gridline-color: #333;
                border: none;
            }
            QTableWidget::item:selected {
                background: #2a2a4a;
            }
        """)
        findings_layout.addWidget(self.findings_table)
        
        splitter.addWidget(findings_group)
        
        # Right: Details
        details_group = QGroupBox("📋 Takeover Details & PoC")
        details_group.setStyleSheet(input_group.styleSheet())
        details_layout = QVBoxLayout(details_group)
        
        self.details_output = QPlainTextEdit()
        self.details_output.setReadOnly(True)
        self.details_output.setStyleSheet("""
            font-family: 'Consolas', monospace;
            font-size: 12px;
            background: #1e1e2e;
        """)
        details_layout.addWidget(self.details_output)
        
        splitter.addWidget(details_group)
        splitter.setSizes([500, 400])
        
        layout.addWidget(splitter)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json = QPushButton("📦 Export JSON")
        export_json.clicked.connect(lambda: self.export_results("json"))
        export_layout.addWidget(export_json)
        
        export_md = QPushButton("📄 Export Markdown")
        export_md.clicked.connect(lambda: self.export_results("markdown"))
        export_layout.addWidget(export_md)
        
        export_layout.addStretch()
        layout.addLayout(export_layout)
        
        # Store results
        self.scan_results = {}
    
    def create_stat_card(self, title, value, color):
        """Create a stat card."""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(5)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #888; font-size: 12px;")
        card_layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        value_label.setObjectName("value")
        card_layout.addWidget(value_label)
        
        return card
    
    def update_stat_card(self, card, value):
        """Update stat card value."""
        label = card.findChild(QLabel, "value")
        if label:
            label.setText(str(value))
    
    def start_scan(self):
        """Start subdomain takeover scan."""
        domain = self.domain_input.text()
        if not domain:
            QMessageBox.warning(self, "Error", "Please enter a domain")
            return
        
        # Parse custom subdomains
        subdomains = None
        custom_text = self.subdomains_input.toPlainText().strip()
        if custom_text and not self.auto_enumerate.isChecked():
            subdomains = [s.strip() for s in custom_text.split('\n') if s.strip()]
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.scan_btn.setEnabled(False)
        self.status_label.setText("Scanning...")
        self.findings_table.setRowCount(0)
        
        self.worker = TakeoverScanWorker(domain, subdomains)
        self.worker.finished.connect(self.scan_complete)
        self.worker.start()
    
    def scan_complete(self, results):
        """Handle scan completion."""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        
        if 'error' in results:
            self.status_label.setText(f"Error: {results['error']}")
            QMessageBox.critical(self, "Scan Error", results['error'])
            return
        
        self.scan_results = results
        self.status_label.setText(f"Scan complete - {len(results.get('findings', []))} vulnerabilities found")
        
        # Update stats
        summary = results.get('summary', {})
        self.update_stat_card(self.checked_card, summary.get('domains_checked', results.get('subdomains_checked', 0)))
        self.update_stat_card(self.vulnerable_card, len(results.get('findings', [])))
        
        by_severity = summary.get('by_severity', {})
        self.update_stat_card(self.critical_card, by_severity.get('Critical', 0))
        self.update_stat_card(self.high_card, by_severity.get('High', 0))
        
        # Populate findings
        for finding in results.get('findings', []):
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            
            self.findings_table.setItem(row, 0, QTableWidgetItem(finding['subdomain']))
            self.findings_table.setItem(row, 1, QTableWidgetItem(finding['type']))
            
            severity = finding['severity']
            severity_item = QTableWidgetItem(severity)
            if severity == "Critical":
                severity_item.setForeground(QColor("#ff4444"))
            elif severity == "High":
                severity_item.setForeground(QColor("#ff8844"))
            else:
                severity_item.setForeground(QColor("#ffcc00"))
            self.findings_table.setItem(row, 2, severity_item)
            
            self.findings_table.setItem(row, 3, QTableWidgetItem(finding.get('cname', '')))
            self.findings_table.setItem(row, 4, QTableWidgetItem(f"{finding.get('confidence', 0)*100:.0f}%"))
    
    def show_details(self, item):
        """Show details for selected finding."""
        row = item.row()
        findings = self.scan_results.get('findings', [])
        
        if row < len(findings):
            finding = findings[row]
            
            details = f"""╔══════════════════════════════════════════════════════════════╗
║  SUBDOMAIN TAKEOVER: {finding['subdomain']}
╚══════════════════════════════════════════════════════════════╝

🌐 SUBDOMAIN: {finding['subdomain']}
☁️  SERVICE: {finding['type']}
⚠️  SEVERITY: {finding['severity']}
🔗 CNAME: {finding.get('cname', 'N/A')}
📊 CONFIDENCE: {finding.get('confidence', 0)*100:.0f}%

📝 EVIDENCE:
{finding.get('evidence', 'N/A')}

═══════════════════════════════════════════════════════════════
🔧 PROOF OF CONCEPT
═══════════════════════════════════════════════════════════════

{finding.get('poc', 'N/A')}

═══════════════════════════════════════════════════════════════
🛠️  REMEDIATION
═══════════════════════════════════════════════════════════════

{finding.get('remediation', 'Remove the dangling DNS record or reclaim the cloud resource.')}
"""
            self.details_output.setPlainText(details)
    
    def export_results(self, format):
        """Export results to file."""
        if not self.scan_results:
            QMessageBox.information(self, "No Data", "No scan results to export")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        if format == "json":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export JSON", "subdomain_takeover.json", "JSON Files (*.json)"
            )
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
        
        elif format == "markdown":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Markdown", "subdomain_takeover.md", "Markdown Files (*.md)"
            )
            if file_path:
                md = f"# Subdomain Takeover Report\n\n"
                md += f"**Domain:** {self.scan_results.get('domain', '')}\n\n"
                md += "## Findings\n\n"
                
                for finding in self.scan_results.get('findings', []):
                    md += f"### {finding['subdomain']}\n"
                    md += f"- **Service:** {finding['type']}\n"
                    md += f"- **Severity:** {finding['severity']}\n"
                    md += f"- **CNAME:** `{finding.get('cname', '')}`\n\n"
                
                with open(file_path, 'w') as f:
                    f.write(md)
