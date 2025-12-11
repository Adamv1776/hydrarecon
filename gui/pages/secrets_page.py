#!/usr/bin/env python3
"""
Secrets Scanner GUI Page
Detect leaked credentials, API keys, and sensitive data.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QGroupBox, QTableWidget, QTableWidgetItem,
    QTabWidget, QPlainTextEdit, QSplitter, QProgressBar, QFileDialog,
    QHeaderView, QComboBox, QCheckBox, QFrame, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor
from pathlib import Path


class ScanWorker(QThread):
    """Worker thread for scanning."""
    progress = pyqtSignal(int)
    finding = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    
    def __init__(self, path, scan_git=False):
        super().__init__()
        self.path = path
        self.scan_git = scan_git
    
    def run(self):
        import asyncio
        from core.secrets_scanner import SecretsScanner
        
        async def scan():
            scanner = SecretsScanner()
            findings = await scanner.scan_directory(Path(self.path))
            
            if self.scan_git and Path(self.path).joinpath('.git').exists():
                git_findings = await scanner.scan_git_history(Path(self.path))
                findings.extend(git_findings)
            
            return scanner.get_summary(), findings
        
        try:
            summary, findings = asyncio.run(scan())
            for f in findings:
                self.finding.emit({
                    'id': f.id,
                    'type': f.secret_type.value,
                    'severity': f.severity.value,
                    'file': f.file_path,
                    'line': f.line_number,
                    'secret': f.secret_value,
                    'description': f.description
                })
            self.finished.emit(summary)
        except Exception as e:
            self.finished.emit({'error': str(e)})


class SecretsPage(QWidget):
    """Secrets Scanner Page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings = []
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🧬 Secrets Scanner")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #ff6b6b;")
        layout.addWidget(header)
        
        subtitle = QLabel("Detect leaked credentials, API keys, tokens, and sensitive data")
        subtitle.setStyleSheet("color: #888; font-size: 14px;")
        layout.addWidget(subtitle)
        
        # Input section
        input_group = QGroupBox("🔍 Scan Target")
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
                color: #ff6b6b;
            }
        """)
        input_layout = QVBoxLayout(input_group)
        
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter directory path or URL to scan...")
        path_layout.addWidget(self.path_input)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self.browse_directory)
        path_layout.addWidget(browse_btn)
        
        input_layout.addLayout(path_layout)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.scan_git = QCheckBox("Scan Git History")
        self.scan_git.setChecked(True)
        options_layout.addWidget(self.scan_git)
        
        self.scan_recursive = QCheckBox("Recursive")
        self.scan_recursive.setChecked(True)
        options_layout.addWidget(self.scan_recursive)
        
        self.verify_secrets = QCheckBox("Verify Secrets (API check)")
        options_layout.addWidget(self.verify_secrets)
        
        options_layout.addStretch()
        
        self.scan_btn = QPushButton("🚀 Start Scan")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #ff6b6b;
                color: white;
                border: none;
                padding: 10px 30px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #ff8888;
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
                background: #ff6b6b;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.critical_card = self.create_stat_card("🔴 Critical", "0", "#ff4444")
        self.high_card = self.create_stat_card("🟠 High", "0", "#ff8844")
        self.medium_card = self.create_stat_card("🟡 Medium", "0", "#ffcc00")
        self.low_card = self.create_stat_card("🟢 Low", "0", "#44cc44")
        self.files_card = self.create_stat_card("📁 Files", "0", "#00d4ff")
        
        stats_layout.addWidget(self.critical_card)
        stats_layout.addWidget(self.high_card)
        stats_layout.addWidget(self.medium_card)
        stats_layout.addWidget(self.low_card)
        stats_layout.addWidget(self.files_card)
        
        layout.addLayout(stats_layout)
        
        # Results table
        results_group = QGroupBox("🔐 Detected Secrets")
        results_group.setStyleSheet(input_group.styleSheet())
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Severity", "Type", "File", "Line", "Secret (Masked)", "Actions"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.results_table.setColumnWidth(0, 80)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.results_table.setColumnWidth(3, 60)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #1e1e2e;
                gridline-color: #333;
                border: none;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #2a2a4a;
            }
            QHeaderView::section {
                background: #252540;
                color: #888;
                padding: 8px;
                border: none;
            }
        """)
        
        results_layout.addWidget(self.results_table)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json = QPushButton("📦 Export JSON")
        export_json.clicked.connect(lambda: self.export_results("json"))
        export_layout.addWidget(export_json)
        
        export_csv = QPushButton("📊 Export CSV")
        export_csv.clicked.connect(lambda: self.export_results("csv"))
        export_layout.addWidget(export_csv)
        
        export_sarif = QPushButton("🔧 Export SARIF")
        export_sarif.clicked.connect(lambda: self.export_results("sarif"))
        export_layout.addWidget(export_sarif)
        
        export_layout.addStretch()
        
        clear_btn = QPushButton("🗑️ Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        export_layout.addWidget(clear_btn)
        
        results_layout.addLayout(export_layout)
        layout.addWidget(results_group)
    
    def create_stat_card(self, title, value, color):
        """Create a statistics card widget."""
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
        title_label.setStyleSheet(f"color: #888; font-size: 12px;")
        card_layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        value_label.setObjectName("value")
        card_layout.addWidget(value_label)
        
        return card
    
    def update_stat_card(self, card, value):
        """Update a stat card's value."""
        label = card.findChild(QLabel, "value")
        if label:
            label.setText(str(value))
    
    def browse_directory(self):
        """Open directory browser."""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory to Scan"
        )
        if directory:
            self.path_input.setText(directory)
    
    def start_scan(self):
        """Start the secrets scan."""
        path = self.path_input.text()
        if not path:
            QMessageBox.warning(self, "Error", "Please enter a path to scan")
            return
        
        self.findings = []
        self.results_table.setRowCount(0)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.scan_btn.setEnabled(False)
        
        self.worker = ScanWorker(path, self.scan_git.isChecked())
        self.worker.finding.connect(self.add_finding)
        self.worker.finished.connect(self.scan_complete)
        self.worker.start()
    
    def add_finding(self, finding):
        """Add a finding to the results table."""
        self.findings.append(finding)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Severity with color
        severity = finding['severity']
        severity_item = QTableWidgetItem(severity)
        if severity == "Critical":
            severity_item.setForeground(QColor("#ff4444"))
        elif severity == "High":
            severity_item.setForeground(QColor("#ff8844"))
        elif severity == "Medium":
            severity_item.setForeground(QColor("#ffcc00"))
        else:
            severity_item.setForeground(QColor("#44cc44"))
        self.results_table.setItem(row, 0, severity_item)
        
        # Other columns
        self.results_table.setItem(row, 1, QTableWidgetItem(finding['type']))
        self.results_table.setItem(row, 2, QTableWidgetItem(finding['file']))
        self.results_table.setItem(row, 3, QTableWidgetItem(str(finding['line'])))
        self.results_table.setItem(row, 4, QTableWidgetItem(finding['secret']))
        
        # Actions
        view_btn = QPushButton("👁️")
        view_btn.setMaximumWidth(40)
        self.results_table.setCellWidget(row, 5, view_btn)
    
    def scan_complete(self, summary):
        """Handle scan completion."""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        
        if 'error' in summary:
            QMessageBox.critical(self, "Scan Error", summary['error'])
            return
        
        # Update stats
        by_severity = summary.get('by_severity', {})
        self.update_stat_card(self.critical_card, by_severity.get('Critical', 0))
        self.update_stat_card(self.high_card, by_severity.get('High', 0))
        self.update_stat_card(self.medium_card, by_severity.get('Medium', 0))
        self.update_stat_card(self.low_card, by_severity.get('Low', 0))
        self.update_stat_card(self.files_card, summary.get('files_scanned', 0))
    
    def export_results(self, format):
        """Export results to file."""
        if not self.findings:
            QMessageBox.information(self, "No Data", "No findings to export")
            return
        
        extensions = {"json": "json", "csv": "csv", "sarif": "sarif.json"}
        ext = extensions.get(format, "json")
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", f"secrets_scan.{ext}",
            f"Files (*.{ext});;All Files (*)"
        )
        
        if file_path:
            import json
            
            if format == "json":
                with open(file_path, 'w') as f:
                    json.dump(self.findings, f, indent=2)
            elif format == "csv":
                with open(file_path, 'w') as f:
                    f.write("ID,Type,Severity,File,Line,Secret\n")
                    for finding in self.findings:
                        f.write(f'"{finding["id"]}","{finding["type"]}","{finding["severity"]}","{finding["file"]}",{finding["line"]},"{finding["secret"]}"\n')
    
    def clear_results(self):
        """Clear all results."""
        self.findings = []
        self.results_table.setRowCount(0)
        self.update_stat_card(self.critical_card, 0)
        self.update_stat_card(self.high_card, 0)
        self.update_stat_card(self.medium_card, 0)
        self.update_stat_card(self.low_card, 0)
        self.update_stat_card(self.files_card, 0)
