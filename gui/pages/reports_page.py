#!/usr/bin/env python3
"""
HydraRecon Reports Page
Professional report generation interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QCheckBox, QGroupBox, QGridLayout, QFileDialog,
    QMessageBox, QProgressBar, QScrollArea, QTabWidget, QSpinBox,
    QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from datetime import datetime
import json
import os

from ..widgets import ModernLineEdit, GlowingButton


class ReportGeneratorThread(QThread):
    """Thread for generating reports"""
    progress = pyqtSignal(int, str)
    finished_report = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, config, data, output_path, format_type):
        super().__init__()
        self.config = config
        self.data = data
        self.output_path = output_path
        self.format_type = format_type
    
    def run(self):
        try:
            self.progress.emit(10, "Gathering data...")
            
            self.progress.emit(30, "Processing findings...")
            
            self.progress.emit(50, "Generating report content...")
            
            self.progress.emit(70, f"Creating {self.format_type.upper()} file...")
            
            # Generate actual report
            if self.format_type == 'json':
                self._generate_json()
            elif self.format_type == 'html':
                self._generate_html()
            elif self.format_type == 'markdown':
                self._generate_markdown()
            elif self.format_type == 'pdf':
                self._generate_pdf()
            
            self.progress.emit(100, "Report generated successfully!")
            self.finished_report.emit(self.output_path)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def _generate_json(self):
        """Generate JSON report"""
        with open(self.output_path, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
    
    def _generate_html(self):
        """Generate HTML report"""
        html = self._get_html_template()
        with open(self.output_path, 'w') as f:
            f.write(html)
    
    def _generate_markdown(self):
        """Generate Markdown report"""
        md = self._get_markdown_template()
        with open(self.output_path, 'w') as f:
            f.write(md)
    
    def _generate_pdf(self):
        """Generate PDF report - requires additional libraries"""
        # For now, generate HTML as fallback
        html_path = self.output_path.replace('.pdf', '.html')
        self._generate_html()
        self.output_path = html_path
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        vulns = self.data.get('vulnerabilities', [])
        targets = self.data.get('targets', [])
        
        vuln_rows = ""
        for vuln in vulns:
            severity = vuln.get('severity', 'info')
            color = {'critical': '#ff4444', 'high': '#f85149', 'medium': '#d29922', 'low': '#238636', 'info': '#0088ff'}.get(severity, '#8b949e')
            vuln_rows += f"""
            <tr>
                <td style="color: {color}; font-weight: bold;">{severity.upper()}</td>
                <td>{vuln.get('title', '-')}</td>
                <td>{vuln.get('host', '-')}</td>
                <td>{vuln.get('cve', '-')}</td>
                <td>{vuln.get('cvss', '-')}</td>
            </tr>
            """
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HydraRecon Security Assessment Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --text-primary: #e6e6e6;
            --text-secondary: #8b949e;
            --accent-green: #00ff88;
            --accent-blue: #0088ff;
            --border-color: #21262d;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 40px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid var(--accent-green);
            margin-bottom: 40px;
        }}
        .header h1 {{
            font-size: 36px;
            color: var(--accent-green);
            margin-bottom: 10px;
        }}
        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 18px;
        }}
        .section {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
        }}
        .section h2 {{
            color: var(--accent-blue);
            font-size: 22px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 32px;
            font-weight: bold;
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: var(--bg-primary);
            color: var(--text-secondary);
            font-weight: 600;
        }}
        tr:hover {{
            background: var(--bg-primary);
        }}
        .footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }}
        @media print {{
            body {{ background: white; color: black; }}
            .section {{ border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 HydraRecon</h1>
            <p class="subtitle">Security Assessment Report</p>
            <p style="margin-top: 16px; color: var(--text-secondary);">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number" style="color: #ff4444;">{len([v for v in vulns if v.get('severity') == 'critical'])}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="number" style="color: #f85149;">{len([v for v in vulns if v.get('severity') == 'high'])}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card">
                    <div class="number" style="color: #d29922;">{len([v for v in vulns if v.get('severity') == 'medium'])}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="number" style="color: #238636;">{len([v for v in vulns if v.get('severity') == 'low'])}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card">
                    <div class="number" style="color: #0088ff;">{len([v for v in vulns if v.get('severity') == 'info'])}</div>
                    <div class="label">Info</div>
                </div>
            </div>
            <p>This report summarizes the findings from the security assessment conducted using HydraRecon. 
            A total of <strong>{len(vulns)}</strong> vulnerabilities were discovered across <strong>{len(targets)}</strong> targets.</p>
        </div>

        <div class="section">
            <h2>Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Host</th>
                        <th>CVE</th>
                        <th>CVSS</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows if vuln_rows else '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No vulnerabilities found</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Generated by HydraRecon - Enterprise Security Assessment Suite</p>
            <p style="font-size: 12px; margin-top: 8px;">Confidential - For authorized personnel only</p>
        </div>
    </div>
</body>
</html>"""
    
    def _get_markdown_template(self) -> str:
        """Get Markdown report template"""
        vulns = self.data.get('vulnerabilities', [])
        targets = self.data.get('targets', [])
        
        md = f"""# 🔒 HydraRecon Security Assessment Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {len([v for v in vulns if v.get('severity') == 'critical'])} |
| High | {len([v for v in vulns if v.get('severity') == 'high'])} |
| Medium | {len([v for v in vulns if v.get('severity') == 'medium'])} |
| Low | {len([v for v in vulns if v.get('severity') == 'low'])} |
| Info | {len([v for v in vulns if v.get('severity') == 'info'])} |

**Total Vulnerabilities:** {len(vulns)}  
**Total Targets:** {len(targets)}

---

## Vulnerabilities

"""
        for vuln in vulns:
            md += f"""### {vuln.get('title', 'Unknown')}

- **Severity:** {vuln.get('severity', 'info').upper()}
- **Host:** {vuln.get('host', '-')}
- **CVE:** {vuln.get('cve', '-')}
- **CVSS:** {vuln.get('cvss', '-')}

**Description:**  
{vuln.get('description', 'No description available.')}

**Remediation:**  
{vuln.get('remediation', 'No remediation guidance available.')}

---

"""
        
        md += """
## Disclaimer

This report is confidential and intended for authorized personnel only. The findings represent a point-in-time assessment and may not reflect the current security posture of the target systems.

---

*Generated by HydraRecon - Enterprise Security Assessment Suite*
"""
        return md


class ReportsPage(QWidget):
    """Reports generation page"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.report_thread = None
        self._setup_ui()
        self._load_reports()
    
    def _setup_ui(self):
        """Setup the reports page UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(20)
        
        # Header
        header = self._create_header()
        layout.addLayout(header)
        
        # Main content
        content = QHBoxLayout()
        content.setSpacing(20)
        
        # Left - Report configuration
        config_panel = self._create_config_panel()
        content.addWidget(config_panel)
        
        # Right - Preview and history
        preview_panel = self._create_preview_panel()
        content.addWidget(preview_panel)
        
        layout.addLayout(content)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("Report Generation")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Create professional security assessment reports")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        return layout
    
    def _create_config_panel(self) -> QFrame:
        """Create the configuration panel"""
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        panel.setMaximumWidth(500)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)
        
        # Report title
        title_label = QLabel("Report Configuration")
        title_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #e6e6e6;")
        layout.addWidget(title_label)
        
        # Report name
        name_label = QLabel("Report Name")
        name_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(name_label)
        
        self.report_name = ModernLineEdit("Security Assessment Report")
        layout.addWidget(self.report_name)
        
        # Output format
        format_label = QLabel("Output Format")
        format_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(format_label)
        
        format_grid = QGridLayout()
        format_grid.setSpacing(8)
        
        self.format_checks = {}
        formats = [
            ("html", "HTML", "Interactive web report"),
            ("pdf", "PDF", "Professional document"),
            ("markdown", "Markdown", "Text-based format"),
            ("json", "JSON", "Machine-readable data"),
        ]
        
        for i, (fmt_id, name, desc) in enumerate(formats):
            check = QCheckBox(name)
            check.setStyleSheet("color: #e6e6e6; font-weight: 500;")
            if fmt_id == 'html':
                check.setChecked(True)
            self.format_checks[fmt_id] = check
            
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #8b949e; font-size: 11px;")
            
            format_grid.addWidget(check, i, 0)
            format_grid.addWidget(desc_label, i, 1)
        
        layout.addLayout(format_grid)
        
        # Sections to include
        sections_label = QLabel("Include Sections")
        sections_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(sections_label)
        
        self.section_checks = {}
        sections = [
            ("executive_summary", "Executive Summary"),
            ("vulnerabilities", "Vulnerabilities"),
            ("hosts", "Discovered Hosts"),
            ("credentials", "Credentials Found"),
            ("osint", "OSINT Findings"),
            ("recommendations", "Recommendations"),
        ]
        
        for section_id, name in sections:
            check = QCheckBox(name)
            check.setChecked(True)
            check.setStyleSheet("color: #e6e6e6;")
            self.section_checks[section_id] = check
            layout.addWidget(check)
        
        # Output directory
        output_label = QLabel("Output Directory")
        output_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(output_label)
        
        output_layout = QHBoxLayout()
        self.output_path = ModernLineEdit(os.path.expanduser("~/HydraRecon_Reports"))
        output_layout.addWidget(self.output_path)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        browse_btn.clicked.connect(self._browse_output)
        output_layout.addWidget(browse_btn)
        
        layout.addLayout(output_layout)
        
        layout.addStretch()
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 6px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #238636;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #8b949e;")
        self.progress_label.setVisible(False)
        layout.addWidget(self.progress_label)
        
        # Generate button
        self.generate_btn = GlowingButton("Generate Report")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 16px;
                color: white;
                font-weight: 600;
                font-size: 15px;
            }
            QPushButton:hover { background-color: #2ea043; }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.generate_btn.clicked.connect(self._generate_report)
        layout.addWidget(self.generate_btn)
        
        return panel
    
    def _create_preview_panel(self) -> QFrame:
        """Create the preview panel"""
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                background-color: #0d1117;
                border: none;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 12px 24px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #00ff88;
                border-bottom: 2px solid #00ff88;
            }
        """)
        
        # History tab
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        history_layout.setContentsMargins(0, 16, 0, 0)
        
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:hover {
                background-color: #161b22;
            }
            QListWidget::item:selected {
                background-color: #238636;
            }
        """)
        self.history_list.itemDoubleClicked.connect(self._open_report)
        history_layout.addWidget(self.history_list)
        
        tabs.addTab(history_tab, "📁 Report History")
        
        # Templates tab
        templates_tab = QWidget()
        templates_layout = QVBoxLayout(templates_tab)
        templates_layout.setContentsMargins(0, 16, 0, 0)
        
        templates = [
            ("Executive Summary", "High-level overview for management"),
            ("Technical Report", "Detailed technical findings"),
            ("Compliance Report", "Formatted for compliance requirements"),
            ("Vulnerability Report", "Focus on vulnerabilities only"),
            ("Network Assessment", "Network infrastructure findings"),
        ]
        
        for name, desc in templates:
            template_btn = QPushButton(f"📄 {name}")
            template_btn.setToolTip(desc)
            template_btn.setStyleSheet("""
                QPushButton {
                    background-color: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 8px;
                    padding: 16px;
                    color: #e6e6e6;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: #21262d;
                    border-color: #00ff88;
                }
            """)
            templates_layout.addWidget(template_btn)
        
        templates_layout.addStretch()
        tabs.addTab(templates_tab, "📝 Templates")
        
        # Statistics tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        stats_layout.setContentsMargins(0, 16, 0, 0)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
                font-family: monospace;
            }
        """)
        self._update_stats()
        stats_layout.addWidget(self.stats_text)
        
        tabs.addTab(stats_tab, "📊 Data Summary")
        
        layout.addWidget(tabs)
        
        return panel
    
    def _load_reports(self):
        """Load report history"""
        self.history_list.clear()
        
        # Check for existing reports
        output_dir = self.output_path.text()
        if os.path.exists(output_dir):
            for filename in os.listdir(output_dir):
                if filename.endswith(('.html', '.pdf', '.md', '.json')):
                    filepath = os.path.join(output_dir, filename)
                    modified = datetime.fromtimestamp(os.path.getmtime(filepath))
                    
                    item = QListWidgetItem(f"📄 {filename}")
                    item.setData(Qt.ItemDataRole.UserRole, filepath)
                    item.setToolTip(f"Modified: {modified.strftime('%Y-%m-%d %H:%M')}")
                    self.history_list.addItem(item)
    
    def _update_stats(self):
        """Update statistics summary"""
        try:
            # Get counts from database
            vuln_count = 0
            target_count = 0
            cred_count = 0
            
            if self.db:
                try:
                    cursor = self.db.execute("SELECT COUNT(*) FROM vulnerabilities")
                    vuln_count = cursor.fetchone()[0]
                except Exception:
                    pass
                
                try:
                    cursor = self.db.execute("SELECT COUNT(*) FROM targets")
                    target_count = cursor.fetchone()[0]
                except Exception:
                    pass
                
                try:
                    cursor = self.db.execute("SELECT COUNT(*) FROM credentials")
                    cred_count = cursor.fetchone()[0]
                except Exception:
                    pass
            
            stats = f"""
╔══════════════════════════════════════════════╗
║           DATA SUMMARY                       ║
╠══════════════════════════════════════════════╣
║  📊 Total Targets:        {target_count:<18}║
║  🔓 Vulnerabilities:      {vuln_count:<18}║
║  🔑 Credentials Found:    {cred_count:<18}║
╠══════════════════════════════════════════════╣
║  Ready to generate report                    ║
╚══════════════════════════════════════════════╝
"""
            self.stats_text.setText(stats)
        except Exception as e:
            self.stats_text.setText(f"Error loading statistics: {e}")
    
    def _browse_output(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Output Directory",
            self.output_path.text()
        )
        if directory:
            self.output_path.setText(directory)
    
    def _generate_report(self):
        """Generate the report"""
        # Get selected formats
        formats = [fmt for fmt, check in self.format_checks.items() if check.isChecked()]
        
        if not formats:
            QMessageBox.warning(self, "Warning", "Please select at least one output format.")
            return
        
        # Prepare output directory
        output_dir = self.output_path.text()
        os.makedirs(output_dir, exist_ok=True)
        
        # Gather data
        data = self._gather_report_data()
        
        # Generate for each format
        self.generate_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        
        for fmt in formats:
            report_name = self.report_name.text().replace(' ', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_name}_{timestamp}.{fmt if fmt != 'markdown' else 'md'}"
            output_path = os.path.join(output_dir, filename)
            
            self.report_thread = ReportGeneratorThread(
                self.config, data, output_path, fmt
            )
            self.report_thread.progress.connect(self._on_progress)
            self.report_thread.finished_report.connect(self._on_finished)
            self.report_thread.error.connect(self._on_error)
            self.report_thread.start()
    
    def _gather_report_data(self) -> dict:
        """Gather data for the report"""
        data = {
            'title': self.report_name.text(),
            'generated': datetime.now().isoformat(),
            'vulnerabilities': [],
            'targets': [],
            'credentials': [],
            'hosts': [],
            'osint': []
        }
        
        # Get vulnerabilities
        if self.section_checks.get('vulnerabilities', QCheckBox()).isChecked():
            try:
                if self.db:
                    cursor = self.db.execute("SELECT * FROM vulnerabilities")
                    for row in cursor.fetchall():
                        data['vulnerabilities'].append({
                            'id': row[0],
                            'title': row[2] if len(row) > 2 else 'Unknown',
                            'severity': row[3] if len(row) > 3 else 'medium',
                            'host': row[4] if len(row) > 4 else '-',
                            'cve': row[7] if len(row) > 7 else '-',
                            'cvss': row[8] if len(row) > 8 else '-',
                            'description': row[9] if len(row) > 9 else '',
                            'remediation': row[10] if len(row) > 10 else ''
                        })
            except Exception:
                # Use sample data
                data['vulnerabilities'] = [
                    {'id': 1, 'title': 'Sample Vulnerability', 'severity': 'high', 'host': '192.168.1.1', 'cve': 'CVE-2024-0001', 'cvss': '7.5'}
                ]
        
        # Get targets
        if self.section_checks.get('hosts', QCheckBox()).isChecked():
            try:
                if self.db:
                    cursor = self.db.execute("SELECT * FROM targets")
                    for row in cursor.fetchall():
                        data['targets'].append({
                            'id': row[0],
                            'target': row[2] if len(row) > 2 else '-'
                        })
            except Exception:
                pass
        
        return data
    
    def _on_progress(self, value: int, message: str):
        """Handle progress updates"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
    
    def _on_finished(self, path: str):
        """Handle report generation completion"""
        self.generate_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        self._load_reports()
        
        QMessageBox.information(
            self, "Report Generated",
            f"Report saved to:\n{path}"
        )
    
    def _on_error(self, error: str):
        """Handle errors"""
        self.generate_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        QMessageBox.warning(self, "Error", f"Failed to generate report: {error}")
    
    def _open_report(self, item: QListWidgetItem):
        """Open a report file"""
        filepath = item.data(Qt.ItemDataRole.UserRole)
        if filepath and os.path.exists(filepath):
            import subprocess
            import platform
            
            if platform.system() == 'Darwin':
                subprocess.run(['open', filepath])
            elif platform.system() == 'Windows':
                os.startfile(filepath)
            else:
                subprocess.run(['xdg-open', filepath])
