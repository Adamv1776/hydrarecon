#!/usr/bin/env python3
"""
Email Security Analyzer GUI Page
SPF, DKIM, DMARC validation and spoofing assessment.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QGroupBox, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QProgressBar, QHeaderView, QFrame, QMessageBox,
    QTabWidget, QGridLayout, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor


class EmailScanWorker(QThread):
    """Worker thread for email security scanning."""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
    
    def run(self):
        import asyncio
        from core.email_security import EmailSecurityAnalyzer
        
        async def scan():
            analyzer = EmailSecurityAnalyzer()
            report = await analyzer.full_analysis(self.domain)
            
            # Convert to dict for signal
            return {
                'domain': report.domain,
                'score': report.overall_score,
                'security_level': report.security_level.value,
                'spoofing_possible': report.spoofing_possible,
                'spoofing_risk': report.spoofing_risk,
                'mx_records': report.mx_records,
                'spf': {
                    'exists': report.spf is not None,
                    'raw': report.spf.raw if report.spf else None,
                    'all_qualifier': report.spf.all_qualifier if report.spf else None,
                    'includes': report.spf.includes if report.spf else [],
                    'lookup_count': report.spf.lookup_count if report.spf else 0,
                    'warnings': report.spf.warnings if report.spf else []
                } if True else None,
                'dkim': {
                    selector: {
                        'selector': d.selector,
                        'key_type': d.key_type,
                        'key_length': d.key_length,
                        'is_valid': d.is_valid
                    } for selector, d in report.dkim.items()
                },
                'dmarc': {
                    'exists': report.dmarc is not None,
                    'raw': report.dmarc.raw if report.dmarc else None,
                    'policy': report.dmarc.policy if report.dmarc else None,
                    'pct': report.dmarc.pct if report.dmarc else 0,
                    'rua': report.dmarc.rua if report.dmarc else [],
                    'warnings': report.dmarc.warnings if report.dmarc else []
                } if True else None,
                'mta_sts': report.mta_sts is not None,
                'tls_rpt': report.tls_rpt is not None,
                'bimi': report.bimi is not None,
                'findings': [{
                    'id': f.id,
                    'category': f.category,
                    'severity': f.severity.value,
                    'title': f.title,
                    'description': f.description,
                    'remediation': f.remediation
                } for f in report.findings]
            }
        
        try:
            results = asyncio.run(scan())
            self.finished.emit(results)
        except Exception as e:
            self.finished.emit({'error': str(e)})


class EmailSecurityPage(QWidget):
    """Email Security Analyzer Page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("📧 Email Security Analyzer")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #00b4d8;")
        layout.addWidget(header)
        
        subtitle = QLabel("SPF, DKIM, DMARC validation and email spoofing assessment")
        subtitle.setStyleSheet("color: #888; font-size: 14px;")
        layout.addWidget(subtitle)
        
        # Input section
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain:"))
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.returnPressed.connect(self.start_scan)
        input_layout.addWidget(self.domain_input)
        
        self.scan_btn = QPushButton("🔍 Analyze")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #00b4d8;
                color: white;
                border: none;
                padding: 10px 30px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00c4e8;
            }
        """)
        self.scan_btn.clicked.connect(self.start_scan)
        input_layout.addWidget(self.scan_btn)
        
        layout.addLayout(input_layout)
        
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
                background: #00b4d8;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Score display
        score_layout = QHBoxLayout()
        
        # Overall score card
        self.score_card = self.create_score_card()
        score_layout.addWidget(self.score_card)
        
        # Spoofing risk card
        self.spoof_card = self.create_spoof_card()
        score_layout.addWidget(self.spoof_card)
        
        layout.addLayout(score_layout)
        
        # Protocol status cards
        protocol_layout = QHBoxLayout()
        
        self.spf_card = self.create_protocol_card("SPF", "—")
        self.dkim_card = self.create_protocol_card("DKIM", "—")
        self.dmarc_card = self.create_protocol_card("DMARC", "—")
        self.mta_sts_card = self.create_protocol_card("MTA-STS", "—")
        self.tls_rpt_card = self.create_protocol_card("TLS-RPT", "—")
        self.bimi_card = self.create_protocol_card("BIMI", "—")
        
        protocol_layout.addWidget(self.spf_card)
        protocol_layout.addWidget(self.dkim_card)
        protocol_layout.addWidget(self.dmarc_card)
        protocol_layout.addWidget(self.mta_sts_card)
        protocol_layout.addWidget(self.tls_rpt_card)
        protocol_layout.addWidget(self.bimi_card)
        
        layout.addLayout(protocol_layout)
        
        # Details tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                border-radius: 8px;
                background: #1a1a2e;
            }
            QTabBar::tab {
                background: #252540;
                color: #888;
                padding: 8px 16px;
            }
            QTabBar::tab:selected {
                background: #1a1a2e;
                color: #00b4d8;
            }
        """)
        
        # SPF Tab
        self.spf_details = QPlainTextEdit()
        self.spf_details.setReadOnly(True)
        self.spf_details.setStyleSheet("font-family: 'Consolas', monospace;")
        self.tabs.addTab(self.spf_details, "📋 SPF")
        
        # DKIM Tab
        self.dkim_details = QPlainTextEdit()
        self.dkim_details.setReadOnly(True)
        self.dkim_details.setStyleSheet("font-family: 'Consolas', monospace;")
        self.tabs.addTab(self.dkim_details, "🔑 DKIM")
        
        # DMARC Tab
        self.dmarc_details = QPlainTextEdit()
        self.dmarc_details.setReadOnly(True)
        self.dmarc_details.setStyleSheet("font-family: 'Consolas', monospace;")
        self.tabs.addTab(self.dmarc_details, "🛡️ DMARC")
        
        # MX Records Tab
        self.mx_details = QPlainTextEdit()
        self.mx_details.setReadOnly(True)
        self.mx_details.setStyleSheet("font-family: 'Consolas', monospace;")
        self.tabs.addTab(self.mx_details, "📬 MX Records")
        
        # Findings Tab
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels([
            "Severity", "Category", "Issue", "Remediation"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.findings_table.setStyleSheet("""
            QTableWidget {
                background: #1e1e2e;
                gridline-color: #333;
                border: none;
            }
        """)
        self.tabs.addTab(self.findings_table, "⚠️ Findings")
        
        layout.addWidget(self.tabs)
        
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
    
    def create_score_card(self):
        """Create the main score card."""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 2px solid #333;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        card.setMinimumWidth(200)
        
        layout = QVBoxLayout(card)
        
        title = QLabel("Security Score")
        title.setStyleSheet("color: #888; font-size: 14px;")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.score_label = QLabel("—")
        self.score_label.setStyleSheet("font-size: 48px; font-weight: bold; color: #888;")
        layout.addWidget(self.score_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.level_label = QLabel("Not Scanned")
        self.level_label.setStyleSheet("color: #888; font-size: 16px;")
        layout.addWidget(self.level_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        return card
    
    def create_spoof_card(self):
        """Create the spoofing risk card."""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 2px solid #333;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        card.setMinimumWidth(300)
        
        layout = QVBoxLayout(card)
        
        title = QLabel("📧 Spoofing Risk")
        title.setStyleSheet("color: #888; font-size: 14px;")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.spoof_label = QLabel("—")
        self.spoof_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #888;")
        self.spoof_label.setWordWrap(True)
        layout.addWidget(self.spoof_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        return card
    
    def create_protocol_card(self, name, status):
        """Create a protocol status card."""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(5)
        
        name_label = QLabel(name)
        name_label.setStyleSheet("color: #888; font-size: 12px; font-weight: bold;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        status_label = QLabel(status)
        status_label.setStyleSheet("font-size: 18px; color: #888;")
        status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_label.setObjectName("status")
        layout.addWidget(status_label)
        
        return card
    
    def update_protocol_card(self, card, exists, extra_info=""):
        """Update protocol card status."""
        label = card.findChild(QLabel, "status")
        if label:
            if exists:
                label.setText("✅")
                label.setStyleSheet("font-size: 18px; color: #00ff88;")
            else:
                label.setText("❌")
                label.setStyleSheet("font-size: 18px; color: #ff4444;")
    
    def start_scan(self):
        """Start email security scan."""
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Error", "Please enter a domain")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.scan_btn.setEnabled(False)
        
        self.worker = EmailScanWorker(domain)
        self.worker.finished.connect(self.scan_complete)
        self.worker.start()
    
    def scan_complete(self, results):
        """Handle scan completion."""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        
        if 'error' in results:
            QMessageBox.critical(self, "Scan Error", results['error'])
            return
        
        self.scan_results = results
        
        # Update score
        score = results.get('score', 0)
        self.score_label.setText(f"{score}")
        
        level = results.get('security_level', 'Unknown')
        level_colors = {
            'Excellent': '#00ff88',
            'Good': '#44cc44',
            'Moderate': '#ffcc00',
            'Weak': '#ff8844',
            'Critical': '#ff4444'
        }
        color = level_colors.get(level, '#888')
        self.score_label.setStyleSheet(f"font-size: 48px; font-weight: bold; color: {color};")
        self.level_label.setText(level)
        self.level_label.setStyleSheet(f"color: {color}; font-size: 16px;")
        
        # Update spoofing risk
        spoof_risk = results.get('spoofing_risk', 'Unknown')
        spoof_possible = results.get('spoofing_possible', True)
        spoof_color = '#ff4444' if spoof_possible else '#00ff88'
        self.spoof_label.setText(spoof_risk)
        self.spoof_label.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {spoof_color};")
        
        # Update protocol cards
        spf = results.get('spf', {})
        self.update_protocol_card(self.spf_card, spf.get('exists', False))
        
        dkim = results.get('dkim', {})
        self.update_protocol_card(self.dkim_card, len(dkim) > 0)
        
        dmarc = results.get('dmarc', {})
        self.update_protocol_card(self.dmarc_card, dmarc.get('exists', False))
        
        self.update_protocol_card(self.mta_sts_card, results.get('mta_sts', False))
        self.update_protocol_card(self.tls_rpt_card, results.get('tls_rpt', False))
        self.update_protocol_card(self.bimi_card, results.get('bimi', False))
        
        # Update SPF details
        if spf.get('exists'):
            spf_text = f"""╔══════════════════════════════════════════════════════════════╗
║  SPF RECORD
╚══════════════════════════════════════════════════════════════╝

📝 RAW RECORD:
{spf.get('raw', 'N/A')}

🎯 ALL QUALIFIER: {spf.get('all_qualifier', 'N/A')}
📊 DNS LOOKUPS: {spf.get('lookup_count', 0)}/10

📦 INCLUDES:
{chr(10).join('  • ' + inc for inc in spf.get('includes', [])) or '  None'}

⚠️  WARNINGS:
{chr(10).join('  ⚠ ' + w for w in spf.get('warnings', [])) or '  None'}
"""
        else:
            spf_text = "❌ NO SPF RECORD FOUND\n\nThis domain does not have an SPF record, making it easier to spoof emails."
        
        self.spf_details.setPlainText(spf_text)
        
        # Update DKIM details
        if dkim:
            dkim_text = "╔══════════════════════════════════════════════════════════════╗\n"
            dkim_text += "║  DKIM RECORDS\n"
            dkim_text += "╚══════════════════════════════════════════════════════════════╝\n\n"
            
            for selector, info in dkim.items():
                dkim_text += f"🔑 SELECTOR: {selector}\n"
                dkim_text += f"   Key Type: {info.get('key_type', 'rsa')}\n"
                dkim_text += f"   Key Length: ~{info.get('key_length', 0)} bits\n"
                dkim_text += f"   Valid: {'✅' if info.get('is_valid') else '❌'}\n\n"
        else:
            dkim_text = "❌ NO DKIM RECORDS FOUND\n\nNo DKIM selectors were found for common email providers."
        
        self.dkim_details.setPlainText(dkim_text)
        
        # Update DMARC details
        if dmarc.get('exists'):
            dmarc_text = f"""╔══════════════════════════════════════════════════════════════╗
║  DMARC RECORD
╚══════════════════════════════════════════════════════════════╝

📝 RAW RECORD:
{dmarc.get('raw', 'N/A')}

🛡️  POLICY: {dmarc.get('policy', 'none')}
📊 PERCENTAGE: {dmarc.get('pct', 100)}%

📬 AGGREGATE REPORTS (rua):
{chr(10).join('  • ' + uri for uri in dmarc.get('rua', [])) or '  None configured'}

⚠️  WARNINGS:
{chr(10).join('  ⚠ ' + w for w in dmarc.get('warnings', [])) or '  None'}
"""
        else:
            dmarc_text = "❌ NO DMARC RECORD FOUND\n\nWithout DMARC, there's no policy for handling failed SPF/DKIM checks."
        
        self.dmarc_details.setPlainText(dmarc_text)
        
        # Update MX details
        mx_records = results.get('mx_records', [])
        if mx_records:
            mx_text = "╔══════════════════════════════════════════════════════════════╗\n"
            mx_text += "║  MX RECORDS\n"
            mx_text += "╚══════════════════════════════════════════════════════════════╝\n\n"
            for mx in mx_records:
                mx_text += f"📬 {mx}\n"
        else:
            mx_text = "❌ NO MX RECORDS FOUND"
        
        self.mx_details.setPlainText(mx_text)
        
        # Update findings
        self.findings_table.setRowCount(0)
        for finding in results.get('findings', []):
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            
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
            
            self.findings_table.setItem(row, 0, severity_item)
            self.findings_table.setItem(row, 1, QTableWidgetItem(finding['category']))
            self.findings_table.setItem(row, 2, QTableWidgetItem(finding['title']))
            self.findings_table.setItem(row, 3, QTableWidgetItem(finding['remediation'][:100]))
    
    def export_results(self, format):
        """Export results to file."""
        if not self.scan_results:
            QMessageBox.information(self, "No Data", "No scan results to export")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        if format == "json":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export JSON", "email_security.json", "JSON Files (*.json)"
            )
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
        
        elif format == "markdown":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Markdown", "email_security.md", "Markdown Files (*.md)"
            )
            if file_path:
                results = self.scan_results
                md = f"# Email Security Report for {results.get('domain', '')}\n\n"
                md += f"**Score:** {results.get('score', 0)}/100\n"
                md += f"**Level:** {results.get('security_level', '')}\n"
                md += f"**Spoofing Risk:** {results.get('spoofing_risk', '')}\n\n"
                
                md += "## Findings\n\n"
                for finding in results.get('findings', []):
                    md += f"### {finding['title']}\n"
                    md += f"- **Severity:** {finding['severity']}\n"
                    md += f"- **Category:** {finding['category']}\n"
                    md += f"- **Remediation:** {finding['remediation']}\n\n"
                
                with open(file_path, 'w') as f:
                    f.write(md)
