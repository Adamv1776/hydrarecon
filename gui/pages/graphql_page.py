#!/usr/bin/env python3
"""
GraphQL Security Scanner GUI Page
Specialized security testing for GraphQL APIs.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QGroupBox, QTableWidget, QTableWidgetItem,
    QTabWidget, QPlainTextEdit, QSplitter, QProgressBar, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QFrame, QMessageBox, QComboBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor


class GraphQLScanWorker(QThread):
    """Worker thread for GraphQL scanning."""
    progress = pyqtSignal(str)
    finding = pyqtSignal(dict)
    schema = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    
    def __init__(self, endpoint, headers=None):
        super().__init__()
        self.endpoint = endpoint
        self.headers = headers or {}
    
    def run(self):
        import asyncio
        from core.graphql_scanner import GraphQLScanner
        
        async def scan():
            scanner = GraphQLScanner()
            results = await scanner.full_scan(self.endpoint, self.headers)
            return results
        
        try:
            results = asyncio.run(scan())
            self.finished.emit(results)
        except Exception as e:
            self.finished.emit({'error': str(e)})


class GraphQLPage(QWidget):
    """GraphQL Security Scanner Page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🔗 GraphQL Security Scanner")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #e535ab;")
        layout.addWidget(header)
        
        subtitle = QLabel("Introspection, injection testing, DoS checks, and schema analysis")
        subtitle.setStyleSheet("color: #888; font-size: 14px;")
        layout.addWidget(subtitle)
        
        # Input section
        input_group = QGroupBox("🎯 Target Configuration")
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
                color: #e535ab;
            }
        """)
        input_layout = QVBoxLayout(input_group)
        
        # Endpoint
        endpoint_layout = QHBoxLayout()
        endpoint_layout.addWidget(QLabel("Endpoint:"))
        self.endpoint_input = QLineEdit()
        self.endpoint_input.setPlaceholderText("https://api.example.com/graphql")
        endpoint_layout.addWidget(self.endpoint_input)
        input_layout.addLayout(endpoint_layout)
        
        # Headers
        headers_layout = QHBoxLayout()
        headers_layout.addWidget(QLabel("Auth Header:"))
        self.auth_type = QComboBox()
        self.auth_type.addItems(["Bearer Token", "API Key", "Basic Auth", "Custom"])
        headers_layout.addWidget(self.auth_type)
        
        self.auth_value = QLineEdit()
        self.auth_value.setPlaceholderText("Token or credentials...")
        self.auth_value.setEchoMode(QLineEdit.EchoMode.Password)
        headers_layout.addWidget(self.auth_value)
        input_layout.addLayout(headers_layout)
        
        # Scan button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.scan_btn = QPushButton("🔍 Scan GraphQL API")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #e535ab;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #ff45bb;
            }
        """)
        self.scan_btn.clicked.connect(self.start_scan)
        btn_layout.addWidget(self.scan_btn)
        
        input_layout.addLayout(btn_layout)
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
                background: #e535ab;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.introspection_card = self.create_stat_card("Introspection", "—", "#e535ab")
        self.vuln_card = self.create_stat_card("Vulnerabilities", "0", "#ff4444")
        self.queries_card = self.create_stat_card("Queries", "0", "#00d4ff")
        self.mutations_card = self.create_stat_card("Mutations", "0", "#ff8844")
        self.types_card = self.create_stat_card("Types", "0", "#44cc44")
        
        stats_layout.addWidget(self.introspection_card)
        stats_layout.addWidget(self.vuln_card)
        stats_layout.addWidget(self.queries_card)
        stats_layout.addWidget(self.mutations_card)
        stats_layout.addWidget(self.types_card)
        
        layout.addLayout(stats_layout)
        
        # Splitter for results
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Findings
        findings_group = QGroupBox("⚠️ Security Findings")
        findings_group.setStyleSheet(input_group.styleSheet())
        findings_layout = QVBoxLayout(findings_group)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels([
            "Severity", "Type", "Title", "CVSS"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.itemClicked.connect(self.show_finding_details)
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
        
        # Right: Schema/Details
        right_panel = QTabWidget()
        right_panel.setStyleSheet("""
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
                color: #e535ab;
            }
        """)
        
        # Schema tree
        self.schema_tree = QTreeWidget()
        self.schema_tree.setHeaderLabels(["Name", "Type", "Details"])
        self.schema_tree.setStyleSheet("""
            QTreeWidget {
                background: #1e1e2e;
                border: none;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        right_panel.addTab(self.schema_tree, "📊 Schema")
        
        # Finding details
        self.finding_details = QPlainTextEdit()
        self.finding_details.setReadOnly(True)
        self.finding_details.setStyleSheet("font-family: 'Consolas', monospace;")
        right_panel.addTab(self.finding_details, "📋 Details")
        
        # Sensitive fields
        self.sensitive_tree = QTreeWidget()
        self.sensitive_tree.setHeaderLabels(["Type", "Field", "Pattern"])
        self.sensitive_tree.setStyleSheet(self.schema_tree.styleSheet())
        right_panel.addTab(self.sensitive_tree, "🔒 Sensitive Fields")
        
        # Dangerous mutations
        self.dangerous_list = QTreeWidget()
        self.dangerous_list.setHeaderLabels(["Mutation", "Risk", "Arguments"])
        self.dangerous_list.setStyleSheet(self.schema_tree.styleSheet())
        right_panel.addTab(self.dangerous_list, "⚡ Dangerous Mutations")
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 500])
        
        layout.addWidget(splitter)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json = QPushButton("📦 Export JSON")
        export_json.clicked.connect(self.export_json)
        export_layout.addWidget(export_json)
        
        export_md = QPushButton("📄 Export Markdown")
        export_md.clicked.connect(self.export_markdown)
        export_layout.addWidget(export_md)
        
        export_layout.addStretch()
        layout.addLayout(export_layout)
        
        # Store results
        self.scan_results = {}
    
    def create_stat_card(self, title, value, color):
        """Create a statistics card."""
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
        value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        value_label.setObjectName("value")
        card_layout.addWidget(value_label)
        
        return card
    
    def update_stat_card(self, card, value):
        """Update stat card value."""
        label = card.findChild(QLabel, "value")
        if label:
            label.setText(str(value))
    
    def start_scan(self):
        """Start GraphQL scan."""
        endpoint = self.endpoint_input.text()
        if not endpoint:
            QMessageBox.warning(self, "Error", "Please enter a GraphQL endpoint")
            return
        
        # Build headers
        headers = {}
        auth_type = self.auth_type.currentText()
        auth_value = self.auth_value.text()
        
        if auth_value:
            if auth_type == "Bearer Token":
                headers["Authorization"] = f"Bearer {auth_value}"
            elif auth_type == "API Key":
                headers["X-API-Key"] = auth_value
            elif auth_type == "Basic Auth":
                import base64
                encoded = base64.b64encode(auth_value.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
            elif auth_type == "Custom":
                headers["Authorization"] = auth_value
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.scan_btn.setEnabled(False)
        
        # Clear previous results
        self.findings_table.setRowCount(0)
        self.schema_tree.clear()
        self.sensitive_tree.clear()
        self.dangerous_list.clear()
        
        self.worker = GraphQLScanWorker(endpoint, headers)
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
        
        # Update stats
        self.update_stat_card(
            self.introspection_card, 
            "✅ Enabled" if results.get('schema_extracted') else "❌ Disabled"
        )
        
        summary = results.get('summary', {})
        self.update_stat_card(self.vuln_card, summary.get('total_findings', 0))
        
        schema_stats = results.get('schema_stats', {})
        self.update_stat_card(self.queries_card, schema_stats.get('queries', 0))
        self.update_stat_card(self.mutations_card, schema_stats.get('mutations', 0))
        self.update_stat_card(self.types_card, schema_stats.get('types', 0))
        
        # Populate findings
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
            self.findings_table.setItem(row, 1, QTableWidgetItem(finding['type']))
            self.findings_table.setItem(row, 2, QTableWidgetItem(finding['title']))
            self.findings_table.setItem(row, 3, QTableWidgetItem(str(finding.get('cvss_score', 0))))
        
        # Populate sensitive fields
        for field in results.get('sensitive_fields', []):
            item = QTreeWidgetItem([
                field['type'],
                field['field'],
                field['pattern_matched']
            ])
            self.sensitive_tree.addTopLevelItem(item)
        
        # Populate dangerous mutations
        for mutation in results.get('dangerous_mutations', []):
            item = QTreeWidgetItem([
                mutation['mutation'],
                mutation['risk'],
                ', '.join(mutation.get('args', []))
            ])
            self.dangerous_list.addTopLevelItem(item)
    
    def show_finding_details(self, item):
        """Show details for selected finding."""
        row = item.row()
        if row < len(self.scan_results.get('findings', [])):
            finding = self.scan_results['findings'][row]
            
            details = f"""╔══════════════════════════════════════════════════════════════╗
║  {finding['title']}
╚══════════════════════════════════════════════════════════════╝

📊 SEVERITY: {finding['severity']}
📈 CVSS SCORE: {finding.get('cvss_score', 'N/A')}
🏷️  TYPE: {finding['type']}

📝 DESCRIPTION:
{finding['description']}

🔧 REMEDIATION:
{finding.get('remediation', 'N/A')}
"""
            self.finding_details.setPlainText(details)
    
    def export_json(self):
        """Export results as JSON."""
        if not self.scan_results:
            QMessageBox.information(self, "No Data", "No scan results to export")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "graphql_scan.json", "JSON Files (*.json)"
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
    
    def export_markdown(self):
        """Export results as Markdown."""
        if not self.scan_results:
            QMessageBox.information(self, "No Data", "No scan results to export")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Markdown", "graphql_scan.md", "Markdown Files (*.md)"
        )
        
        if file_path:
            md = f"# GraphQL Security Scan Report\n\n"
            md += f"**Endpoint:** `{self.endpoint_input.text()}`\n\n"
            
            md += "## Findings\n\n"
            for finding in self.scan_results.get('findings', []):
                md += f"### {finding['title']}\n"
                md += f"- **Severity:** {finding['severity']}\n"
                md += f"- **Type:** {finding['type']}\n"
                md += f"- **CVSS:** {finding.get('cvss_score', 'N/A')}\n\n"
            
            with open(file_path, 'w') as f:
                f.write(md)
