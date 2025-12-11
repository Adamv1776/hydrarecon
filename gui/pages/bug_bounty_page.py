#!/usr/bin/env python3
"""
Bug Bounty Copilot GUI Page
AI-powered bug bounty report generation.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QComboBox, QLineEdit, QGroupBox, QFormLayout,
    QSpinBox, QTabWidget, QPlainTextEdit, QSplitter, QFrame,
    QScrollArea, QGridLayout, QCheckBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class BugBountyCopilotPage(QWidget):
    """AI Bug Bounty Report Generator."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🎯 AI Bug Bounty Copilot")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff;")
        layout.addWidget(header)
        
        subtitle = QLabel("Auto-generate professional bug bounty reports with CVSS scoring")
        subtitle.setStyleSheet("color: #888; font-size: 14px;")
        layout.addWidget(subtitle)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Input
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Vulnerability Details Group
        vuln_group = QGroupBox("📋 Vulnerability Details")
        vuln_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: #1a1a2e;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #00d4ff;
            }
        """)
        vuln_layout = QFormLayout(vuln_group)
        
        # Target
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., example.com")
        vuln_layout.addRow("Target:", self.target_input)
        
        # Endpoint
        self.endpoint_input = QLineEdit()
        self.endpoint_input.setPlaceholderText("e.g., /api/users")
        vuln_layout.addRow("Endpoint:", self.endpoint_input)
        
        # Parameter
        self.param_input = QLineEdit()
        self.param_input.setPlaceholderText("e.g., id, search, query")
        vuln_layout.addRow("Parameter:", self.param_input)
        
        # Vulnerability Type
        self.vuln_type = QComboBox()
        self.vuln_type.addItems([
            "Cross-Site Scripting (Reflected)",
            "Cross-Site Scripting (Stored)",
            "Cross-Site Scripting (DOM-based)",
            "SQL Injection",
            "Blind SQL Injection",
            "Server-Side Request Forgery",
            "Insecure Direct Object Reference",
            "Remote Code Execution",
            "Local File Inclusion",
            "Remote File Inclusion",
            "Open Redirect",
            "CSRF",
            "CORS Misconfiguration",
            "Subdomain Takeover",
            "Secrets/Credentials Leak",
            "GraphQL Vulnerability",
            "JWT Implementation Weakness",
            "Server-Side Template Injection",
            "Path Traversal",
            "Command Injection",
            "Business Logic Flaw",
            "Other"
        ])
        vuln_layout.addRow("Vuln Type:", self.vuln_type)
        
        left_layout.addWidget(vuln_group)
        
        # Description Group
        desc_group = QGroupBox("📝 Description")
        desc_group.setStyleSheet(vuln_group.styleSheet())
        desc_layout = QVBoxLayout(desc_group)
        
        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText("Describe the vulnerability in detail...\n\nExample:\nA reflected XSS vulnerability exists in the search functionality. User input is reflected in the response without proper sanitization...")
        self.description_input.setMaximumHeight(150)
        desc_layout.addWidget(self.description_input)
        
        left_layout.addWidget(desc_group)
        
        # PoC Group
        poc_group = QGroupBox("🔧 Proof of Concept")
        poc_group.setStyleSheet(vuln_group.styleSheet())
        poc_layout = QVBoxLayout(poc_group)
        
        poc_type_layout = QHBoxLayout()
        poc_type_layout.addWidget(QLabel("PoC Type:"))
        self.poc_type = QComboBox()
        self.poc_type.addItems(["cURL", "Python", "Browser", "Burp Suite"])
        poc_type_layout.addWidget(self.poc_type)
        poc_type_layout.addStretch()
        poc_layout.addLayout(poc_type_layout)
        
        self.poc_input = QPlainTextEdit()
        self.poc_input.setPlaceholderText("curl -X GET 'https://example.com/search?q=<script>alert(1)</script>'")
        self.poc_input.setMaximumHeight(120)
        poc_layout.addWidget(self.poc_input)
        
        left_layout.addWidget(poc_group)
        
        # CVSS Group
        cvss_group = QGroupBox("📊 CVSS 3.1 Calculator")
        cvss_group.setStyleSheet(vuln_group.styleSheet())
        cvss_layout = QGridLayout(cvss_group)
        
        # Attack Vector
        cvss_layout.addWidget(QLabel("Attack Vector:"), 0, 0)
        self.cvss_av = QComboBox()
        self.cvss_av.addItems(["Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"])
        cvss_layout.addWidget(self.cvss_av, 0, 1)
        
        # Attack Complexity
        cvss_layout.addWidget(QLabel("Complexity:"), 0, 2)
        self.cvss_ac = QComboBox()
        self.cvss_ac.addItems(["Low (L)", "High (H)"])
        cvss_layout.addWidget(self.cvss_ac, 0, 3)
        
        # Privileges Required
        cvss_layout.addWidget(QLabel("Privileges:"), 1, 0)
        self.cvss_pr = QComboBox()
        self.cvss_pr.addItems(["None (N)", "Low (L)", "High (H)"])
        cvss_layout.addWidget(self.cvss_pr, 1, 1)
        
        # User Interaction
        cvss_layout.addWidget(QLabel("User Interaction:"), 1, 2)
        self.cvss_ui = QComboBox()
        self.cvss_ui.addItems(["None (N)", "Required (R)"])
        cvss_layout.addWidget(self.cvss_ui, 1, 3)
        
        # Scope
        cvss_layout.addWidget(QLabel("Scope:"), 2, 0)
        self.cvss_s = QComboBox()
        self.cvss_s.addItems(["Unchanged (U)", "Changed (C)"])
        cvss_layout.addWidget(self.cvss_s, 2, 1)
        
        # CIA
        cvss_layout.addWidget(QLabel("Confidentiality:"), 3, 0)
        self.cvss_c = QComboBox()
        self.cvss_c.addItems(["None (N)", "Low (L)", "High (H)"])
        cvss_layout.addWidget(self.cvss_c, 3, 1)
        
        cvss_layout.addWidget(QLabel("Integrity:"), 3, 2)
        self.cvss_i = QComboBox()
        self.cvss_i.addItems(["None (N)", "Low (L)", "High (H)"])
        cvss_layout.addWidget(self.cvss_i, 3, 3)
        
        cvss_layout.addWidget(QLabel("Availability:"), 4, 0)
        self.cvss_a = QComboBox()
        self.cvss_a.addItems(["None (N)", "Low (L)", "High (H)"])
        cvss_layout.addWidget(self.cvss_a, 4, 1)
        
        # CVSS Score display
        self.cvss_score = QLabel("Score: 0.0")
        self.cvss_score.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff88;")
        cvss_layout.addWidget(self.cvss_score, 4, 2, 1, 2)
        
        left_layout.addWidget(cvss_group)
        
        # Generate Button
        self.generate_btn = QPushButton("🚀 Generate Report")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #0099cc);
                color: white;
                border: none;
                padding: 15px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00e5ff, stop:1 #00aadd);
            }
        """)
        self.generate_btn.clicked.connect(self.generate_report)
        left_layout.addWidget(self.generate_btn)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right panel - Output
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Output tabs
        self.output_tabs = QTabWidget()
        self.output_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                border-radius: 8px;
                background: #1a1a2e;
            }
            QTabBar::tab {
                background: #252540;
                color: #888;
                padding: 8px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #1a1a2e;
                color: #00d4ff;
            }
        """)
        
        # Markdown tab
        self.markdown_output = QPlainTextEdit()
        self.markdown_output.setReadOnly(True)
        self.markdown_output.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.output_tabs.addTab(self.markdown_output, "📄 Markdown")
        
        # HackerOne tab
        self.h1_output = QPlainTextEdit()
        self.h1_output.setReadOnly(True)
        self.h1_output.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.output_tabs.addTab(self.h1_output, "🔴 HackerOne")
        
        # Bugcrowd tab
        self.bc_output = QPlainTextEdit()
        self.bc_output.setReadOnly(True)
        self.bc_output.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.output_tabs.addTab(self.bc_output, "🟠 Bugcrowd")
        
        # JSON tab
        self.json_output = QPlainTextEdit()
        self.json_output.setReadOnly(True)
        self.json_output.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.output_tabs.addTab(self.json_output, "📦 JSON")
        
        right_layout.addWidget(self.output_tabs)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        export_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("💾 Save Report")
        save_btn.clicked.connect(self.save_report)
        export_layout.addWidget(save_btn)
        
        right_layout.addLayout(export_layout)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([500, 600])
        
        layout.addWidget(splitter)
        
        # Connect CVSS changes to score calculation
        for combo in [self.cvss_av, self.cvss_ac, self.cvss_pr, self.cvss_ui,
                      self.cvss_s, self.cvss_c, self.cvss_i, self.cvss_a]:
            combo.currentIndexChanged.connect(self.calculate_cvss)
    
    def calculate_cvss(self):
        """Calculate CVSS score based on selections."""
        # Simplified CVSS calculation
        av_weights = {"Network (N)": 0.85, "Adjacent (A)": 0.62, "Local (L)": 0.55, "Physical (P)": 0.2}
        ac_weights = {"Low (L)": 0.77, "High (H)": 0.44}
        pr_weights = {"None (N)": 0.85, "Low (L)": 0.62, "High (H)": 0.27}
        ui_weights = {"None (N)": 0.85, "Required (R)": 0.62}
        cia_weights = {"None (N)": 0, "Low (L)": 0.22, "High (H)": 0.56}
        
        av = av_weights.get(self.cvss_av.currentText(), 0.85)
        ac = ac_weights.get(self.cvss_ac.currentText(), 0.77)
        pr = pr_weights.get(self.cvss_pr.currentText(), 0.85)
        ui = ui_weights.get(self.cvss_ui.currentText(), 0.85)
        
        c = cia_weights.get(self.cvss_c.currentText(), 0)
        i = cia_weights.get(self.cvss_i.currentText(), 0)
        a = cia_weights.get(self.cvss_a.currentText(), 0)
        
        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui
        
        # Impact
        isc = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if self.cvss_s.currentText() == "Unchanged (U)":
            impact = 6.42 * isc
        else:
            impact = 7.52 * (isc - 0.029) - 3.25 * pow(isc - 0.02, 15)
        
        if impact <= 0:
            score = 0.0
        elif self.cvss_s.currentText() == "Unchanged (U)":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)
        
        score = round(score, 1)
        
        # Color based on severity
        if score >= 9.0:
            color = "#ff4444"
            severity = "CRITICAL"
        elif score >= 7.0:
            color = "#ff8844"
            severity = "HIGH"
        elif score >= 4.0:
            color = "#ffcc00"
            severity = "MEDIUM"
        elif score >= 0.1:
            color = "#44cc44"
            severity = "LOW"
        else:
            color = "#888888"
            severity = "NONE"
        
        self.cvss_score.setText(f"Score: {score} ({severity})")
        self.cvss_score.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {color};")
    
    def generate_report(self):
        """Generate bug bounty report."""
        target = self.target_input.text() or "example.com"
        endpoint = self.endpoint_input.text() or "/"
        param = self.param_input.text()
        vuln_type = self.vuln_type.currentText()
        description = self.description_input.toPlainText()
        poc = self.poc_input.toPlainText()
        
        # Get CVSS
        score_text = self.cvss_score.text()
        score = float(score_text.split(":")[1].split("(")[0].strip())
        severity = score_text.split("(")[1].replace(")", "")
        
        # Generate markdown report
        markdown = f"""# {vuln_type} in {endpoint} on {target}

## Summary
| Field | Value |
|-------|-------|
| **Target** | {target} |
| **Endpoint** | `{endpoint}` |
| **Parameter** | `{param or 'N/A'}` |
| **Severity** | {severity} |
| **CVSS Score** | {score} |

## Description
{description or 'A vulnerability was discovered that allows...'}

## Steps to Reproduce
1. Navigate to {target}
2. Access the endpoint {endpoint}
3. Inject payload in the {param or 'input'} parameter
4. Observe the vulnerability trigger

## Proof of Concept
```
{poc or 'curl example...'}
```

## Impact
This vulnerability could allow an attacker to...

## Remediation
1. Implement proper input validation
2. Use output encoding
3. Apply security headers

---
*Generated by HydraRecon Bug Bounty Copilot*
"""
        
        self.markdown_output.setPlainText(markdown)
        
        # HackerOne format
        h1 = f"""## Summary:
{description or 'A vulnerability was discovered...'}

## Steps To Reproduce:
1. Navigate to {target}
2. Access {endpoint}
3. Submit payload
4. Observe the result

## Supporting Material/References:
```
{poc or 'PoC code here'}
```

## Impact
This vulnerability allows...

CVSS: {score}
"""
        self.h1_output.setPlainText(h1)
        
        # Bugcrowd format
        bc = f"""### Title
{vuln_type} in {endpoint} on {target}

### Vulnerability Details
**Type:** {vuln_type}
**Severity:** {severity}
**CVSS:** {score}

### Description
{description or 'Description here'}

### Proof of Concept
```
{poc or 'PoC code'}
```

### Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

### Remediation
Implement proper security controls.
"""
        self.bc_output.setPlainText(bc)
        
        # JSON format
        import json
        json_data = {
            "title": f"{vuln_type} in {endpoint}",
            "target": target,
            "endpoint": endpoint,
            "parameter": param,
            "vulnerability_type": vuln_type,
            "severity": severity,
            "cvss_score": score,
            "description": description,
            "poc": poc,
            "generated_at": datetime.now().isoformat()
        }
        self.json_output.setPlainText(json.dumps(json_data, indent=2))
    
    def copy_to_clipboard(self):
        """Copy current tab content to clipboard."""
        from PyQt6.QtWidgets import QApplication
        current_widget = self.output_tabs.currentWidget()
        if isinstance(current_widget, QPlainTextEdit):
            QApplication.clipboard().setText(current_widget.toPlainText())
    
    def save_report(self):
        """Save report to file."""
        current_tab = self.output_tabs.currentIndex()
        extensions = {0: "md", 1: "txt", 2: "txt", 3: "json"}
        ext = extensions.get(current_tab, "txt")
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", f"bug_bounty_report.{ext}",
            f"Files (*.{ext});;All Files (*)"
        )
        
        if file_path:
            current_widget = self.output_tabs.currentWidget()
            if isinstance(current_widget, QPlainTextEdit):
                with open(file_path, 'w') as f:
                    f.write(current_widget.toPlainText())
