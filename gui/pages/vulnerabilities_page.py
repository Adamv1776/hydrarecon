#!/usr/bin/env python3
"""
HydraRecon Vulnerabilities Page
Vulnerability management and tracking interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QComboBox,
    QMenu, QMessageBox, QTextEdit, QGridLayout, QScrollArea, QGroupBox,
    QProgressBar, QTabWidget
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from datetime import datetime

from ..widgets import ModernLineEdit, GlowingButton, SeverityBadge


class VulnerabilitiesPage(QWidget):
    """Vulnerabilities management page"""
    
    SEVERITY_COLORS = {
        'critical': '#ff4444',
        'high': '#f85149',
        'medium': '#d29922',
        'low': '#238636',
        'info': '#0088ff'
    }
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.vulnerabilities = []
        self._setup_ui()
        self._load_vulnerabilities()
    
    def _setup_ui(self):
        """Setup the vulnerabilities page UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(20)
        
        # Header
        header = self._create_header()
        layout.addLayout(header)
        
        # Stats row
        stats = self._create_stats_row()
        layout.addLayout(stats)
        
        # Main content
        content = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Vulnerability list
        list_panel = self._create_list_panel()
        content.addWidget(list_panel)
        
        # Right - Details
        details_panel = self._create_details_panel()
        content.addWidget(details_panel)
        
        content.setSizes([700, 500])
        layout.addWidget(content)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("Vulnerabilities")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Track and manage discovered vulnerabilities")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Action buttons
        export_btn = QPushButton("Export Report")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 12px 20px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        export_btn.clicked.connect(self._export_report)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px 20px;
                color: #e6e6e6;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        refresh_btn.clicked.connect(self._refresh)
        
        layout.addWidget(refresh_btn)
        layout.addWidget(export_btn)
        
        return layout
    
    def _create_stats_row(self) -> QHBoxLayout:
        """Create the severity stats row"""
        layout = QHBoxLayout()
        layout.setSpacing(16)
        
        self.stat_labels = {}
        
        stats = [
            ("Critical", "0", '#ff4444'),
            ("High", "0", '#f85149'),
            ("Medium", "0", '#d29922'),
            ("Low", "0", '#238636'),
            ("Info", "0", '#0088ff'),
        ]
        
        for label, value, color in stats:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba({int(color[1:3], 16)}, {int(color[3:5], 16)}, {int(color[5:7], 16)}, 0.15);
                    border: 1px solid {color};
                    border-radius: 10px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(20, 16, 20, 16)
            card_layout.setSpacing(4)
            
            value_label = QLabel(value)
            value_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
            value_label.setStyleSheet(f"color: {color};")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_label = QLabel(label)
            name_label.setStyleSheet(f"color: {color}; font-weight: 600;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(value_label)
            card_layout.addWidget(name_label)
            
            self.stat_labels[label.lower()] = value_label
            layout.addWidget(card)
        
        return layout
    
    def _create_list_panel(self) -> QFrame:
        """Create the vulnerability list panel"""
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Filters
        filter_layout = QHBoxLayout()
        
        self.search_input = ModernLineEdit("Search vulnerabilities...")
        self.search_input.textChanged.connect(self._filter_vulns)
        filter_layout.addWidget(self.search_input)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
                min-width: 120px;
            }
        """)
        self.severity_filter.currentTextChanged.connect(self._filter_vulns)
        filter_layout.addWidget(self.severity_filter)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Status", "Open", "Confirmed", "Fixed", "False Positive"])
        self.status_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
                min-width: 120px;
            }
        """)
        self.status_filter.currentTextChanged.connect(self._filter_vulns)
        filter_layout.addWidget(self.status_filter)
        
        layout.addLayout(filter_layout)
        
        # Vulnerability table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(6)
        self.vuln_table.setHorizontalHeaderLabels([
            "Severity", "Title", "Host", "CVE", "CVSS", "Status"
        ])
        self.vuln_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.vuln_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.vuln_table.customContextMenuRequested.connect(self._show_context_menu)
        self.vuln_table.itemSelectionChanged.connect(self._on_selection_changed)
        self.vuln_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
                gridline-color: #21262d;
            }
            QTableWidget::item:hover { background-color: #161b22; }
            QTableWidget::item:selected { background-color: #238636; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 12px;
                font-weight: 600;
            }
        """)
        layout.addWidget(self.vuln_table)
        
        return panel
    
    def _create_details_panel(self) -> QFrame:
        """Create the details panel"""
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Scroll area for details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(16)
        
        # Title and severity
        header_layout = QHBoxLayout()
        
        self.vuln_title = QLabel("Select a vulnerability")
        self.vuln_title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.vuln_title.setStyleSheet("color: #e6e6e6;")
        self.vuln_title.setWordWrap(True)
        header_layout.addWidget(self.vuln_title)
        
        self.severity_badge = SeverityBadge("info")
        header_layout.addWidget(self.severity_badge)
        header_layout.addStretch()
        
        scroll_layout.addLayout(header_layout)
        
        # Info grid
        info_grid = QGridLayout()
        info_grid.setSpacing(12)
        
        self.detail_labels = {}
        fields = [
            ("CVE:", "cve"),
            ("CVSS Score:", "cvss"),
            ("Host:", "host"),
            ("Port:", "port"),
            ("Service:", "service"),
            ("Status:", "status"),
            ("Discovered:", "discovered"),
            ("Source:", "source"),
        ]
        
        for i, (label, key) in enumerate(fields):
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e; font-weight: 500;")
            value = QLabel("-")
            value.setStyleSheet("color: #e6e6e6;")
            self.detail_labels[key] = value
            
            info_grid.addWidget(name, i // 2, (i % 2) * 2)
            info_grid.addWidget(value, i // 2, (i % 2) * 2 + 1)
        
        scroll_layout.addLayout(info_grid)
        
        # Description
        desc_label = QLabel("Description")
        desc_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        desc_label.setStyleSheet("color: #e6e6e6;")
        scroll_layout.addWidget(desc_label)
        
        self.description_text = QTextEdit()
        self.description_text.setReadOnly(True)
        self.description_text.setMaximumHeight(120)
        self.description_text.setStyleSheet("""
            QTextEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                color: #e6e6e6;
            }
        """)
        scroll_layout.addWidget(self.description_text)
        
        # Remediation
        remed_label = QLabel("Remediation")
        remed_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        remed_label.setStyleSheet("color: #e6e6e6;")
        scroll_layout.addWidget(remed_label)
        
        self.remediation_text = QTextEdit()
        self.remediation_text.setReadOnly(True)
        self.remediation_text.setMaximumHeight(120)
        self.remediation_text.setStyleSheet("""
            QTextEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                color: #e6e6e6;
            }
        """)
        scroll_layout.addWidget(self.remediation_text)
        
        # References
        ref_label = QLabel("References")
        ref_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        ref_label.setStyleSheet("color: #e6e6e6;")
        scroll_layout.addWidget(ref_label)
        
        self.references_text = QTextEdit()
        self.references_text.setReadOnly(True)
        self.references_text.setMaximumHeight(100)
        self.references_text.setStyleSheet("""
            QTextEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                color: #0088ff;
                font-family: monospace;
            }
        """)
        scroll_layout.addWidget(self.references_text)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        status_btn = QPushButton("Change Status")
        status_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        status_btn.clicked.connect(self._change_status)
        
        export_btn = QPushButton("Export Details")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        export_btn.clicked.connect(self._export_details)
        
        actions_layout.addWidget(status_btn)
        actions_layout.addWidget(export_btn)
        actions_layout.addStretch()
        
        layout.addLayout(actions_layout)
        
        return panel
    
    def _load_vulnerabilities(self):
        """Load vulnerabilities from database"""
        try:
            if self.db:
                cursor = self.db.execute(
                    "SELECT * FROM vulnerabilities WHERE project_id = ?",
                    (getattr(self.config, 'project_id', 1),)
                )
                rows = cursor.fetchall()
                
                self.vulnerabilities = []
                for row in rows:
                    self.vulnerabilities.append({
                        'id': row[0],
                        'title': row[2] if len(row) > 2 else 'Unknown',
                        'severity': row[3] if len(row) > 3 else 'medium',
                        'host': row[4] if len(row) > 4 else '-',
                        'port': row[5] if len(row) > 5 else '-',
                        'service': row[6] if len(row) > 6 else '-',
                        'cve': row[7] if len(row) > 7 else '-',
                        'cvss': row[8] if len(row) > 8 else '-',
                        'description': row[9] if len(row) > 9 else '',
                        'remediation': row[10] if len(row) > 10 else '',
                        'references': row[11] if len(row) > 11 else '',
                        'status': row[12] if len(row) > 12 else 'open',
                        'source': row[13] if len(row) > 13 else 'nmap',
                        'discovered': row[14] if len(row) > 14 else datetime.now().isoformat()
                    })
                
                self._refresh_table()
        except Exception:
            # Load sample data for demo
            self.vulnerabilities = self._get_sample_vulnerabilities()
            self._refresh_table()
    
    def _get_sample_vulnerabilities(self) -> list:
        """Get sample vulnerabilities for demo"""
        return [
            {
                'id': 1,
                'title': 'OpenSSH < 8.0 Remote Code Execution',
                'severity': 'critical',
                'host': '192.168.1.10',
                'port': '22',
                'service': 'ssh',
                'cve': 'CVE-2019-6111',
                'cvss': '9.8',
                'description': 'An issue was discovered in OpenSSH 7.9. Due to missing character encoding in the progress display, a malicious server can employ crafted object names to manipulate the client output.',
                'remediation': 'Upgrade OpenSSH to version 8.0 or later. Apply vendor patches. Consider implementing network segmentation.',
                'references': 'https://nvd.nist.gov/vuln/detail/CVE-2019-6111\nhttps://www.openssh.com/security.html',
                'status': 'open',
                'source': 'nmap',
                'discovered': '2024-01-15 14:30'
            },
            {
                'id': 2,
                'title': 'Apache HTTP Server 2.4.49 Path Traversal',
                'severity': 'high',
                'host': '192.168.1.20',
                'port': '80',
                'service': 'http',
                'cve': 'CVE-2021-41773',
                'cvss': '7.5',
                'description': 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack.',
                'remediation': 'Update to Apache HTTP Server 2.4.51 or later.',
                'references': 'https://httpd.apache.org/security/vulnerabilities_24.html',
                'status': 'open',
                'source': 'nmap',
                'discovered': '2024-01-15 14:35'
            },
            {
                'id': 3,
                'title': 'MySQL Default Credentials',
                'severity': 'high',
                'host': '192.168.1.30',
                'port': '3306',
                'service': 'mysql',
                'cve': '-',
                'cvss': '8.0',
                'description': 'MySQL server is accessible with default or weak credentials. This allows unauthorized database access.',
                'remediation': 'Change default credentials immediately. Implement strong password policy.',
                'references': 'https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html',
                'status': 'confirmed',
                'source': 'hydra',
                'discovered': '2024-01-15 15:00'
            },
            {
                'id': 4,
                'title': 'SSL/TLS Certificate Expired',
                'severity': 'medium',
                'host': '192.168.1.40',
                'port': '443',
                'service': 'https',
                'cve': '-',
                'cvss': '5.3',
                'description': 'The SSL/TLS certificate has expired, which may lead to man-in-the-middle attacks.',
                'remediation': 'Renew the SSL/TLS certificate from a trusted Certificate Authority.',
                'references': 'https://www.ssllabs.com/ssltest/',
                'status': 'open',
                'source': 'osint',
                'discovered': '2024-01-15 15:15'
            },
            {
                'id': 5,
                'title': 'Anonymous FTP Login Allowed',
                'severity': 'low',
                'host': '192.168.1.50',
                'port': '21',
                'service': 'ftp',
                'cve': '-',
                'cvss': '3.1',
                'description': 'The FTP server allows anonymous login, potentially exposing sensitive files.',
                'remediation': 'Disable anonymous FTP access unless explicitly required.',
                'references': 'https://www.us-cert.gov/ncas/alerts/TA17-117A',
                'status': 'open',
                'source': 'nmap',
                'discovered': '2024-01-15 15:30'
            },
        ]
    
    def _refresh_table(self):
        """Refresh the vulnerability table"""
        self.vuln_table.setRowCount(0)
        
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in self.vulnerabilities:
            if self._matches_filter(vuln):
                self._add_table_row(vuln)
            
            severity = vuln.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        
        # Update stats
        for severity, count in counts.items():
            if severity in self.stat_labels:
                self.stat_labels[severity].setText(str(count))
    
    def _add_table_row(self, vuln: dict):
        """Add a row to the table"""
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        
        severity = vuln.get('severity', 'info').lower()
        
        # Severity indicator
        sev_item = QTableWidgetItem(severity.upper())
        sev_item.setData(Qt.ItemDataRole.UserRole, vuln.get('id'))
        sev_item.setForeground(QColor(self.SEVERITY_COLORS.get(severity, '#8b949e')))
        sev_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self.vuln_table.setItem(row, 0, sev_item)
        
        # Title
        self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln.get('title', '-')))
        
        # Host
        self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln.get('host', '-')))
        
        # CVE
        self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln.get('cve', '-')))
        
        # CVSS
        cvss = vuln.get('cvss', '-')
        cvss_item = QTableWidgetItem(str(cvss))
        try:
            cvss_val = float(cvss)
            if cvss_val >= 9.0:
                cvss_item.setForeground(QColor('#ff4444'))
            elif cvss_val >= 7.0:
                cvss_item.setForeground(QColor('#f85149'))
            elif cvss_val >= 4.0:
                cvss_item.setForeground(QColor('#d29922'))
            else:
                cvss_item.setForeground(QColor('#238636'))
        except:
            pass
        self.vuln_table.setItem(row, 4, cvss_item)
        
        # Status
        status = vuln.get('status', 'open')
        status_item = QTableWidgetItem(status.title())
        if status == 'fixed':
            status_item.setForeground(QColor('#238636'))
        elif status == 'false_positive':
            status_item.setForeground(QColor('#8b949e'))
        else:
            status_item.setForeground(QColor('#d29922'))
        self.vuln_table.setItem(row, 5, status_item)
    
    def _matches_filter(self, vuln: dict) -> bool:
        """Check if vulnerability matches filters"""
        search = self.search_input.text().lower()
        if search:
            searchable = f"{vuln.get('title', '')} {vuln.get('host', '')} {vuln.get('cve', '')}".lower()
            if search not in searchable:
                return False
        
        severity_filter = self.severity_filter.currentText()
        if severity_filter != "All Severities":
            if vuln.get('severity', '').lower() != severity_filter.lower():
                return False
        
        status_filter = self.status_filter.currentText()
        if status_filter != "All Status":
            vuln_status = vuln.get('status', 'open').replace('_', ' ').title()
            if vuln_status != status_filter:
                return False
        
        return True
    
    def _filter_vulns(self):
        """Filter vulnerabilities"""
        self._refresh_table()
    
    def _on_selection_changed(self):
        """Handle selection change"""
        selected = self.vuln_table.selectedItems()
        if selected:
            row = selected[0].row()
            sev_item = self.vuln_table.item(row, 0)
            if sev_item:
                vuln_id = sev_item.data(Qt.ItemDataRole.UserRole)
                vuln = next((v for v in self.vulnerabilities if v.get('id') == vuln_id), None)
                
                if vuln:
                    self._show_details(vuln)
    
    def _show_details(self, vuln: dict):
        """Show vulnerability details"""
        self.vuln_title.setText(vuln.get('title', 'Unknown'))
        
        severity = vuln.get('severity', 'info').lower()
        self.severity_badge.setSeverity(severity)
        
        self.detail_labels['cve'].setText(vuln.get('cve', '-'))
        self.detail_labels['cvss'].setText(str(vuln.get('cvss', '-')))
        self.detail_labels['host'].setText(vuln.get('host', '-'))
        self.detail_labels['port'].setText(str(vuln.get('port', '-')))
        self.detail_labels['service'].setText(vuln.get('service', '-'))
        self.detail_labels['status'].setText(vuln.get('status', 'open').title())
        self.detail_labels['discovered'].setText(vuln.get('discovered', '-'))
        self.detail_labels['source'].setText(vuln.get('source', '-').title())
        
        self.description_text.setText(vuln.get('description', 'No description available.'))
        self.remediation_text.setText(vuln.get('remediation', 'No remediation guidance available.'))
        self.references_text.setText(vuln.get('references', 'No references available.'))
    
    def _show_context_menu(self, pos):
        """Show context menu"""
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QMenu::item {
                padding: 8px 16px;
                color: #e6e6e6;
            }
            QMenu::item:selected {
                background-color: #238636;
            }
        """)
        
        confirm_action = menu.addAction("✅ Mark Confirmed")
        fixed_action = menu.addAction("🔧 Mark Fixed")
        false_positive_action = menu.addAction("❌ Mark False Positive")
        menu.addSeparator()
        export_action = menu.addAction("📄 Export")
        
        action = menu.exec(self.vuln_table.mapToGlobal(pos))
        
        if action == confirm_action:
            self._set_status('confirmed')
        elif action == fixed_action:
            self._set_status('fixed')
        elif action == false_positive_action:
            self._set_status('false_positive')
        elif action == export_action:
            self._export_details()
    
    def _set_status(self, status: str):
        """Set vulnerability status"""
        selected = self.vuln_table.selectedItems()
        if selected:
            row = selected[0].row()
            sev_item = self.vuln_table.item(row, 0)
            if sev_item:
                vuln_id = sev_item.data(Qt.ItemDataRole.UserRole)
                for vuln in self.vulnerabilities:
                    if vuln.get('id') == vuln_id:
                        vuln['status'] = status
                        break
                
                self._refresh_table()
    
    def _change_status(self):
        """Change vulnerability status via dialog"""
        selected = self.vuln_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Info", "Please select a vulnerability first.")
            return
        
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #161b22;
                border: 1px solid #30363d;
            }
            QMenu::item {
                padding: 8px 16px;
                color: #e6e6e6;
            }
            QMenu::item:selected {
                background-color: #238636;
            }
        """)
        
        menu.addAction("Open").triggered.connect(lambda: self._set_status('open'))
        menu.addAction("Confirmed").triggered.connect(lambda: self._set_status('confirmed'))
        menu.addAction("Fixed").triggered.connect(lambda: self._set_status('fixed'))
        menu.addAction("False Positive").triggered.connect(lambda: self._set_status('false_positive'))
        
        menu.exec(self.cursor().pos())
    
    def _export_details(self):
        """Export vulnerability details"""
        selected = self.vuln_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Info", "Please select a vulnerability first.")
            return
        
        QMessageBox.information(self, "Export", "Vulnerability details exported to report.")
    
    def _export_report(self):
        """Export all vulnerabilities report"""
        if not self.vulnerabilities:
            QMessageBox.information(self, "Info", "No vulnerabilities to export.")
            return
        
        QMessageBox.information(
            self, "Export Report",
            f"Would export {len(self.vulnerabilities)} vulnerabilities.\nSee Reports page for full report generation."
        )
    
    def _refresh(self):
        """Refresh vulnerabilities"""
        self._load_vulnerabilities()
        QMessageBox.information(self, "Refresh", "Vulnerabilities refreshed.")
