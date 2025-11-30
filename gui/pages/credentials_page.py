#!/usr/bin/env python3
"""
HydraRecon Credentials Page
Credential management and verification interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QComboBox, QMenu, QMessageBox, QFileDialog, QDialog, QDialogButtonBox,
    QFormLayout, QTextEdit, QCheckBox, QGridLayout, QTabWidget,
    QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import json
import csv
from datetime import datetime

from ..widgets import ModernLineEdit, GlowingButton, SeverityBadge


class CredentialVerifyThread(QThread):
    """Thread for verifying credentials"""
    progress = pyqtSignal(int, str)
    result = pyqtSignal(int, bool)  # cred_id, valid
    finished_verify = pyqtSignal()
    
    def __init__(self, credentials, scanner):
        super().__init__()
        self.credentials = credentials
        self.scanner = scanner
    
    def run(self):
        total = len(self.credentials)
        for i, cred in enumerate(self.credentials):
            self.progress.emit(int((i / total) * 100), f"Verifying {cred['username']}@{cred['host']}...")
            # Verification logic would go here
            # For now, just emit the result
            self.result.emit(cred['id'], True)
        
        self.finished_verify.emit()


class AddCredentialDialog(QDialog):
    """Dialog for adding a credential"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Credential")
        self.setMinimumWidth(450)
        self.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
            }
            QLabel {
                color: #e6e6e6;
            }
        """)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        title = QLabel("Add New Credential")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(title)
        
        form = QFormLayout()
        form.setSpacing(12)
        
        input_style = """
            QLineEdit, QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """
        
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("IP address or hostname")
        self.host_input.setStyleSheet(input_style)
        form.addRow("Host:", self.host_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port number")
        self.port_input.setStyleSheet(input_style)
        form.addRow("Port:", self.port_input)
        
        self.service_combo = QComboBox()
        self.service_combo.addItems([
            "ssh", "ftp", "rdp", "telnet", "mysql", "mssql",
            "postgresql", "smb", "vnc", "http", "https", "smtp",
            "pop3", "imap", "ldap", "snmp", "oracle", "mongodb"
        ])
        self.service_combo.setStyleSheet(input_style)
        form.addRow("Service:", self.service_combo)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setStyleSheet(input_style)
        form.addRow("Username:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(input_style)
        form.addRow("Password:", self.password_input)
        
        self.source_combo = QComboBox()
        self.source_combo.addItems(["Manual", "Hydra", "Other Tool", "Known"])
        self.source_combo.setStyleSheet(input_style)
        form.addRow("Source:", self.source_combo)
        
        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Additional notes...")
        self.notes_input.setMaximumHeight(80)
        self.notes_input.setStyleSheet("""
            QTextEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        form.addRow("Notes:", self.notes_input)
        
        layout.addLayout(form)
        
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        button_box.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                color: white;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        layout.addWidget(button_box)
    
    def get_data(self) -> dict:
        return {
            'host': self.host_input.text().strip(),
            'port': int(self.port_input.text()) if self.port_input.text().isdigit() else 0,
            'service': self.service_combo.currentText(),
            'username': self.username_input.text(),
            'password': self.password_input.text(),
            'source': self.source_combo.currentText().lower(),
            'notes': self.notes_input.toPlainText()
        }


class CredentialsPage(QWidget):
    """Credentials management page"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.credentials = []
        self._setup_ui()
        self._load_credentials()
    
    def _setup_ui(self):
        """Setup the credentials page UI"""
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
        content = QSplitter(Qt.Orientation.Vertical)
        
        # Credentials table
        table_panel = self._create_table_panel()
        content.addWidget(table_panel)
        
        # Details panel
        details_panel = self._create_details_panel()
        content.addWidget(details_panel)
        
        content.setSizes([500, 200])
        layout.addWidget(content)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("Credentials Database")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Manage discovered and known credentials")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Action buttons
        add_btn = GlowingButton("Add Credential")
        add_btn.setStyleSheet("""
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
        add_btn.clicked.connect(self._add_credential)
        
        import_btn = QPushButton("Import")
        import_btn.setStyleSheet("""
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
        import_btn.clicked.connect(self._import_credentials)
        
        export_btn = QPushButton("Export")
        export_btn.setStyleSheet("""
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
        export_btn.clicked.connect(self._export_credentials)
        
        verify_btn = QPushButton("Verify All")
        verify_btn.setStyleSheet("""
            QPushButton {
                background-color: #0088ff;
                border: none;
                border-radius: 8px;
                padding: 12px 20px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #0099ff; }
        """)
        verify_btn.clicked.connect(self._verify_credentials)
        
        layout.addWidget(import_btn)
        layout.addWidget(export_btn)
        layout.addWidget(verify_btn)
        layout.addWidget(add_btn)
        
        return layout
    
    def _create_stats_row(self) -> QHBoxLayout:
        """Create the stats row"""
        layout = QHBoxLayout()
        layout.setSpacing(16)
        
        stats = [
            ("Total", "0", "#e6e6e6"),
            ("Verified", "0", "#238636"),
            ("Invalid", "0", "#da3633"),
            ("Untested", "0", "#d29922"),
        ]
        
        for label, value, color in stats:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #0d1117;
                    border: 1px solid #21262d;
                    border-radius: 10px;
                    padding: 12px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 12, 16, 12)
            card_layout.setSpacing(4)
            
            value_label = QLabel(value)
            value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
            value_label.setStyleSheet(f"color: {color};")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #8b949e;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(value_label)
            card_layout.addWidget(name_label)
            
            if label == "Total":
                self.total_label = value_label
            elif label == "Verified":
                self.verified_label = value_label
            elif label == "Invalid":
                self.invalid_label = value_label
            elif label == "Untested":
                self.untested_label = value_label
            
            layout.addWidget(card)
        
        return layout
    
    def _create_table_panel(self) -> QFrame:
        """Create the credentials table panel"""
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
        
        self.search_input = ModernLineEdit("Search credentials...")
        self.search_input.textChanged.connect(self._filter_credentials)
        filter_layout.addWidget(self.search_input)
        
        self.service_filter = QComboBox()
        self.service_filter.addItems([
            "All Services", "ssh", "ftp", "rdp", "telnet", "mysql",
            "mssql", "postgresql", "smb", "vnc", "http", "https"
        ])
        self.service_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
                min-width: 120px;
            }
        """)
        self.service_filter.currentTextChanged.connect(self._filter_credentials)
        filter_layout.addWidget(self.service_filter)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Status", "Verified", "Invalid", "Untested"])
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
        self.status_filter.currentTextChanged.connect(self._filter_credentials)
        filter_layout.addWidget(self.status_filter)
        
        layout.addLayout(filter_layout)
        
        # Credentials table
        self.creds_table = QTableWidget()
        self.creds_table.setColumnCount(8)
        self.creds_table.setHorizontalHeaderLabels([
            "Host", "Port", "Service", "Username", "Password", "Status", "Source", "Discovered"
        ])
        self.creds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.creds_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.creds_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.creds_table.customContextMenuRequested.connect(self._show_context_menu)
        self.creds_table.itemSelectionChanged.connect(self._on_selection_changed)
        self.creds_table.setStyleSheet("""
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
        layout.addWidget(self.creds_table)
        
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
        
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Credential details
        details_layout = QVBoxLayout()
        
        details_label = QLabel("Credential Details")
        details_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        details_label.setStyleSheet("color: #e6e6e6;")
        details_layout.addWidget(details_label)
        
        details_grid = QGridLayout()
        details_grid.setSpacing(8)
        
        self.detail_labels = {}
        fields = [
            ("Host:", "host"),
            ("Port:", "port"),
            ("Service:", "service"),
            ("Username:", "username"),
            ("Password:", "password"),
            ("Status:", "status"),
            ("Source:", "source"),
            ("Discovered:", "discovered"),
        ]
        
        for i, (label, key) in enumerate(fields):
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e;")
            value = QLabel("-")
            value.setStyleSheet("color: #e6e6e6;")
            if key == "password":
                value.setStyleSheet("color: #00ff88; font-family: monospace;")
            self.detail_labels[key] = value
            
            details_grid.addWidget(name, i // 4, (i % 4) * 2)
            details_grid.addWidget(value, i // 4, (i % 4) * 2 + 1)
        
        details_layout.addLayout(details_grid)
        layout.addLayout(details_layout)
        
        # Quick actions
        actions_layout = QVBoxLayout()
        
        actions_label = QLabel("Quick Actions")
        actions_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        actions_label.setStyleSheet("color: #e6e6e6;")
        actions_layout.addWidget(actions_label)
        
        button_style = """
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
                text-align: left;
            }
            QPushButton:hover { background-color: #30363d; }
        """
        
        verify_btn = QPushButton("✅ Verify Credential")
        verify_btn.setStyleSheet(button_style)
        verify_btn.clicked.connect(self._verify_selected)
        actions_layout.addWidget(verify_btn)
        
        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.setStyleSheet(button_style)
        copy_btn.clicked.connect(self._copy_credential)
        actions_layout.addWidget(copy_btn)
        
        connect_btn = QPushButton("🔗 Open Connection")
        connect_btn.setStyleSheet(button_style)
        connect_btn.clicked.connect(self._open_connection)
        actions_layout.addWidget(connect_btn)
        
        delete_btn = QPushButton("🗑️ Delete")
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(218, 54, 51, 0.2);
                border: 1px solid #da3633;
                border-radius: 6px;
                padding: 10px 16px;
                color: #f85149;
                text-align: left;
            }
            QPushButton:hover { background-color: rgba(218, 54, 51, 0.3); }
        """)
        delete_btn.clicked.connect(self._delete_selected)
        actions_layout.addWidget(delete_btn)
        
        actions_layout.addStretch()
        layout.addLayout(actions_layout)
        
        return panel
    
    def _load_credentials(self):
        """Load credentials from database"""
        try:
            if self.db:
                cursor = self.db.execute(
                    "SELECT * FROM credentials WHERE project_id = ?",
                    (getattr(self.config, 'project_id', 1),)
                )
                rows = cursor.fetchall()
                
                self.credentials = []
                for row in rows:
                    self.credentials.append({
                        'id': row[0],
                        'host': row[2],
                        'port': row[3],
                        'service': row[4],
                        'username': row[5],
                        'password': row[6],
                        'status': row[7] if len(row) > 7 else 'untested',
                        'source': row[8] if len(row) > 8 else 'manual',
                        'discovered': row[9] if len(row) > 9 else datetime.now().isoformat()
                    })
                
                self._refresh_table()
        except Exception:
            self.credentials = []
    
    def _refresh_table(self):
        """Refresh the credentials table"""
        self.creds_table.setRowCount(0)
        
        verified = 0
        invalid = 0
        untested = 0
        
        for cred in self.credentials:
            if self._matches_filter(cred):
                self._add_table_row(cred)
            
            status = cred.get('status', 'untested').lower()
            if status == 'verified' or status == 'valid':
                verified += 1
            elif status == 'invalid':
                invalid += 1
            else:
                untested += 1
        
        # Update stats
        self.total_label.setText(str(len(self.credentials)))
        self.verified_label.setText(str(verified))
        self.invalid_label.setText(str(invalid))
        self.untested_label.setText(str(untested))
    
    def _add_table_row(self, cred: dict):
        """Add a row to the credentials table"""
        row = self.creds_table.rowCount()
        self.creds_table.insertRow(row)
        
        # Store ID
        host_item = QTableWidgetItem(cred.get('host', '-'))
        host_item.setData(Qt.ItemDataRole.UserRole, cred.get('id'))
        self.creds_table.setItem(row, 0, host_item)
        
        # Port
        self.creds_table.setItem(row, 1, QTableWidgetItem(str(cred.get('port', '-'))))
        
        # Service
        self.creds_table.setItem(row, 2, QTableWidgetItem(cred.get('service', '-')))
        
        # Username
        self.creds_table.setItem(row, 3, QTableWidgetItem(cred.get('username', '-')))
        
        # Password (masked)
        password = cred.get('password', '')
        masked = '*' * min(len(password), 12) if password else '-'
        pass_item = QTableWidgetItem(masked)
        pass_item.setData(Qt.ItemDataRole.UserRole + 1, password)  # Store actual password
        self.creds_table.setItem(row, 4, pass_item)
        
        # Status with color
        status = cred.get('status', 'untested')
        status_item = QTableWidgetItem(status.title())
        if status.lower() in ['verified', 'valid']:
            status_item.setForeground(QColor('#238636'))
        elif status.lower() == 'invalid':
            status_item.setForeground(QColor('#da3633'))
        else:
            status_item.setForeground(QColor('#d29922'))
        self.creds_table.setItem(row, 5, status_item)
        
        # Source
        self.creds_table.setItem(row, 6, QTableWidgetItem(cred.get('source', '-').title()))
        
        # Discovered
        self.creds_table.setItem(row, 7, QTableWidgetItem(cred.get('discovered', '-')))
    
    def _matches_filter(self, cred: dict) -> bool:
        """Check if credential matches filters"""
        search = self.search_input.text().lower()
        if search:
            searchable = f"{cred.get('host', '')} {cred.get('username', '')} {cred.get('service', '')}".lower()
            if search not in searchable:
                return False
        
        service_filter = self.service_filter.currentText()
        if service_filter != "All Services":
            if cred.get('service', '').lower() != service_filter.lower():
                return False
        
        status_filter = self.status_filter.currentText()
        if status_filter != "All Status":
            if cred.get('status', 'untested').lower() != status_filter.lower():
                return False
        
        return True
    
    def _filter_credentials(self):
        """Filter credentials"""
        self._refresh_table()
    
    def _add_credential(self):
        """Add a new credential"""
        dialog = AddCredentialDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if data['host'] and data['username']:
                cred = {
                    'id': len(self.credentials) + 1,
                    **data,
                    'status': 'untested',
                    'discovered': datetime.now().strftime('%Y-%m-%d %H:%M')
                }
                self.credentials.append(cred)
                self._refresh_table()
    
    def _import_credentials(self):
        """Import credentials from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Credentials", "",
            "All Supported (*.csv *.json);;CSV Files (*.csv);;JSON Files (*.json)"
        )
        
        if file_path:
            try:
                imported = 0
                
                if file_path.endswith('.csv'):
                    with open(file_path, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            self.credentials.append({
                                'id': len(self.credentials) + 1,
                                'host': row.get('host', row.get('ip', '')),
                                'port': int(row.get('port', 0)) if row.get('port', '').isdigit() else 0,
                                'service': row.get('service', 'ssh'),
                                'username': row.get('username', row.get('user', '')),
                                'password': row.get('password', row.get('pass', '')),
                                'status': 'untested',
                                'source': 'import',
                                'discovered': datetime.now().strftime('%Y-%m-%d %H:%M')
                            })
                            imported += 1
                
                elif file_path.endswith('.json'):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                self.credentials.append({
                                    'id': len(self.credentials) + 1,
                                    'host': item.get('host', item.get('ip', '')),
                                    'port': item.get('port', 0),
                                    'service': item.get('service', 'ssh'),
                                    'username': item.get('username', item.get('user', '')),
                                    'password': item.get('password', item.get('pass', '')),
                                    'status': item.get('status', 'untested'),
                                    'source': 'import',
                                    'discovered': datetime.now().strftime('%Y-%m-%d %H:%M')
                                })
                                imported += 1
                
                self._refresh_table()
                QMessageBox.information(self, "Import Complete", f"Imported {imported} credentials.")
                
            except Exception as e:
                QMessageBox.warning(self, "Import Error", f"Failed to import: {e}")
    
    def _export_credentials(self):
        """Export credentials to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Credentials", "credentials.json",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.credentials, f, indent=2)
                
                elif file_path.endswith('.csv'):
                    with open(file_path, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['host', 'port', 'service', 'username', 'password', 'status', 'source'])
                        for cred in self.credentials:
                            writer.writerow([
                                cred.get('host', ''),
                                cred.get('port', ''),
                                cred.get('service', ''),
                                cred.get('username', ''),
                                cred.get('password', ''),
                                cred.get('status', ''),
                                cred.get('source', '')
                            ])
                
                QMessageBox.information(self, "Export Complete", f"Exported {len(self.credentials)} credentials.")
                
            except Exception as e:
                QMessageBox.warning(self, "Export Error", f"Failed to export: {e}")
    
    def _verify_credentials(self):
        """Verify all credentials"""
        if not self.credentials:
            QMessageBox.information(self, "Info", "No credentials to verify.")
            return
        
        QMessageBox.information(
            self, "Verification",
            f"Would verify {len(self.credentials)} credentials.\nThis feature requires active connections to target services."
        )
    
    def _verify_selected(self):
        """Verify selected credential"""
        selected = self.creds_table.selectedItems()
        if selected:
            QMessageBox.information(self, "Verification", "Credential verification requires active service connection.")
    
    def _on_selection_changed(self):
        """Handle selection change"""
        selected = self.creds_table.selectedItems()
        if selected:
            row = selected[0].row()
            host_item = self.creds_table.item(row, 0)
            if host_item:
                cred_id = host_item.data(Qt.ItemDataRole.UserRole)
                cred = next((c for c in self.credentials if c.get('id') == cred_id), None)
                
                if cred:
                    self.detail_labels['host'].setText(cred.get('host', '-'))
                    self.detail_labels['port'].setText(str(cred.get('port', '-')))
                    self.detail_labels['service'].setText(cred.get('service', '-'))
                    self.detail_labels['username'].setText(cred.get('username', '-'))
                    self.detail_labels['password'].setText(cred.get('password', '-'))
                    self.detail_labels['status'].setText(cred.get('status', 'untested').title())
                    self.detail_labels['source'].setText(cred.get('source', '-').title())
                    self.detail_labels['discovered'].setText(cred.get('discovered', '-'))
    
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
        
        verify_action = menu.addAction("✅ Verify")
        copy_action = menu.addAction("📋 Copy")
        connect_action = menu.addAction("🔗 Connect")
        menu.addSeparator()
        delete_action = menu.addAction("🗑️ Delete")
        
        action = menu.exec(self.creds_table.mapToGlobal(pos))
        
        if action == verify_action:
            self._verify_selected()
        elif action == copy_action:
            self._copy_credential()
        elif action == connect_action:
            self._open_connection()
        elif action == delete_action:
            self._delete_selected()
    
    def _copy_credential(self):
        """Copy credential to clipboard"""
        from PyQt6.QtWidgets import QApplication
        
        selected = self.creds_table.selectedItems()
        if selected:
            row = selected[0].row()
            host = self.creds_table.item(row, 0).text()
            port = self.creds_table.item(row, 1).text()
            username = self.creds_table.item(row, 3).text()
            password = self.creds_table.item(row, 4).data(Qt.ItemDataRole.UserRole + 1)
            
            text = f"{username}:{password}@{host}:{port}"
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", "Credential copied to clipboard.")
    
    def _open_connection(self):
        """Open connection with credential"""
        selected = self.creds_table.selectedItems()
        if selected:
            row = selected[0].row()
            service = self.creds_table.item(row, 2).text().lower()
            host = self.creds_table.item(row, 0).text()
            port = self.creds_table.item(row, 1).text()
            
            QMessageBox.information(
                self, "Connection",
                f"Would open {service} connection to {host}:{port}\nFeature requires external tools integration."
            )
    
    def _delete_selected(self):
        """Delete selected credentials"""
        selected = self.creds_table.selectedItems()
        if not selected:
            return
        
        rows = set(item.row() for item in selected)
        
        if QMessageBox.question(
            self, "Confirm Delete",
            f"Delete {len(rows)} selected credential(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            ids_to_delete = []
            for row in sorted(rows, reverse=True):
                item = self.creds_table.item(row, 0)
                if item:
                    ids_to_delete.append(item.data(Qt.ItemDataRole.UserRole))
            
            self.credentials = [c for c in self.credentials if c.get('id') not in ids_to_delete]
            self._refresh_table()
