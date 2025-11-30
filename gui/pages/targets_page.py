#!/usr/bin/env python3
"""
HydraRecon Targets Page
Target management and organization interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QTabWidget, QComboBox, QMenu, QMessageBox, QFileDialog,
    QDialog, QDialogButtonBox, QFormLayout, QSpinBox, QGridLayout,
    QGroupBox, QListWidget, QListWidgetItem, QInputDialog
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QAction
import json
import csv
from datetime import datetime

from ..widgets import ModernLineEdit, GlowingButton


class AddTargetDialog(QDialog):
    """Dialog for adding a new target"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Target")
        self.setMinimumWidth(500)
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
        
        # Title
        title = QLabel("Add New Target")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Form
        form = QFormLayout()
        form.setSpacing(12)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP address, domain, or CIDR range")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        form.addRow("Target:", self.target_input)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["IP Address", "Domain", "Network (CIDR)", "URL", "Hostname"])
        self.type_combo.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        form.addRow("Type:", self.type_combo)
        
        self.scope_combo = QComboBox()
        self.scope_combo.addItems(["In Scope", "Out of Scope", "Informational"])
        self.scope_combo.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        form.addRow("Scope:", self.scope_combo)
        
        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("Comma-separated tags")
        self.tags_input.setStyleSheet("""
            QLineEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        form.addRow("Tags:", self.tags_input)
        
        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Additional notes...")
        self.notes_input.setMaximumHeight(100)
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
        
        # Buttons
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
            'target': self.target_input.text().strip(),
            'type': self.type_combo.currentText().lower().replace(" ", "_"),
            'scope': self.scope_combo.currentText().lower().replace(" ", "_"),
            'tags': [t.strip() for t in self.tags_input.text().split(',') if t.strip()],
            'notes': self.notes_input.toPlainText()
        }


class TargetsPage(QWidget):
    """Target management page"""
    
    targetAdded = pyqtSignal(dict)
    targetRemoved = pyqtSignal(int)
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.targets = []
        self._setup_ui()
        self._load_targets()
    
    def _setup_ui(self):
        """Setup the targets page UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(20)
        
        # Header
        header = self._create_header()
        layout.addLayout(header)
        
        # Main content
        content = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Target list
        left_panel = self._create_target_list_panel()
        content.addWidget(left_panel)
        
        # Right panel - Target details and actions
        right_panel = self._create_details_panel()
        content.addWidget(right_panel)
        
        content.setSizes([700, 500])
        layout.addWidget(content)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("Target Management")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Organize and manage your assessment targets")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Action buttons
        add_btn = GlowingButton("Add Target")
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
        add_btn.clicked.connect(self._add_target)
        
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
        import_btn.clicked.connect(self._import_targets)
        
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
        export_btn.clicked.connect(self._export_targets)
        
        layout.addWidget(import_btn)
        layout.addWidget(export_btn)
        layout.addWidget(add_btn)
        
        return layout
    
    def _create_target_list_panel(self) -> QFrame:
        """Create the target list panel"""
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
        
        self.search_input = ModernLineEdit("Search targets...")
        self.search_input.textChanged.connect(self._filter_targets)
        filter_layout.addWidget(self.search_input)
        
        self.scope_filter = QComboBox()
        self.scope_filter.addItems(["All Scopes", "In Scope", "Out of Scope", "Informational"])
        self.scope_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
                min-width: 120px;
            }
        """)
        self.scope_filter.currentTextChanged.connect(self._filter_targets)
        filter_layout.addWidget(self.scope_filter)
        
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All Types", "IP Address", "Domain", "Network (CIDR)", "URL", "Hostname"])
        self.type_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
                min-width: 120px;
            }
        """)
        self.type_filter.currentTextChanged.connect(self._filter_targets)
        filter_layout.addWidget(self.type_filter)
        
        layout.addLayout(filter_layout)
        
        # Target table
        self.targets_table = QTableWidget()
        self.targets_table.setColumnCount(6)
        self.targets_table.setHorizontalHeaderLabels([
            "Target", "Type", "Scope", "Tags", "Hosts", "Last Scan"
        ])
        self.targets_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.targets_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.targets_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.targets_table.customContextMenuRequested.connect(self._show_context_menu)
        self.targets_table.itemSelectionChanged.connect(self._on_selection_changed)
        self.targets_table.setStyleSheet("""
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
        layout.addWidget(self.targets_table)
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.stats_label = QLabel("0 targets")
        self.stats_label.setStyleSheet("color: #8b949e;")
        stats_layout.addWidget(self.stats_label)
        
        stats_layout.addStretch()
        
        # Bulk actions
        select_all = QPushButton("Select All")
        select_all.clicked.connect(self.targets_table.selectAll)
        select_all.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                color: #0088ff;
                padding: 4px 8px;
            }
            QPushButton:hover { text-decoration: underline; }
        """)
        
        delete_selected = QPushButton("Delete Selected")
        delete_selected.clicked.connect(self._delete_selected)
        delete_selected.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                color: #da3633;
                padding: 4px 8px;
            }
            QPushButton:hover { text-decoration: underline; }
        """)
        
        stats_layout.addWidget(select_all)
        stats_layout.addWidget(delete_selected)
        
        layout.addLayout(stats_layout)
        
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
        
        # Header
        header_label = QLabel("Target Details")
        header_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header_label.setStyleSheet("color: #e6e6e6;")
        layout.addWidget(header_label)
        
        # Details form
        details_widget = QWidget()
        details_layout = QFormLayout(details_widget)
        details_layout.setSpacing(12)
        
        self.detail_target = QLabel("-")
        self.detail_target.setStyleSheet("color: #00ff88; font-family: monospace; font-size: 14px;")
        details_layout.addRow("Target:", self.detail_target)
        
        self.detail_type = QLabel("-")
        self.detail_type.setStyleSheet("color: #e6e6e6;")
        details_layout.addRow("Type:", self.detail_type)
        
        self.detail_scope = QLabel("-")
        self.detail_scope.setStyleSheet("color: #e6e6e6;")
        details_layout.addRow("Scope:", self.detail_scope)
        
        self.detail_added = QLabel("-")
        self.detail_added.setStyleSheet("color: #8b949e;")
        details_layout.addRow("Added:", self.detail_added)
        
        self.detail_last_scan = QLabel("-")
        self.detail_last_scan.setStyleSheet("color: #8b949e;")
        details_layout.addRow("Last Scan:", self.detail_last_scan)
        
        layout.addWidget(details_widget)
        
        # Tags
        tags_label = QLabel("Tags")
        tags_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(tags_label)
        
        self.tags_container = QWidget()
        self.tags_layout = QHBoxLayout(self.tags_container)
        self.tags_layout.setContentsMargins(0, 0, 0, 0)
        self.tags_layout.setSpacing(8)
        self.tags_layout.addStretch()
        layout.addWidget(self.tags_container)
        
        # Notes
        notes_label = QLabel("Notes")
        notes_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(notes_label)
        
        self.notes_display = QTextEdit()
        self.notes_display.setReadOnly(True)
        self.notes_display.setMaximumHeight(100)
        self.notes_display.setStyleSheet("""
            QTextEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        layout.addWidget(self.notes_display)
        
        layout.addStretch()
        
        # Quick actions
        actions_label = QLabel("Quick Actions")
        actions_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(actions_label)
        
        actions_grid = QGridLayout()
        actions_grid.setSpacing(8)
        
        actions = [
            ("🔍 Nmap Scan", self._quick_nmap),
            ("🔓 Hydra Attack", self._quick_hydra),
            ("🌐 OSINT Gather", self._quick_osint),
            ("📋 Copy Target", self._copy_target),
        ]
        
        for i, (text, callback) in enumerate(actions):
            btn = QPushButton(text)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262d;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 10px;
                    color: #e6e6e6;
                }
                QPushButton:hover { background-color: #30363d; }
            """)
            btn.clicked.connect(callback)
            actions_grid.addWidget(btn, i // 2, i % 2)
        
        layout.addLayout(actions_grid)
        
        return panel
    
    def _load_targets(self):
        """Load targets from database"""
        try:
            if self.db:
                cursor = self.db.execute(
                    "SELECT * FROM targets WHERE project_id = ?",
                    (getattr(self.config, 'project_id', 1),)
                )
                rows = cursor.fetchall()
                
                self.targets = []
                for row in rows:
                    self.targets.append({
                        'id': row[0],
                        'target': row[2],
                        'type': row[3],
                        'scope': row[4] if len(row) > 4 else 'in_scope',
                        'tags': row[5].split(',') if len(row) > 5 and row[5] else [],
                        'notes': row[6] if len(row) > 6 else '',
                        'added': row[7] if len(row) > 7 else datetime.now().isoformat(),
                        'last_scan': row[8] if len(row) > 8 else None
                    })
                
                self._refresh_table()
        except Exception as e:
            # If database doesn't exist or has different schema, use empty list
            self.targets = []
    
    def _refresh_table(self):
        """Refresh the targets table"""
        self.targets_table.setRowCount(0)
        
        for target in self.targets:
            if self._matches_filter(target):
                self._add_table_row(target)
        
        self._update_stats()
    
    def _add_table_row(self, target: dict):
        """Add a row to the targets table"""
        row = self.targets_table.rowCount()
        self.targets_table.insertRow(row)
        
        # Target
        target_item = QTableWidgetItem(target['target'])
        target_item.setData(Qt.ItemDataRole.UserRole, target.get('id'))
        self.targets_table.setItem(row, 0, target_item)
        
        # Type
        type_item = QTableWidgetItem(target.get('type', 'unknown').replace('_', ' ').title())
        self.targets_table.setItem(row, 1, type_item)
        
        # Scope
        scope = target.get('scope', 'in_scope')
        scope_item = QTableWidgetItem(scope.replace('_', ' ').title())
        if scope == 'in_scope':
            scope_item.setForeground(QColor('#238636'))
        elif scope == 'out_of_scope':
            scope_item.setForeground(QColor('#da3633'))
        else:
            scope_item.setForeground(QColor('#d29922'))
        self.targets_table.setItem(row, 2, scope_item)
        
        # Tags
        tags = target.get('tags', [])
        tags_item = QTableWidgetItem(', '.join(tags) if tags else '-')
        self.targets_table.setItem(row, 3, tags_item)
        
        # Hosts count (placeholder)
        hosts_item = QTableWidgetItem('0')
        hosts_item.setForeground(QColor('#8b949e'))
        self.targets_table.setItem(row, 4, hosts_item)
        
        # Last scan
        last_scan = target.get('last_scan')
        scan_item = QTableWidgetItem(last_scan if last_scan else 'Never')
        scan_item.setForeground(QColor('#8b949e'))
        self.targets_table.setItem(row, 5, scan_item)
    
    def _matches_filter(self, target: dict) -> bool:
        """Check if target matches current filters"""
        search = self.search_input.text().lower()
        if search and search not in target['target'].lower():
            return False
        
        scope_filter = self.scope_filter.currentText()
        if scope_filter != "All Scopes":
            if target.get('scope', '').replace('_', ' ').title() != scope_filter:
                return False
        
        type_filter = self.type_filter.currentText()
        if type_filter != "All Types":
            if target.get('type', '').replace('_', ' ').title() != type_filter:
                return False
        
        return True
    
    def _filter_targets(self):
        """Filter targets based on search and filters"""
        self._refresh_table()
    
    def _update_stats(self):
        """Update the stats label"""
        total = len(self.targets)
        in_scope = len([t for t in self.targets if t.get('scope') == 'in_scope'])
        self.stats_label.setText(f"{total} targets ({in_scope} in scope)")
    
    def _add_target(self):
        """Add a new target"""
        dialog = AddTargetDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if data['target']:
                target = {
                    'id': len(self.targets) + 1,
                    'target': data['target'],
                    'type': data['type'],
                    'scope': data['scope'],
                    'tags': data['tags'],
                    'notes': data['notes'],
                    'added': datetime.now().strftime('%Y-%m-%d %H:%M'),
                    'last_scan': None
                }
                self.targets.append(target)
                self._refresh_table()
                self.targetAdded.emit(target)
    
    def _import_targets(self):
        """Import targets from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Targets", "",
            "All Supported (*.txt *.csv *.json);;Text Files (*.txt);;CSV Files (*.csv);;JSON Files (*.json)"
        )
        
        if file_path:
            try:
                imported = 0
                
                if file_path.endswith('.txt'):
                    with open(file_path, 'r') as f:
                        for line in f:
                            target = line.strip()
                            if target and not target.startswith('#'):
                                self.targets.append({
                                    'id': len(self.targets) + 1,
                                    'target': target,
                                    'type': 'ip_address',
                                    'scope': 'in_scope',
                                    'tags': [],
                                    'notes': '',
                                    'added': datetime.now().strftime('%Y-%m-%d %H:%M'),
                                    'last_scan': None
                                })
                                imported += 1
                
                elif file_path.endswith('.csv'):
                    with open(file_path, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            self.targets.append({
                                'id': len(self.targets) + 1,
                                'target': row.get('target', row.get('ip', row.get('host', ''))),
                                'type': row.get('type', 'ip_address'),
                                'scope': row.get('scope', 'in_scope'),
                                'tags': row.get('tags', '').split(','),
                                'notes': row.get('notes', ''),
                                'added': datetime.now().strftime('%Y-%m-%d %H:%M'),
                                'last_scan': None
                            })
                            imported += 1
                
                elif file_path.endswith('.json'):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, str):
                                    target_val = item
                                    target_data = {
                                        'type': 'ip_address',
                                        'scope': 'in_scope',
                                        'tags': [],
                                        'notes': ''
                                    }
                                else:
                                    target_val = item.get('target', item.get('ip', item.get('host', '')))
                                    target_data = item
                                
                                self.targets.append({
                                    'id': len(self.targets) + 1,
                                    'target': target_val,
                                    'type': target_data.get('type', 'ip_address'),
                                    'scope': target_data.get('scope', 'in_scope'),
                                    'tags': target_data.get('tags', []),
                                    'notes': target_data.get('notes', ''),
                                    'added': datetime.now().strftime('%Y-%m-%d %H:%M'),
                                    'last_scan': None
                                })
                                imported += 1
                
                self._refresh_table()
                QMessageBox.information(self, "Import Complete", f"Imported {imported} targets.")
                
            except Exception as e:
                QMessageBox.warning(self, "Import Error", f"Failed to import: {e}")
    
    def _export_targets(self):
        """Export targets to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Targets", "targets.json",
            "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.targets, f, indent=2)
                
                elif file_path.endswith('.csv'):
                    with open(file_path, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['target', 'type', 'scope', 'tags', 'notes'])
                        for target in self.targets:
                            writer.writerow([
                                target['target'],
                                target.get('type', ''),
                                target.get('scope', ''),
                                ','.join(target.get('tags', [])),
                                target.get('notes', '')
                            ])
                
                elif file_path.endswith('.txt'):
                    with open(file_path, 'w') as f:
                        for target in self.targets:
                            f.write(target['target'] + '\n')
                
                QMessageBox.information(self, "Export Complete", f"Exported {len(self.targets)} targets.")
                
            except Exception as e:
                QMessageBox.warning(self, "Export Error", f"Failed to export: {e}")
    
    def _delete_selected(self):
        """Delete selected targets"""
        selected = self.targets_table.selectedItems()
        if not selected:
            return
        
        rows = set()
        for item in selected:
            rows.add(item.row())
        
        if QMessageBox.question(
            self, "Confirm Delete",
            f"Delete {len(rows)} selected target(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            # Get target IDs to delete
            ids_to_delete = []
            for row in sorted(rows, reverse=True):
                item = self.targets_table.item(row, 0)
                if item:
                    target_id = item.data(Qt.ItemDataRole.UserRole)
                    ids_to_delete.append(target_id)
            
            # Remove from list
            self.targets = [t for t in self.targets if t.get('id') not in ids_to_delete]
            self._refresh_table()
    
    def _show_context_menu(self, pos):
        """Show context menu for target"""
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 4px;
            }
            QMenu::item {
                padding: 8px 16px;
                color: #e6e6e6;
            }
            QMenu::item:selected {
                background-color: #238636;
            }
        """)
        
        scan_action = menu.addAction("🔍 Nmap Scan")
        attack_action = menu.addAction("🔓 Hydra Attack")
        osint_action = menu.addAction("🌐 OSINT Gather")
        menu.addSeparator()
        copy_action = menu.addAction("📋 Copy Target")
        edit_action = menu.addAction("✏️ Edit")
        delete_action = menu.addAction("🗑️ Delete")
        
        action = menu.exec(self.targets_table.mapToGlobal(pos))
        
        if action == scan_action:
            self._quick_nmap()
        elif action == attack_action:
            self._quick_hydra()
        elif action == osint_action:
            self._quick_osint()
        elif action == copy_action:
            self._copy_target()
        elif action == delete_action:
            self._delete_selected()
    
    def _on_selection_changed(self):
        """Handle selection change"""
        selected = self.targets_table.selectedItems()
        if selected:
            row = selected[0].row()
            target_item = self.targets_table.item(row, 0)
            if target_item:
                target_id = target_item.data(Qt.ItemDataRole.UserRole)
                target = next((t for t in self.targets if t.get('id') == target_id), None)
                
                if target:
                    self._show_target_details(target)
    
    def _show_target_details(self, target: dict):
        """Show target details"""
        self.detail_target.setText(target['target'])
        self.detail_type.setText(target.get('type', 'unknown').replace('_', ' ').title())
        self.detail_scope.setText(target.get('scope', 'in_scope').replace('_', ' ').title())
        self.detail_added.setText(target.get('added', '-'))
        self.detail_last_scan.setText(target.get('last_scan') or 'Never')
        self.notes_display.setText(target.get('notes', ''))
        
        # Clear old tags
        while self.tags_layout.count() > 1:
            item = self.tags_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Add tags
        for tag in target.get('tags', []):
            if tag:
                tag_label = QLabel(tag)
                tag_label.setStyleSheet("""
                    QLabel {
                        background-color: #0088ff;
                        color: white;
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-size: 11px;
                    }
                """)
                self.tags_layout.insertWidget(self.tags_layout.count() - 1, tag_label)
    
    def _quick_nmap(self):
        """Quick Nmap scan on selected target"""
        selected = self.targets_table.selectedItems()
        if selected:
            target = self.targets_table.item(selected[0].row(), 0).text()
            # Emit signal or navigate to Nmap page
            QMessageBox.information(self, "Nmap Scan", f"Starting Nmap scan on {target}")
    
    def _quick_hydra(self):
        """Quick Hydra attack on selected target"""
        selected = self.targets_table.selectedItems()
        if selected:
            target = self.targets_table.item(selected[0].row(), 0).text()
            QMessageBox.information(self, "Hydra Attack", f"Starting Hydra attack on {target}")
    
    def _quick_osint(self):
        """Quick OSINT gather on selected target"""
        selected = self.targets_table.selectedItems()
        if selected:
            target = self.targets_table.item(selected[0].row(), 0).text()
            QMessageBox.information(self, "OSINT", f"Starting OSINT gathering on {target}")
    
    def _copy_target(self):
        """Copy target to clipboard"""
        from PyQt6.QtWidgets import QApplication
        selected = self.targets_table.selectedItems()
        if selected:
            target = self.targets_table.item(selected[0].row(), 0).text()
            QApplication.clipboard().setText(target)
