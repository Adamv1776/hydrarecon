#!/usr/bin/env python3
"""
HydraRecon Dialogs
Project management and utility dialogs.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit,
    QPushButton, QComboBox, QCheckBox, QFrame, QFormLayout,
    QFileDialog, QMessageBox, QListWidget, QListWidgetItem,
    QDialogButtonBox, QGridLayout, QGroupBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
import os
from datetime import datetime


class NewProjectDialog(QDialog):
    """Dialog for creating a new project"""
    
    projectCreated = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Project")
        self.setMinimumSize(600, 500)
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
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(24)
        
        # Header
        header = QLabel("🔒 Create New Project")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ff88;")
        layout.addWidget(header)
        
        subtitle = QLabel("Set up a new security assessment project")
        subtitle.setStyleSheet("color: #8b949e;")
        layout.addWidget(subtitle)
        
        # Form
        form = QFormLayout()
        form.setSpacing(16)
        
        input_style = """
            QLineEdit, QTextEdit, QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                color: #e6e6e6;
                font-size: 14px;
            }
            QLineEdit:focus, QTextEdit:focus {
                border-color: #00ff88;
            }
        """
        
        # Project name
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., Client ABC Security Assessment")
        self.name_input.setStyleSheet(input_style)
        form.addRow("Project Name *", self.name_input)
        
        # Project type
        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "Full Security Assessment",
            "Vulnerability Assessment",
            "Penetration Test",
            "Network Discovery",
            "Web Application Test",
            "OSINT Reconnaissance",
            "Custom"
        ])
        self.type_combo.setStyleSheet(input_style)
        form.addRow("Project Type", self.type_combo)
        
        # Client name
        self.client_input = QLineEdit()
        self.client_input.setPlaceholderText("Optional - Client or organization name")
        self.client_input.setStyleSheet(input_style)
        form.addRow("Client Name", self.client_input)
        
        # Description
        self.desc_input = QTextEdit()
        self.desc_input.setPlaceholderText("Describe the scope and objectives of this project...")
        self.desc_input.setMaximumHeight(100)
        self.desc_input.setStyleSheet(input_style)
        form.addRow("Description", self.desc_input)
        
        # Project directory
        dir_layout = QHBoxLayout()
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText(os.path.expanduser("~/HydraRecon_Projects"))
        self.dir_input.setText(os.path.expanduser("~/HydraRecon_Projects"))
        self.dir_input.setStyleSheet(input_style)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px 20px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        browse_btn.clicked.connect(self._browse_directory)
        
        dir_layout.addWidget(self.dir_input)
        dir_layout.addWidget(browse_btn)
        form.addRow("Save Location", dir_layout)
        
        layout.addLayout(form)
        
        # Options
        options_group = QFrame()
        options_group.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        options_layout = QVBoxLayout(options_group)
        options_layout.setContentsMargins(16, 16, 16, 16)
        options_layout.setSpacing(8)
        
        options_label = QLabel("Options")
        options_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        options_layout.addWidget(options_label)
        
        self.create_structure = QCheckBox("Create default folder structure")
        self.create_structure.setChecked(True)
        self.create_structure.setStyleSheet("color: #e6e6e6;")
        options_layout.addWidget(self.create_structure)
        
        self.import_targets = QCheckBox("Import targets from file after creation")
        self.import_targets.setStyleSheet("color: #e6e6e6;")
        options_layout.addWidget(self.import_targets)
        
        layout.addWidget(options_group)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px 24px;
                color: #e6e6e6;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        cancel_btn.clicked.connect(self.reject)
        
        create_btn = QPushButton("Create Project")
        create_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        create_btn.clicked.connect(self._create_project)
        
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(create_btn)
        
        layout.addLayout(button_layout)
    
    def _browse_directory(self):
        """Browse for directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Project Directory", self.dir_input.text()
        )
        if directory:
            self.dir_input.setText(directory)
    
    def _create_project(self):
        """Create the project"""
        name = self.name_input.text().strip()
        
        if not name:
            QMessageBox.warning(self, "Warning", "Please enter a project name.")
            return
        
        project_data = {
            'name': name,
            'type': self.type_combo.currentText(),
            'client': self.client_input.text().strip(),
            'description': self.desc_input.toPlainText(),
            'directory': self.dir_input.text(),
            'created': datetime.now().isoformat(),
            'create_structure': self.create_structure.isChecked(),
            'import_targets': self.import_targets.isChecked()
        }
        
        # Create project directory
        project_dir = os.path.join(project_data['directory'], name.replace(' ', '_'))
        os.makedirs(project_dir, exist_ok=True)
        
        if project_data['create_structure']:
            subdirs = ['scans', 'reports', 'evidence', 'notes', 'wordlists']
            for subdir in subdirs:
                os.makedirs(os.path.join(project_dir, subdir), exist_ok=True)
        
        project_data['path'] = project_dir
        
        self.projectCreated.emit(project_data)
        self.accept()


class OpenProjectDialog(QDialog):
    """Dialog for opening an existing project"""
    
    projectOpened = pyqtSignal(dict)
    
    def __init__(self, recent_projects=None, parent=None):
        super().__init__(parent)
        self.recent_projects = recent_projects or []
        self.setWindowTitle("Open Project")
        self.setMinimumSize(600, 500)
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
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(24)
        
        # Header
        header = QLabel("📂 Open Project")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ff88;")
        layout.addWidget(header)
        
        # Recent projects
        recent_label = QLabel("Recent Projects")
        recent_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(recent_label)
        
        self.project_list = QListWidget()
        self.project_list.setStyleSheet("""
            QListWidget {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 16px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:hover {
                background-color: #21262d;
            }
            QListWidget::item:selected {
                background-color: #238636;
            }
        """)
        self.project_list.itemDoubleClicked.connect(self._open_selected)
        
        # Add recent projects
        if self.recent_projects:
            for project in self.recent_projects:
                item = QListWidgetItem(f"📁 {project.get('name', 'Unknown')}")
                item.setData(Qt.ItemDataRole.UserRole, project)
                item.setToolTip(project.get('path', ''))
                self.project_list.addItem(item)
        else:
            item = QListWidgetItem("No recent projects")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.project_list.addItem(item)
        
        layout.addWidget(self.project_list)
        
        # Browse button
        browse_layout = QHBoxLayout()
        
        browse_btn = QPushButton("📁 Browse for Project...")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 14px 24px;
                color: #e6e6e6;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        browse_btn.clicked.connect(self._browse_project)
        
        browse_layout.addWidget(browse_btn)
        browse_layout.addStretch()
        
        layout.addLayout(browse_layout)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px 24px;
                color: #e6e6e6;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        cancel_btn.clicked.connect(self.reject)
        
        open_btn = QPushButton("Open Project")
        open_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        open_btn.clicked.connect(self._open_selected)
        
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(open_btn)
        
        layout.addLayout(button_layout)
    
    def _browse_project(self):
        """Browse for project directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Project Directory",
            os.path.expanduser("~/HydraRecon_Projects")
        )
        if directory:
            project_data = {
                'name': os.path.basename(directory),
                'path': directory,
                'opened': datetime.now().isoformat()
            }
            self.projectOpened.emit(project_data)
            self.accept()
    
    def _open_selected(self):
        """Open selected project"""
        selected = self.project_list.selectedItems()
        if selected:
            project_data = selected[0].data(Qt.ItemDataRole.UserRole)
            if project_data:
                self.projectOpened.emit(project_data)
                self.accept()


class AboutDialog(QDialog):
    """About dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About HydraRecon")
        self.setFixedSize(500, 400)
        self.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
            }
        """)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Logo
        logo = QLabel("🔒")
        logo.setFont(QFont("Segoe UI", 64))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)
        
        # Name
        name = QLabel("HydraRecon")
        name.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        name.setStyleSheet("color: #00ff88;")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name)
        
        # Version
        version = QLabel("Version 1.0.0")
        version.setStyleSheet("color: #8b949e; font-size: 14px;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)
        
        # Description
        desc = QLabel("Enterprise Security Assessment Suite\nCombining Nmap, Hydra, and OSINT")
        desc.setStyleSheet("color: #e6e6e6; font-size: 14px;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        layout.addStretch()
        
        # Copyright
        copyright_label = QLabel("© 2024 HydraRecon. All rights reserved.")
        copyright_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(copyright_label)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 12px 32px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignCenter)


class TargetImportDialog(QDialog):
    """Dialog for importing targets"""
    
    targetsImported = pyqtSignal(list)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import Targets")
        self.setMinimumSize(500, 400)
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
        
        # Header
        header = QLabel("Import Targets")
        header.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Info
        info = QLabel("Enter targets below (one per line) or import from a file.\nSupported: IP addresses, domains, CIDR ranges, URLs")
        info.setStyleSheet("color: #8b949e;")
        layout.addWidget(info)
        
        # Text area
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText("192.168.1.1\nexample.com\n10.0.0.0/24\nhttps://target.com")
        self.targets_input.setStyleSheet("""
            QTextEdit {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                color: #e6e6e6;
                font-family: monospace;
            }
        """)
        layout.addWidget(self.targets_input)
        
        # Import from file
        file_layout = QHBoxLayout()
        
        import_file_btn = QPushButton("📁 Import from File...")
        import_file_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        import_file_btn.clicked.connect(self._import_from_file)
        
        file_layout.addWidget(import_file_btn)
        file_layout.addStretch()
        
        layout.addLayout(file_layout)
        
        # Options
        self.validate_targets = QCheckBox("Validate targets before importing")
        self.validate_targets.setChecked(True)
        self.validate_targets.setStyleSheet("color: #e6e6e6;")
        layout.addWidget(self.validate_targets)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        cancel_btn.clicked.connect(self.reject)
        
        import_btn = QPushButton("Import")
        import_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        import_btn.clicked.connect(self._import_targets)
        
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(import_btn)
        
        layout.addLayout(button_layout)
    
    def _import_from_file(self):
        """Import targets from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Targets", "",
            "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                self.targets_input.setPlainText(content)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to read file: {e}")
    
    def _import_targets(self):
        """Import the targets"""
        text = self.targets_input.toPlainText()
        targets = []
        
        for line in text.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
        
        if targets:
            self.targetsImported.emit(targets)
            self.accept()
        else:
            QMessageBox.warning(self, "Warning", "No targets to import.")
