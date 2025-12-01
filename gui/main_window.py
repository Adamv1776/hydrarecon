#!/usr/bin/env python3
"""
HydraRecon Main Window
The primary application window with modern sidebar navigation.
"""

import asyncio
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QFrame, QLabel, QPushButton, QSplitter, QToolBar, QStatusBar,
    QMenuBar, QMenu, QMessageBox, QFileDialog, QApplication
)
from PyQt6.QtCore import Qt, QSize, QTimer
from PyQt6.QtGui import QAction, QIcon, QFont, QKeySequence

from .themes import DARK_THEME, COLORS
from .widgets import NavButton, GlowingButton
from .pages.dashboard import DashboardPage
from .pages.nmap_page import NmapPage
from .pages.hydra_page import HydraPage
from .pages.osint_page import OSINTPage
from .pages.targets_page import TargetsPage
from .pages.credentials_page import CredentialsPage
from .pages.vulnerabilities_page import VulnerabilitiesPage
from .pages.reports_page import ReportsPage
from .pages.settings_page import SettingsPage
from .pages.automation_page import AutomationPage
from .pages.attack_surface_page import AttackSurfacePage


class HydraReconMainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, config, db):
        super().__init__()
        self.config = config
        self.db = db
        self.current_project = None
        
        self._setup_window()
        self._setup_ui()
        self._setup_menubar()
        self._setup_statusbar()
        self._connect_signals()
        self._apply_theme()
    
    def _setup_window(self):
        """Configure main window properties"""
        self.setWindowTitle("HydraRecon - Enterprise Security Assessment Suite")
        self.setMinimumSize(1400, 900)
        self.resize(1600, 1000)
        
        # Center on screen
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
    
    def _setup_ui(self):
        """Setup the main UI layout"""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        self.sidebar = self._create_sidebar()
        main_layout.addWidget(self.sidebar)
        
        # Content area
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack, stretch=1)
        
        # Initialize pages
        self._init_pages()
    
    def _create_sidebar(self) -> QWidget:
        """Create the navigation sidebar"""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(280)
        sidebar.setStyleSheet("""
            QFrame#sidebar {
                background-color: #0d1117;
                border-right: 1px solid #21262d;
            }
        """)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 20, 16, 20)
        layout.setSpacing(8)
        
        # Logo/Brand section
        brand_layout = QHBoxLayout()
        brand_layout.setSpacing(12)
        
        # Logo placeholder
        logo = QLabel("⚡")
        logo.setStyleSheet("""
            font-size: 32px;
            color: #00ff88;
        """)
        
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        
        title = QLabel("HydraRecon")
        title.setStyleSheet("""
            font-size: 22px;
            font-weight: 700;
            color: #e6e6e6;
        """)
        
        subtitle = QLabel("Security Suite v1.0")
        subtitle.setStyleSheet("""
            font-size: 11px;
            color: #8b949e;
        """)
        
        brand_text.addWidget(title)
        brand_text.addWidget(subtitle)
        
        brand_layout.addWidget(logo)
        brand_layout.addLayout(brand_text)
        brand_layout.addStretch()
        
        layout.addLayout(brand_layout)
        layout.addSpacing(24)
        
        # Section: Main
        section_main = QLabel("MAIN")
        section_main.setStyleSheet("""
            font-size: 11px;
            font-weight: 700;
            color: #8b949e;
            letter-spacing: 1px;
            padding-left: 12px;
        """)
        layout.addWidget(section_main)
        layout.addSpacing(8)
        
        # Navigation buttons
        self.nav_buttons = {}
        
        nav_items = [
            ("dashboard", "Dashboard", "🏠"),
            ("nmap", "Nmap Scanner", "🔍"),
            ("hydra", "Hydra Attack", "🔓"),
            ("osint", "OSINT", "🌐"),
            ("automation", "Automation", "⚡"),
            ("attack_surface", "Attack Surface", "🗺️"),
        ]
        
        for key, text, icon in nav_items:
            btn = NavButton(text, icon_char=icon)
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))
            self.nav_buttons[key] = btn
            layout.addWidget(btn)
        
        layout.addSpacing(16)
        
        # Section: Data
        section_data = QLabel("DATA")
        section_data.setStyleSheet("""
            font-size: 11px;
            font-weight: 700;
            color: #8b949e;
            letter-spacing: 1px;
            padding-left: 12px;
        """)
        layout.addWidget(section_data)
        layout.addSpacing(8)
        
        data_items = [
            ("targets", "Targets", "🎯"),
            ("credentials", "Credentials", "🔑"),
            ("vulnerabilities", "Vulnerabilities", "⚠️"),
            ("reports", "Reports", "📊"),
        ]
        
        for key, text, icon in data_items:
            btn = NavButton(text, icon_char=icon)
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))
            self.nav_buttons[key] = btn
            layout.addWidget(btn)
        
        layout.addStretch()
        
        # Section: System
        section_system = QLabel("SYSTEM")
        section_system.setStyleSheet("""
            font-size: 11px;
            font-weight: 700;
            color: #8b949e;
            letter-spacing: 1px;
            padding-left: 12px;
        """)
        layout.addWidget(section_system)
        layout.addSpacing(8)
        
        # Settings button
        settings_btn = NavButton("Settings", icon_char="⚙️")
        settings_btn.clicked.connect(lambda: self._navigate("settings"))
        self.nav_buttons["settings"] = settings_btn
        layout.addWidget(settings_btn)
        
        # Project info at bottom
        layout.addSpacing(16)
        
        project_frame = QFrame()
        project_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
            }
        """)
        project_layout = QVBoxLayout(project_frame)
        project_layout.setContentsMargins(12, 12, 12, 12)
        project_layout.setSpacing(4)
        
        self.project_label = QLabel("No Project")
        self.project_label.setStyleSheet("""
            font-size: 13px;
            font-weight: 600;
            color: #e6e6e6;
        """)
        
        self.project_status = QLabel("Create or open a project")
        self.project_status.setStyleSheet("""
            font-size: 11px;
            color: #8b949e;
        """)
        
        project_layout.addWidget(self.project_label)
        project_layout.addWidget(self.project_status)
        
        layout.addWidget(project_frame)
        
        # Set default active
        self.nav_buttons["dashboard"].setChecked(True)
        
        return sidebar
    
    def _init_pages(self):
        """Initialize all pages"""
        self.pages = {
            "dashboard": DashboardPage(self.config, self.db, self),
            "nmap": NmapPage(self.config, self.db, self),
            "hydra": HydraPage(self.config, self.db, self),
            "osint": OSINTPage(self.config, self.db, self),
            "targets": TargetsPage(self.config, self.db, self),
            "credentials": CredentialsPage(self.config, self.db, self),
            "vulnerabilities": VulnerabilitiesPage(self.config, self.db, self),
            "reports": ReportsPage(self.config, self.db, self),
            "settings": SettingsPage(self.config, self.db, self),
            "automation": AutomationPage(self),
            "attack_surface": AttackSurfacePage(self),
        }
        
        for page in self.pages.values():
            self.content_stack.addWidget(page)
    
    def _setup_menubar(self):
        """Setup the menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_project = QAction("New Project", self)
        new_project.setShortcut(QKeySequence.StandardKey.New)
        new_project.triggered.connect(self._new_project)
        file_menu.addAction(new_project)
        
        open_project = QAction("Open Project", self)
        open_project.setShortcut(QKeySequence.StandardKey.Open)
        open_project.triggered.connect(self._open_project)
        file_menu.addAction(open_project)
        
        file_menu.addSeparator()
        
        import_action = QAction("Import Scan Results", self)
        import_action.triggered.connect(self._import_results)
        file_menu.addAction(import_action)
        
        export_action = QAction("Export Project", self)
        export_action.triggered.connect(self._export_project)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan menu
        scan_menu = menubar.addMenu("Scan")
        
        quick_scan = QAction("Quick Scan", self)
        quick_scan.setShortcut("Ctrl+Shift+Q")
        quick_scan.triggered.connect(lambda: self._navigate("nmap"))
        scan_menu.addAction(quick_scan)
        
        full_scan = QAction("Full Audit", self)
        full_scan.setShortcut("Ctrl+Shift+F")
        scan_menu.addAction(full_scan)
        
        scan_menu.addSeparator()
        
        vuln_scan = QAction("Vulnerability Scan", self)
        scan_menu.addAction(vuln_scan)
        
        brute_force = QAction("Brute Force Attack", self)
        brute_force.triggered.connect(lambda: self._navigate("hydra"))
        scan_menu.addAction(brute_force)
        
        osint_gather = QAction("OSINT Gathering", self)
        osint_gather.triggered.connect(lambda: self._navigate("osint"))
        scan_menu.addAction(osint_gather)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        dns_lookup = QAction("DNS Lookup", self)
        tools_menu.addAction(dns_lookup)
        
        whois_lookup = QAction("WHOIS Lookup", self)
        tools_menu.addAction(whois_lookup)
        
        port_checker = QAction("Port Checker", self)
        tools_menu.addAction(port_checker)
        
        tools_menu.addSeparator()
        
        hash_analyzer = QAction("Hash Analyzer", self)
        tools_menu.addAction(hash_analyzer)
        
        encoder = QAction("Encoder/Decoder", self)
        tools_menu.addAction(encoder)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        toggle_sidebar = QAction("Toggle Sidebar", self)
        toggle_sidebar.setShortcut("Ctrl+B")
        toggle_sidebar.triggered.connect(self._toggle_sidebar)
        view_menu.addAction(toggle_sidebar)
        
        view_menu.addSeparator()
        
        zoom_in = QAction("Zoom In", self)
        zoom_in.setShortcut(QKeySequence.StandardKey.ZoomIn)
        view_menu.addAction(zoom_in)
        
        zoom_out = QAction("Zoom Out", self)
        zoom_out.setShortcut(QKeySequence.StandardKey.ZoomOut)
        view_menu.addAction(zoom_out)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        documentation = QAction("Documentation", self)
        documentation.setShortcut(QKeySequence.StandardKey.HelpContents)
        help_menu.addAction(documentation)
        
        shortcuts = QAction("Keyboard Shortcuts", self)
        help_menu.addAction(shortcuts)
        
        help_menu.addSeparator()
        
        check_updates = QAction("Check for Updates", self)
        help_menu.addAction(check_updates)
        
        about = QAction("About HydraRecon", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)
    
    def _setup_statusbar(self):
        """Setup the status bar"""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        
        # Status sections
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #8b949e;")
        
        self.scan_status = QLabel("")
        self.scan_status.setStyleSheet("color: #00ff88;")
        
        self.connection_status = QLabel("● Connected")
        self.connection_status.setStyleSheet("color: #238636;")
        
        self.statusbar.addWidget(self.status_label)
        self.statusbar.addPermanentWidget(self.scan_status)
        self.statusbar.addPermanentWidget(self.connection_status)
    
    def _connect_signals(self):
        """Connect signals between components"""
        pass
    
    def _apply_theme(self):
        """Apply the dark theme"""
        self.setStyleSheet(DARK_THEME)
    
    def _navigate(self, page_key: str):
        """Navigate to a specific page"""
        # Update nav buttons
        for key, btn in self.nav_buttons.items():
            btn.setChecked(key == page_key)
        
        # Show page
        if page_key in self.pages:
            self.content_stack.setCurrentWidget(self.pages[page_key])
    
    def _toggle_sidebar(self):
        """Toggle sidebar visibility"""
        self.sidebar.setVisible(not self.sidebar.isVisible())
    
    def _new_project(self):
        """Create a new project"""
        from .dialogs import NewProjectDialog
        dialog = NewProjectDialog(self)
        if dialog.exec():
            # Project data is emitted via signal
            pass
    
    def _open_project(self):
        """Open an existing project"""
        from .dialogs import OpenProjectDialog
        dialog = OpenProjectDialog([], self)
        if dialog.exec():
            # Project data is emitted via signal
            pass
    
    def _update_project_display(self):
        """Update project display in sidebar"""
        if self.current_project:
            self.project_label.setText(self.current_project['name'])
            self.project_status.setText(f"Status: {self.current_project['status']}")
    
    def _import_results(self):
        """Import scan results from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Scan Results", "",
            "XML Files (*.xml);;JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.status_label.setText(f"Importing {file_path}...")
    
    def _export_project(self):
        """Export current project"""
        if not self.current_project:
            QMessageBox.warning(self, "Warning", "No project is currently open.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Project", f"{self.current_project['name']}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.status_label.setText(f"Exporting to {file_path}...")
    
    def _show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About HydraRecon",
            """<h2>HydraRecon v1.0</h2>
            <p>Enterprise Security Assessment Suite</p>
            <p>A professional-grade penetration testing platform combining 
            Nmap, Hydra, and comprehensive OSINT capabilities.</p>
            <p><b>Features:</b></p>
            <ul>
                <li>Advanced Nmap Integration</li>
                <li>Hydra Brute-Force Attacks</li>
                <li>Comprehensive OSINT Gathering</li>
                <li>Real-time Visualization</li>
                <li>Professional Reporting</li>
            </ul>
            <p><small>For authorized security testing only.</small></p>
            """
        )
    
    def closeEvent(self, event):
        """Handle window close"""
        reply = QMessageBox.question(
            self, "Confirm Exit",
            "Are you sure you want to exit HydraRecon?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()
