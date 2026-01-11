#!/usr/bin/env python3
"""
HydraRecon Lite Window
═══════════════════════════════════════════════════════════════════════════════
Lightweight main window with essential features only.
Loads fast and uses minimal memory.
═══════════════════════════════════════════════════════════════════════════════
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QFrame, QLabel, QPushButton, QSplitter, QStatusBar, QTabWidget,
    QMessageBox, QScrollArea, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QIcon

from .themes import DARK_THEME


class HydraReconLiteWindow(QMainWindow):
    """Lightweight main window for HydraRecon"""
    
    # Only load essential pages
    LITE_PAGES = [
        ("dashboard", "🏠 Dashboard", "DashboardPage"),
        ("nmap", "🔍 Network Scan", "NmapPage"),
        ("hydra", "🔓 Credentials", "HydraPage"),
        ("osint", "🌐 OSINT", "OSINTPage"),
        ("targets", "🎯 Targets", "TargetsPage"),
        ("reports", "📊 Reports", "ReportsPage"),
        ("settings", "⚙️ Settings", "SettingsPage"),
    ]
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.pages = {}
        
        self._setup_ui()
        self._apply_theme()
        
    def _setup_ui(self):
        """Setup the lite UI"""
        self.setWindowTitle("HydraRecon Lite - Security Assessment Suite")
        self.setMinimumSize(1200, 800)
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        
        # Main layout
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Sidebar
        sidebar = self._create_sidebar()
        layout.addWidget(sidebar)
        
        # Content area
        self.content_stack = QStackedWidget()
        layout.addWidget(self.content_stack, stretch=1)
        
        # Load lite pages
        self._load_pages()
        
        # Status bar
        self.statusBar().showMessage("HydraRecon Lite Mode - Ready")
        
    def _create_sidebar(self) -> QFrame:
        """Create the navigation sidebar"""
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border-right: 1px solid #21262d;
            }
        """)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(8, 16, 8, 16)
        layout.setSpacing(4)
        
        # Logo/Title
        title = QLabel("⚡ HydraRecon")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88; padding: 8px;")
        layout.addWidget(title)
        
        subtitle = QLabel("LITE MODE")
        subtitle.setStyleSheet("color: #8b949e; padding-left: 8px; font-size: 11px;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(16)
        
        # Navigation list
        self.nav_list = QListWidget()
        self.nav_list.setStyleSheet("""
            QListWidget {
                background: transparent;
                border: none;
                outline: none;
            }
            QListWidget::item {
                color: #c9d1d9;
                padding: 12px 16px;
                border-radius: 6px;
                margin: 2px 0;
            }
            QListWidget::item:hover {
                background: rgba(255, 255, 255, 0.05);
            }
            QListWidget::item:selected {
                background: rgba(0, 255, 136, 0.15);
                color: #00ff88;
            }
        """)
        
        for page_id, label, _ in self.LITE_PAGES:
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, page_id)
            item.setSizeHint(QSize(0, 44))
            self.nav_list.addItem(item)
        
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        layout.addWidget(self.nav_list)
        
        layout.addStretch()
        
        # Version info
        version = QLabel("v1.0.0 Lite")
        version.setStyleSheet("color: #484f58; font-size: 10px; padding: 8px;")
        layout.addWidget(version)
        
        return sidebar
    
    def _load_pages(self):
        """Load only essential pages"""
        for page_id, label, class_name in self.LITE_PAGES:
            try:
                page = self._create_page(page_id, class_name)
                self.pages[page_id] = page
                self.content_stack.addWidget(page)
            except Exception as e:
                # Create placeholder for failed pages
                placeholder = QLabel(f"Failed to load {label}:\n{str(e)}")
                placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
                placeholder.setStyleSheet("color: #f85149; font-size: 14px;")
                self.pages[page_id] = placeholder
                self.content_stack.addWidget(placeholder)
        
        # Select first page
        self.nav_list.setCurrentRow(0)
    
    def _create_page(self, page_id: str, class_name: str) -> QWidget:
        """Dynamically import and create a page"""
        module_map = {
            "DashboardPage": "gui.pages.dashboard",
            "NmapPage": "gui.pages.nmap_page",
            "HydraPage": "gui.pages.hydra_page",
            "OSINTPage": "gui.pages.osint_page",
            "TargetsPage": "gui.pages.targets_page",
            "ReportsPage": "gui.pages.reports_page",
            "SettingsPage": "gui.pages.settings_page",
        }
        
        module_name = module_map.get(class_name)
        if not module_name:
            raise ImportError(f"Unknown page: {class_name}")
        
        import importlib
        module = importlib.import_module(module_name)
        page_class = getattr(module, class_name)
        
        return page_class(self.config, self.db, self)
    
    def _on_nav_changed(self, index: int):
        """Handle navigation change"""
        if 0 <= index < len(self.LITE_PAGES):
            page_id = self.LITE_PAGES[index][0]
            if page_id in self.pages:
                self.content_stack.setCurrentWidget(self.pages[page_id])
                self.statusBar().showMessage(f"HydraRecon Lite - {self.LITE_PAGES[index][1]}")
    
    def _apply_theme(self):
        """Apply dark theme"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0d1117;
            }
            QStatusBar {
                background-color: #161b22;
                color: #8b949e;
                border-top: 1px solid #21262d;
            }
        """)
