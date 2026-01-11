"""
Plugin Manager Page
GUI for managing HydraRecon plugins
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QTreeWidget, QTreeWidgetItem,
    QGridLayout, QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
    QFormLayout, QPlainTextEdit, QFileDialog, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon
import asyncio
import json
from pathlib import Path


class PluginLoadWorker(QThread):
    """Worker thread for plugin operations"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, operation: str, plugin_id: str = None):
        super().__init__()
        self.operation = operation
        self.plugin_id = plugin_id
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.plugin_system import PluginManager
            
            async def operate():
                manager = PluginManager()
                
                if self.operation == "discover":
                    self.progress.emit("Discovering plugins...")
                    return await manager.discover_plugins()
                elif self.operation == "load":
                    self.progress.emit(f"Loading plugin {self.plugin_id}...")
                    await manager.load_plugin(self.plugin_id)
                    return []
                elif self.operation == "enable":
                    self.progress.emit(f"Enabling plugin {self.plugin_id}...")
                    await manager.enable_plugin(self.plugin_id)
                    return []
                elif self.operation == "disable":
                    self.progress.emit(f"Disabling plugin {self.plugin_id}...")
                    await manager.disable_plugin(self.plugin_id)
                    return []
                
                return []
                
            result = asyncio.run(operate())
            self.finished.emit(result if result else [])
            
        except Exception as e:
            self.error.emit(str(e))


class NewPluginDialog(QDialog):
    """Dialog for creating new plugins"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Plugin")
        self.setMinimumWidth(500)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        
        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("my-custom-plugin")
        form.addRow("Plugin ID:", self.id_input)
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("My Custom Plugin")
        form.addRow("Plugin Name:", self.name_input)
        
        self.author_input = QLineEdit()
        self.author_input.setPlaceholderText("Your Name")
        form.addRow("Author:", self.author_input)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "Scanner",
            "Exploit",
            "Reporter",
            "Integration",
            "Analyzer",
            "Visualization",
            "Automation",
            "Custom"
        ])
        form.addRow("Plugin Type:", self.type_combo)
        
        self.desc_input = QPlainTextEdit()
        self.desc_input.setMaximumHeight(80)
        self.desc_input.setPlaceholderText("Description of your plugin...")
        form.addRow("Description:", self.desc_input)
        
        layout.addLayout(form)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_plugin_info(self) -> dict:
        return {
            'id': self.id_input.text(),
            'name': self.name_input.text(),
            'author': self.author_input.text(),
            'type': self.type_combo.currentText().upper(),
            'description': self.desc_input.toPlainText()
        }


class PluginCard(QFrame):
    """Widget representing a single plugin"""
    
    enable_clicked = pyqtSignal(str)
    disable_clicked = pyqtSignal(str)
    configure_clicked = pyqtSignal(str)
    uninstall_clicked = pyqtSignal(str)
    
    def __init__(self, plugin_info: dict, parent=None):
        super().__init__(parent)
        self.plugin_info = plugin_info
        self._setup_ui()
    
    def _setup_ui(self):
        self.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 10px;
            }
            QFrame:hover {
                border-color: #1f6feb;
            }
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Icon
        icon_label = QLabel(self._get_type_icon())
        icon_label.setStyleSheet("""
            font-size: 32px;
            padding: 10px;
        """)
        layout.addWidget(icon_label)
        
        # Info section
        info_layout = QVBoxLayout()
        info_layout.setSpacing(4)
        
        # Title row
        title_row = QHBoxLayout()
        
        name = QLabel(self.plugin_info.get('name', 'Unknown'))
        name.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        title_row.addWidget(name)
        
        version = QLabel(f"v{self.plugin_info.get('version', '1.0.0')}")
        version.setStyleSheet("""
            font-size: 11px;
            color: #8b949e;
            background: #21262d;
            padding: 2px 8px;
            border-radius: 4px;
        """)
        title_row.addWidget(version)
        title_row.addStretch()
        
        info_layout.addLayout(title_row)
        
        # Description
        desc = QLabel(self.plugin_info.get('description', 'No description'))
        desc.setStyleSheet("color: #8b949e; font-size: 12px;")
        desc.setWordWrap(True)
        info_layout.addWidget(desc)
        
        # Meta info
        meta = QLabel(f"By {self.plugin_info.get('author', 'Unknown')} • Type: {self.plugin_info.get('type', 'custom')}")
        meta.setStyleSheet("color: #6e7681; font-size: 11px;")
        info_layout.addWidget(meta)
        
        layout.addLayout(info_layout, stretch=1)
        
        # Action buttons
        actions_layout = QVBoxLayout()
        actions_layout.setSpacing(8)
        
        if self.plugin_info.get('enabled', False):
            disable_btn = QPushButton("Disable")
            disable_btn.setStyleSheet("""
                QPushButton {
                    background: #da3633;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:hover { background: #f85149; }
            """)
            disable_btn.clicked.connect(
                lambda: self.disable_clicked.emit(self.plugin_info.get('id'))
            )
            actions_layout.addWidget(disable_btn)
        else:
            enable_btn = QPushButton("Enable")
            enable_btn.setStyleSheet("""
                QPushButton {
                    background: #238636;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:hover { background: #2ea043; }
            """)
            enable_btn.clicked.connect(
                lambda: self.enable_clicked.emit(self.plugin_info.get('id'))
            )
            actions_layout.addWidget(enable_btn)
        
        config_btn = QPushButton("⚙️")
        config_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
            }
            QPushButton:hover { background: #30363d; }
        """)
        config_btn.clicked.connect(
            lambda: self.configure_clicked.emit(self.plugin_info.get('id'))
        )
        actions_layout.addWidget(config_btn)
        
        layout.addLayout(actions_layout)
    
    def _get_type_icon(self) -> str:
        icons = {
            'scanner': '🔍',
            'exploit': '💀',
            'reporter': '📊',
            'integration': '🔌',
            'analyzer': '🧠',
            'visualization': '📈',
            'automation': '⚡',
            'custom': '🔧',
        }
        plugin_type = self.plugin_info.get('type', 'custom').lower()
        return icons.get(plugin_type, '🔧')


class PluginManagerPage(QWidget):
    """Plugin Manager GUI"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.worker = None
        self.plugins = []
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #21262d;
                color: #8b949e;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #00ff88;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_installed_tab(), "📦 Installed")
        self.tabs.addTab(self._create_marketplace_tab(), "🏪 Marketplace")
        self.tabs.addTab(self._create_develop_tab(), "🛠️ Develop")
        self.tabs.addTab(self._create_hooks_tab(), "🪝 Hooks")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1f29, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔌 Plugin Manager")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        
        subtitle = QLabel("Extend HydraRecon with custom scanners, exploits, and integrations")
        subtitle.setStyleSheet("""
            font-size: 13px;
            color: #8b949e;
        """)
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Quick stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)
        
        self.stats = {
            'installed': self._create_stat_widget("Installed", "0"),
            'enabled': self._create_stat_widget("Enabled", "0"),
            'updates': self._create_stat_widget("Updates", "0"),
        }
        
        for stat in self.stats.values():
            stats_layout.addWidget(stat)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_stat_widget(self, label: str, value: str) -> QFrame:
        """Create a stat display widget"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setObjectName(f"stat_{label.lower()}")
        value_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #00ff88;
        """)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("""
            font-size: 11px;
            color: #8b949e;
        """)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(name_label)
        
        return frame
    
    def _create_installed_tab(self) -> QWidget:
        """Create installed plugins tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Controls
        controls = QHBoxLayout()
        
        search = QLineEdit()
        search.setPlaceholderText("🔍 Search plugins...")
        search.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        controls.addWidget(search)
        
        filter_combo = QComboBox()
        filter_combo.addItems(["All Types", "Scanner", "Exploit", "Reporter", "Integration"])
        filter_combo.setStyleSheet("""
            QComboBox {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
                min-width: 120px;
            }
        """)
        controls.addWidget(filter_combo)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_plugins)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
            QPushButton:hover { background: #30363d; }
        """)
        controls.addWidget(refresh_btn)
        
        install_btn = QPushButton("➕ Install Plugin")
        install_btn.clicked.connect(self._install_plugin)
        install_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:hover { background: #2ea043; }
        """)
        controls.addWidget(install_btn)
        
        layout.addLayout(controls)
        
        # Plugin list (scrollable)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        scroll_content = QWidget()
        self.plugins_layout = QVBoxLayout(scroll_content)
        self.plugins_layout.setSpacing(12)
        self.plugins_layout.addStretch()
        
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        # Add some example plugins
        self._add_example_plugins()
        
        return widget
    
    def _add_example_plugins(self):
        """Add example plugin cards"""
        example_plugins = [
            {
                'id': 'metasploit-integration',
                'name': 'Metasploit Integration',
                'version': '2.1.0',
                'description': 'Full integration with Metasploit Framework for exploit execution and session management',
                'author': 'HydraRecon Team',
                'type': 'integration',
                'enabled': True
            },
            {
                'id': 'burp-suite-sync',
                'name': 'Burp Suite Sync',
                'version': '1.5.0',
                'description': 'Sync findings and targets with Burp Suite Professional',
                'author': 'HydraRecon Team',
                'type': 'integration',
                'enabled': False
            },
            {
                'id': 'nuclei-scanner',
                'name': 'Nuclei Scanner',
                'version': '3.0.0',
                'description': 'Integration with Nuclei for template-based vulnerability scanning',
                'author': 'ProjectDiscovery',
                'type': 'scanner',
                'enabled': True
            },
            {
                'id': 'ai-vuln-analyzer',
                'name': 'AI Vulnerability Analyzer',
                'version': '1.0.0',
                'description': 'Uses machine learning to prioritize and analyze vulnerabilities',
                'author': 'HydraRecon Team',
                'type': 'analyzer',
                'enabled': False
            },
        ]
        
        for plugin in example_plugins:
            card = PluginCard(plugin)
            card.enable_clicked.connect(self._enable_plugin)
            card.disable_clicked.connect(self._disable_plugin)
            card.configure_clicked.connect(self._configure_plugin)
            self.plugins_layout.insertWidget(self.plugins_layout.count() - 1, card)
    
    def _create_marketplace_tab(self) -> QWidget:
        """Create marketplace tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Categories
        categories = QHBoxLayout()
        
        cat_buttons = [
            ("All", "#1f6feb"),
            ("Scanners", "#3fb950"),
            ("Exploits", "#f85149"),
            ("Reporters", "#8957e5"),
            ("Integrations", "#f0883e"),
        ]
        
        for text, color in cat_buttons:
            btn = QPushButton(text)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {color}20;
                    color: {color};
                    border: 1px solid {color};
                    border-radius: 6px;
                    padding: 8px 16px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background: {color}40;
                }}
            """)
            categories.addWidget(btn)
        
        categories.addStretch()
        layout.addLayout(categories)
        
        # Featured plugins
        featured_label = QLabel("🌟 Featured Plugins")
        featured_label.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #e6e6e6;
            padding: 10px 0;
        """)
        layout.addWidget(featured_label)
        
        # Marketplace grid
        marketplace_content = QLabel("Coming soon: Browse and install plugins from the HydraRecon marketplace")
        marketplace_content.setAlignment(Qt.AlignmentFlag.AlignCenter)
        marketplace_content.setStyleSheet("""
            color: #8b949e;
            padding: 50px;
            font-size: 14px;
        """)
        layout.addWidget(marketplace_content)
        layout.addStretch()
        
        return widget
    
    def _create_develop_tab(self) -> QWidget:
        """Create plugin development tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        
        actions_layout = QHBoxLayout(actions_group)
        
        new_plugin_btn = QPushButton("📝 Create New Plugin")
        new_plugin_btn.clicked.connect(self._create_new_plugin)
        new_plugin_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 16px 24px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover { background: #2ea043; }
        """)
        
        import_btn = QPushButton("📥 Import Plugin")
        import_btn.clicked.connect(self._import_plugin)
        import_btn.setStyleSheet(new_plugin_btn.styleSheet().replace("#238636", "#1f6feb").replace("#2ea043", "#388bfd"))
        
        docs_btn = QPushButton("📚 Documentation")
        docs_btn.setStyleSheet(new_plugin_btn.styleSheet().replace("#238636", "#6e40c9").replace("#2ea043", "#8957e5"))
        
        actions_layout.addWidget(new_plugin_btn)
        actions_layout.addWidget(import_btn)
        actions_layout.addWidget(docs_btn)
        actions_layout.addStretch()
        
        layout.addWidget(actions_group)
        
        # Plugin template preview
        template_group = QGroupBox("Plugin Template")
        template_group.setStyleSheet(actions_group.styleSheet())
        
        template_layout = QVBoxLayout(template_group)
        
        self.template_preview = QPlainTextEdit()
        self.template_preview.setReadOnly(True)
        self.template_preview.setStyleSheet("""
            QPlainTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #e6e6e6;
                font-family: monospace;
                font-size: 12px;
            }
        """)
        
        template_code = '''from core.plugin_system import ScannerPlugin, PluginInfo, PluginType

class MyScanner(ScannerPlugin):
    """Custom scanner plugin"""
    
    PLUGIN_INFO = PluginInfo(
        id="my-scanner",
        name="My Scanner",
        version="1.0.0",
        description="A custom scanner plugin",
        author="Your Name",
        plugin_type=PluginType.SCANNER,
        entry_point="plugin.MyScanner"
    )
    
    async def initialize(self) -> bool:
        self.log("Scanner initialized")
        return True
    
    async def shutdown(self) -> None:
        self.log("Scanner shutting down")
    
    async def scan(self, target: str, options: dict) -> dict:
        self.log(f"Scanning {target}")
        # Your scanning logic here
        return {"status": "complete", "findings": []}
    
    def get_scan_options(self) -> list:
        return [
            {"name": "depth", "type": "int", "default": 3},
            {"name": "timeout", "type": "int", "default": 30}
        ]'''
        
        self.template_preview.setPlainText(template_code)
        template_layout.addWidget(self.template_preview)
        
        layout.addWidget(template_group)
        
        return widget
    
    def _create_hooks_tab(self) -> QWidget:
        """Create hooks documentation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Hooks table
        hooks_table = QTableWidget()
        hooks_table.setColumnCount(4)
        hooks_table.setHorizontalHeaderLabels([
            "Hook Name", "Description", "Parameters", "Async"
        ])
        hooks_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        hooks_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QTableWidget::item {
                padding: 10px;
                color: #e6e6e6;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
        """)
        
        hooks = [
            ("before_scan", "Called before a scan starts", "target, options", "✓"),
            ("after_scan", "Called after a scan completes", "target, results", "✓"),
            ("on_finding", "Called when a finding is discovered", "finding", "✓"),
            ("on_target_added", "Called when a new target is added", "target", ""),
            ("before_report", "Called before report generation", "data", "✓"),
            ("after_report", "Called after report generation", "report, format", "✓"),
            ("on_startup", "Called when application starts", "", "✓"),
            ("on_shutdown", "Called when application shuts down", "", "✓"),
        ]
        
        hooks_table.setRowCount(len(hooks))
        for i, (name, desc, params, is_async) in enumerate(hooks):
            hooks_table.setItem(i, 0, QTableWidgetItem(name))
            hooks_table.setItem(i, 1, QTableWidgetItem(desc))
            hooks_table.setItem(i, 2, QTableWidgetItem(params))
            
            async_item = QTableWidgetItem(is_async)
            if is_async:
                async_item.setForeground(QColor("#3fb950"))
            hooks_table.setItem(i, 3, async_item)
        
        layout.addWidget(hooks_table)
        
        return widget
    
    def _connect_signals(self):
        """Connect widget signals"""
        pass
    
    def _refresh_plugins(self):
        """Refresh plugin list"""
        self.worker = PluginLoadWorker("discover")
        self.worker.finished.connect(self._on_plugins_loaded)
        self.worker.start()
    
    def _on_plugins_loaded(self, plugins: list):
        """Handle loaded plugins"""
        self.plugins = plugins
        # Update UI with discovered plugins
    
    def _install_plugin(self):
        """Open install plugin dialog"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Plugin", "", "Plugin Files (*.zip);;All files (*)"
        )
        if file_path:
            # Install the plugin
            pass
    
    def _enable_plugin(self, plugin_id: str):
        """Enable a plugin"""
        self.worker = PluginLoadWorker("enable", plugin_id)
        self.worker.start()
    
    def _disable_plugin(self, plugin_id: str):
        """Disable a plugin"""
        self.worker = PluginLoadWorker("disable", plugin_id)
        self.worker.start()
    
    def _configure_plugin(self, plugin_id: str):
        """Open plugin configuration dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton, QHBoxLayout, QMessageBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Configure Plugin: {plugin_id}")
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout(dialog)
        form = QFormLayout()
        
        # Get current config if exists
        config_path = Path(f"plugins/{plugin_id}/config.json")
        current_config = {}
        if config_path.exists():
            try:
                import json
                current_config = json.loads(config_path.read_text())
            except Exception:
                pass
        
        # Config editor
        config_edit = QTextEdit()
        config_edit.setPlainText(json.dumps(current_config, indent=2) if current_config else '{}')
        config_edit.setMinimumHeight(200)
        form.addRow("Configuration (JSON):", config_edit)
        
        layout.addLayout(form)
        
        # Buttons
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        
        def save_config():
            try:
                import json
                new_config = json.loads(config_edit.toPlainText())
                config_path.parent.mkdir(parents=True, exist_ok=True)
                config_path.write_text(json.dumps(new_config, indent=2))
                QMessageBox.information(dialog, "Success", "Configuration saved")
                dialog.accept()
            except json.JSONDecodeError as e:
                QMessageBox.warning(dialog, "Invalid JSON", str(e))
        
        save_btn.clicked.connect(save_config)
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        dialog.exec()
    
    def _create_new_plugin(self):
        """Create a new plugin"""
        dialog = NewPluginDialog(self)
        if dialog.exec():
            info = dialog.get_plugin_info()
            # Create plugin from template
            self._generate_plugin(info)
    
    def _generate_plugin(self, info: dict):
        """Generate plugin files from template"""
        import sys
        sys.path.insert(0, '..')
        from core.plugin_system import create_plugin_template
        
        template = create_plugin_template(
            info['id'],
            info['name'],
            info['description'],
            info['author'],
            info['type']
        )
        
        # Show generated template
        self.template_preview.setPlainText(template)
        self.tabs.setCurrentIndex(2)  # Switch to develop tab
    
    def _import_plugin(self):
        """Import a plugin from disk"""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Plugin Folder"
        )
        if folder:
            # Import the plugin
            pass
