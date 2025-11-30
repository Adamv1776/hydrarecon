#!/usr/bin/env python3
"""
HydraRecon Ultimate Dark Theme
Premium cybersecurity-inspired dark theme with neon accents,
glassmorphism effects, and advanced visual styling.
"""

DARK_THEME = """
/* ==================== Global Styles ==================== */
* {
    font-family: "Segoe UI", "SF Pro Display", -apple-system, BlinkMacSystemFont, sans-serif;
}

QMainWindow, QWidget {
    background-color: #0a0e14;
    color: #e6e6e6;
    font-family: "Segoe UI", "SF Pro Display", -apple-system, sans-serif;
}

QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #0a0e14, stop:0.5 #0d1117, stop:1 #0a0e14);
    border: 1px solid #1a1f2e;
}

/* ==================== Menu Bar ==================== */
QMenuBar {
    background-color: #0d1117;
    border-bottom: 1px solid #21262d;
    padding: 4px;
}

QMenuBar::item {
    background-color: transparent;
    padding: 8px 12px;
    border-radius: 6px;
}

QMenuBar::item:selected {
    background-color: #21262d;
}

QMenu {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 8px;
}

QMenu::item {
    padding: 8px 24px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #238636;
    color: white;
}

QMenu::separator {
    height: 1px;
    background-color: #30363d;
    margin: 6px 12px;
}

/* ==================== Tool Bar ==================== */
QToolBar {
    background-color: #0d1117;
    border: none;
    border-bottom: 1px solid #21262d;
    padding: 4px;
    spacing: 4px;
}

QToolButton {
    background-color: transparent;
    border: none;
    border-radius: 6px;
    padding: 8px;
    margin: 2px;
}

QToolButton:hover {
    background-color: #21262d;
}

QToolButton:pressed {
    background-color: #30363d;
}

/* ==================== Tab Widget ==================== */
QTabWidget::pane {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    top: -1px;
}

QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    border: none;
    padding: 12px 24px;
    margin-right: 2px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}

QTabBar::tab:selected {
    background-color: #0d1117;
    color: #00ff88;
    border-bottom: 2px solid #00ff88;
}

QTabBar::tab:hover:!selected {
    background-color: #21262d;
    color: #e6e6e6;
}

/* ==================== Buttons ==================== */
QPushButton {
    background-color: #21262d;
    color: #e6e6e6;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px 20px;
    font-weight: 600;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #30363d;
    border-color: #484f58;
}

QPushButton:pressed {
    background-color: #484f58;
}

QPushButton:disabled {
    background-color: #161b22;
    color: #484f58;
    border-color: #21262d;
}

/* Primary Button */
QPushButton[class="primary"], QPushButton#primaryButton {
    background-color: #238636;
    border-color: #2ea043;
    color: white;
}

QPushButton[class="primary"]:hover, QPushButton#primaryButton:hover {
    background-color: #2ea043;
    border-color: #3fb950;
}

/* Danger Button */
QPushButton[class="danger"], QPushButton#dangerButton {
    background-color: #da3633;
    border-color: #f85149;
    color: white;
}

QPushButton[class="danger"]:hover, QPushButton#dangerButton:hover {
    background-color: #f85149;
}

/* Accent Button */
QPushButton[class="accent"], QPushButton#accentButton {
    background-color: #00ff88;
    border-color: #00ff88;
    color: #0a0e14;
}

QPushButton[class="accent"]:hover, QPushButton#accentButton:hover {
    background-color: #00cc6a;
}

/* ==================== Input Fields ==================== */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px 14px;
    color: #e6e6e6;
    selection-background-color: #238636;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, 
QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #00ff88;
    outline: none;
}

QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {
    background-color: #161b22;
    color: #484f58;
}

/* ==================== Combo Box ==================== */
QComboBox {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px 14px;
    color: #e6e6e6;
    min-width: 120px;
}

QComboBox:hover {
    border-color: #484f58;
}

QComboBox:focus {
    border-color: #00ff88;
}

QComboBox::drop-down {
    border: none;
    width: 30px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid #8b949e;
    margin-right: 10px;
}

QComboBox QAbstractItemView {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 4px;
    selection-background-color: #238636;
}

/* ==================== Lists and Trees ==================== */
QListWidget, QListView, QTreeWidget, QTreeView, QTableWidget, QTableView {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    outline: none;
    padding: 4px;
}

QListWidget::item, QListView::item, QTreeWidget::item, QTreeView::item {
    padding: 8px 12px;
    border-radius: 6px;
    margin: 2px 4px;
}

QListWidget::item:selected, QListView::item:selected,
QTreeWidget::item:selected, QTreeView::item:selected {
    background-color: #238636;
    color: white;
}

QListWidget::item:hover, QListView::item:hover,
QTreeWidget::item:hover, QTreeView::item:hover {
    background-color: #21262d;
}

QTreeWidget::branch:has-siblings:!adjoins-item {
    border-image: url(none);
}

QTreeWidget::branch:has-siblings:adjoins-item {
    border-image: url(none);
}

QTreeWidget::branch:!has-children:!has-siblings:adjoins-item {
    border-image: url(none);
}

/* Table Headers */
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    border: none;
    border-bottom: 1px solid #21262d;
    padding: 12px 16px;
    font-weight: 600;
}

QHeaderView::section:hover {
    background-color: #21262d;
}

/* ==================== Scroll Bars ==================== */
QScrollBar:vertical {
    background-color: #0d1117;
    width: 12px;
    border-radius: 6px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #30363d;
    border-radius: 6px;
    min-height: 40px;
    margin: 2px;
}

QScrollBar::handle:vertical:hover {
    background-color: #484f58;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background-color: #0d1117;
    height: 12px;
    border-radius: 6px;
    margin: 0;
}

QScrollBar::handle:horizontal {
    background-color: #30363d;
    border-radius: 6px;
    min-width: 40px;
    margin: 2px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #484f58;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* ==================== Progress Bar ==================== */
QProgressBar {
    background-color: #21262d;
    border: none;
    border-radius: 8px;
    height: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #00ff88, stop:1 #0088ff);
    border-radius: 8px;
}

/* ==================== Group Box ==================== */
QGroupBox {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 12px;
    margin-top: 20px;
    padding: 20px;
    padding-top: 30px;
    font-weight: 600;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 16px;
    padding: 0 8px;
    color: #00ff88;
    background-color: #0d1117;
}

/* ==================== Splitter ==================== */
QSplitter::handle {
    background-color: #21262d;
}

QSplitter::handle:horizontal {
    width: 2px;
}

QSplitter::handle:vertical {
    height: 2px;
}

QSplitter::handle:hover {
    background-color: #00ff88;
}

/* ==================== Status Bar ==================== */
QStatusBar {
    background-color: #0d1117;
    border-top: 1px solid #21262d;
    color: #8b949e;
    padding: 4px;
}

QStatusBar::item {
    border: none;
}

/* ==================== Tool Tips ==================== */
QToolTip {
    background-color: #161b22;
    color: #e6e6e6;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 12px;
}

/* ==================== Sliders ==================== */
QSlider::groove:horizontal {
    background-color: #21262d;
    height: 6px;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background-color: #00ff88;
    width: 18px;
    height: 18px;
    margin: -6px 0;
    border-radius: 9px;
}

QSlider::handle:horizontal:hover {
    background-color: #00cc6a;
}

QSlider::sub-page:horizontal {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #00ff88, stop:1 #0088ff);
    border-radius: 3px;
}

/* ==================== Check Box ==================== */
QCheckBox {
    spacing: 10px;
    color: #e6e6e6;
}

QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border: 2px solid #30363d;
    border-radius: 4px;
    background-color: #0d1117;
}

QCheckBox::indicator:checked {
    background-color: #238636;
    border-color: #238636;
    image: url(none);
}

QCheckBox::indicator:hover {
    border-color: #00ff88;
}

/* ==================== Radio Button ==================== */
QRadioButton {
    spacing: 10px;
    color: #e6e6e6;
}

QRadioButton::indicator {
    width: 20px;
    height: 20px;
    border: 2px solid #30363d;
    border-radius: 11px;
    background-color: #0d1117;
}

QRadioButton::indicator:checked {
    background-color: #238636;
    border-color: #238636;
}

QRadioButton::indicator:hover {
    border-color: #00ff88;
}

/* ==================== Dock Widget ==================== */
QDockWidget {
    titlebar-close-icon: url(none);
    titlebar-normal-icon: url(none);
}

QDockWidget::title {
    background-color: #161b22;
    border-bottom: 1px solid #21262d;
    padding: 10px;
    text-align: left;
}

/* ==================== Frame ==================== */
QFrame[class="card"] {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 16px;
}

/* ==================== Custom Classes ==================== */
/* Sidebar */
QWidget#sidebar {
    background-color: #0d1117;
    border-right: 1px solid #21262d;
}

/* Header */
QLabel#headerTitle {
    font-size: 24px;
    font-weight: 700;
    color: #e6e6e6;
}

QLabel#headerSubtitle {
    font-size: 14px;
    color: #8b949e;
}

/* Stats Cards */
QFrame#statsCard {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 16px;
}

QLabel#statsValue {
    font-size: 32px;
    font-weight: 700;
    color: #00ff88;
}

QLabel#statsLabel {
    font-size: 12px;
    color: #8b949e;
    text-transform: uppercase;
}

/* Severity Badges */
QLabel#severityCritical {
    background-color: #da3633;
    color: white;
    padding: 4px 10px;
    border-radius: 12px;
    font-weight: 600;
}

QLabel#severityHigh {
    background-color: #f85149;
    color: white;
    padding: 4px 10px;
    border-radius: 12px;
    font-weight: 600;
}

QLabel#severityMedium {
    background-color: #d29922;
    color: white;
    padding: 4px 10px;
    border-radius: 12px;
    font-weight: 600;
}

QLabel#severityLow {
    background-color: #238636;
    color: white;
    padding: 4px 10px;
    border-radius: 12px;
    font-weight: 600;
}

QLabel#severityInfo {
    background-color: #0088ff;
    color: white;
    padding: 4px 10px;
    border-radius: 12px;
    font-weight: 600;
}

/* Terminal/Console */
QPlainTextEdit#console {
    background-color: #0a0e14;
    font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
    font-size: 12px;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 12px;
    color: #00ff88;
}

/* Navigation Items */
QPushButton#navItem {
    background-color: transparent;
    border: none;
    border-radius: 8px;
    padding: 12px 16px;
    text-align: left;
    color: #8b949e;
    font-weight: 500;
}

QPushButton#navItem:hover {
    background-color: #21262d;
    color: #e6e6e6;
}

QPushButton#navItem:checked, QPushButton#navItem[selected="true"] {
    background-color: rgba(0, 255, 136, 0.1);
    color: #00ff88;
    border-left: 3px solid #00ff88;
}

/* Glow Effects - use border instead of box-shadow (not supported by Qt) */
QLineEdit:focus {
    border: 2px solid #00ff88;
}

/* Animation placeholder - handled in code */
"""

# Color constants for use in code
COLORS = {
    'bg_dark': '#0a0e14',
    'bg_primary': '#0d1117',
    'bg_secondary': '#161b22',
    'bg_tertiary': '#21262d',
    'border_primary': '#21262d',
    'border_secondary': '#30363d',
    'border_highlight': '#484f58',
    'text_primary': '#e6e6e6',
    'text_secondary': '#8b949e',
    'text_muted': '#484f58',
    'accent_green': '#00ff88',
    'accent_green_hover': '#00cc6a',
    'accent_blue': '#0088ff',
    'accent_purple': '#a855f7',
    'success': '#238636',
    'success_hover': '#2ea043',
    'warning': '#d29922',
    'danger': '#da3633',
    'danger_hover': '#f85149',
    'critical': '#ff4444',
}

# Icon paths (placeholder for custom icons)
ICONS = {
    'dashboard': 'icons/dashboard.svg',
    'nmap': 'icons/nmap.svg',
    'hydra': 'icons/hydra.svg',
    'osint': 'icons/osint.svg',
    'targets': 'icons/targets.svg',
    'credentials': 'icons/credentials.svg',
    'vulnerabilities': 'icons/vulnerabilities.svg',
    'reports': 'icons/reports.svg',
    'settings': 'icons/settings.svg',
}
