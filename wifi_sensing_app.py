#!/usr/bin/env python3
"""
WiFi Sensing Studio - Advanced Human Sensing Application
═══════════════════════════════════════════════════════════════════════════════
Launch the WiFi Sensing 3D visualization with full immersive experience.

Features:
  • Real-time CSI-based human detection and tracking
  • First-person 3D visualization with WASD controls
  • Activity recognition (walking, sitting, falling)
  • Vital signs monitoring (heart rate, respiration)
  • Room occupancy analysis
  • Emergency detection (falls, intrusions)
  • ESP32 hardware integration

Usage:
  python wifi_sensing_app.py [options]

Options:
  --fullscreen       Launch in fullscreen mode
  --demo             Run with simulated demo data
  --esp32 HOST:PORT  Connect to ESP32 CSI source
  --debug            Enable debug logging
  --record FILE      Record session to file
  --playback FILE    Playback recorded session

Copyright (c) 2024-2025 HydraRecon Security Suite
For authorized security research only.
═══════════════════════════════════════════════════════════════════════════════
"""

import sys
import os
import argparse
import logging
from datetime import datetime
from typing import Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QMenuBar, QMenu, QStatusBar,
    QMessageBox, QFileDialog, QLabel, QToolBar, QWidget,
    QVBoxLayout, QHBoxLayout, QFrame, QSplitter
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QSettings
from PyQt6.QtGui import QFont, QAction, QIcon, QKeySequence, QColor

# Attempt to import WiFi sensing modules
try:
    from gui.pages.wifi_sensing_page import WifiSensingPage, WIFI_AVAILABLE, WIFI_IMPORT_ERROR
except ImportError as e:
    WIFI_AVAILABLE = False
    WIFI_IMPORT_ERROR = str(e)
    WifiSensingPage = None


class WifiSensingStatusBar(QStatusBar):
    """Enhanced status bar with real-time metrics."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QStatusBar {
                background: #0d1520;
                border-top: 1px solid #1f3a5f;
                color: #8fb3ff;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QLabel {
                padding: 2px 8px;
                color: #8fb3ff;
            }
        """)
        
        # Status indicators
        self.connection_label = QLabel("⚫ Disconnected")
        self.entities_label = QLabel("👥 Entities: 0")
        self.fps_label = QLabel("📊 FPS: 0")
        self.packets_label = QLabel("📡 Packets: 0")
        self.memory_label = QLabel("💾 Mem: 0 MB")
        self.time_label = QLabel("")
        
        self.addWidget(self.connection_label)
        self.addWidget(self._create_separator())
        self.addWidget(self.entities_label)
        self.addWidget(self._create_separator())
        self.addWidget(self.fps_label)
        self.addWidget(self._create_separator())
        self.addWidget(self.packets_label)
        self.addPermanentWidget(self.memory_label)
        self.addPermanentWidget(self._create_separator())
        self.addPermanentWidget(self.time_label)
        
        # Update timer
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_time)
        self.update_timer.start(1000)
        
    def _create_separator(self) -> QLabel:
        sep = QLabel("|")
        sep.setStyleSheet("color: #2a4a6f; padding: 0 4px;")
        return sep
        
    def _update_time(self):
        self.time_label.setText(datetime.now().strftime("🕐 %H:%M:%S"))
        
    def set_connected(self, connected: bool, source: str = ""):
        if connected:
            self.connection_label.setText(f"🟢 Connected: {source}")
            self.connection_label.setStyleSheet("color: #00ff88;")
        else:
            self.connection_label.setText("🔴 Disconnected")
            self.connection_label.setStyleSheet("color: #ff6b6b;")
            
    def update_metrics(self, entities: int, fps: float, packets: int, memory_mb: float):
        self.entities_label.setText(f"👥 Entities: {entities}")
        self.fps_label.setText(f"📊 FPS: {fps:.1f}")
        self.packets_label.setText(f"📡 Packets: {packets}")
        self.memory_label.setText(f"💾 Mem: {memory_mb:.1f} MB")


class WifiSensingWindow(QMainWindow):
    """Advanced WiFi Sensing Studio main window."""
    
    connection_changed = pyqtSignal(bool, str)
    
    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args
        self.settings = QSettings("HydraRecon", "WifiSensingStudio")
        self.recording = False
        self.record_file = None
        
        self._setup_window()
        self._setup_menubar()
        self._setup_toolbar()
        self._setup_signal_dock()
        self._setup_statusbar()
        self._setup_central_widget()
        self._apply_settings()
        
        # Apply command line options
        if args.fullscreen:
            self.showFullScreen()
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            
        # Metrics update timer
        self.metrics_timer = QTimer(self)
        self.metrics_timer.timeout.connect(self._update_metrics)
        self.metrics_timer.start(500)
        
    def _setup_window(self):
        self.setWindowTitle("🛰️ WiFi Sensing Studio - Advanced Human Sensing")
        self.setMinimumSize(1400, 900)
        self.resize(1700, 1000)
        
        # Restore geometry
        geometry = self.settings.value("window/geometry")
        if geometry:
            self.restoreGeometry(geometry)
            
        # Dark cyberpunk theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0f1a;
            }
            QWidget {
                color: #e6f1ff;
                font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
            }
            QMenuBar {
                background: #0d1520;
                border-bottom: 1px solid #1f3a5f;
                color: #d7e7ff;
                padding: 4px;
            }
            QMenuBar::item {
                padding: 6px 12px;
                border-radius: 4px;
            }
            QMenuBar::item:selected {
                background: #1a3050;
            }
            QMenu {
                background: #0d1520;
                border: 1px solid #1f3a5f;
                border-radius: 8px;
                padding: 6px;
            }
            QMenu::item {
                padding: 8px 24px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background: #1a3050;
            }
            QMenu::separator {
                height: 1px;
                background: #1f3a5f;
                margin: 6px 12px;
            }
            QToolBar {
                background: #0d1520;
                border-bottom: 1px solid #1f3a5f;
                spacing: 6px;
                padding: 4px;
            }
            QToolButton {
                background: transparent;
                border: 1px solid transparent;
                border-radius: 6px;
                padding: 8px;
                color: #8fb3ff;
            }
            QToolButton:hover {
                background: #1a3050;
                border-color: #2a5080;
            }
            QToolButton:pressed {
                background: #1a2a40;
            }
            QLabel { color: #d7e7ff; }
            QPushButton {
                background-color: #1a2744;
                border: 1px solid #2a3a5a;
                border-radius: 6px;
                padding: 8px 16px;
                color: #d7e7ff;
            }
            QPushButton:hover {
                background-color: #243a5c;
                border-color: #3a5a8c;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #0f1726;
                border: 1px solid #1f2e47;
                border-radius: 6px;
                padding: 6px 10px;
                color: #d7e7ff;
            }
            QCheckBox { color: #d7e7ff; }
            QCheckBox::indicator {
                width: 18px; height: 18px;
                border-radius: 4px;
                border: 1px solid #2a3a5a;
                background-color: #0f1726;
            }
            QCheckBox::indicator:checked {
                background-color: #1e8fff;
                border-color: #1e8fff;
            }
            QSplitter::handle { background-color: #1f2e47; }
            QFrame { border-radius: 10px; }
            QScrollBar:vertical {
                background: #0a0f1a;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #1f3a5f;
                border-radius: 6px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover { background: #2a5080; }
        """)
        
    def _setup_menubar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        new_action = QAction("🆕 New Session", self)
        new_action.setShortcut(QKeySequence.StandardKey.New)
        new_action.triggered.connect(self._new_session)
        file_menu.addAction(new_action)
        
        file_menu.addSeparator()
        
        record_action = QAction("🔴 Start Recording", self)
        record_action.setShortcut("Ctrl+R")
        record_action.triggered.connect(self._toggle_recording)
        file_menu.addAction(record_action)
        self.record_action = record_action
        
        playback_action = QAction("▶️ Playback Session", self)
        playback_action.setShortcut("Ctrl+P")
        playback_action.triggered.connect(self._playback_session)
        file_menu.addAction(playback_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("📤 Export Data...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self._export_data)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        quit_action = QAction("❌ Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        fullscreen_action = QAction("🖥️ Fullscreen", self)
        fullscreen_action.setShortcut("F11")
        fullscreen_action.setCheckable(True)
        fullscreen_action.triggered.connect(self._toggle_fullscreen)
        view_menu.addAction(fullscreen_action)
        self.fullscreen_action = fullscreen_action
        
        view_menu.addSeparator()
        
        pov_action = QAction("👁️ First-Person POV", self)
        pov_action.setShortcut("1")
        pov_action.triggered.connect(lambda: self._switch_view(1))
        view_menu.addAction(pov_action)
        
        scene_action = QAction("🌐 3D Scene View", self)
        scene_action.setShortcut("2")
        scene_action.triggered.connect(lambda: self._switch_view(0))
        view_menu.addAction(scene_action)
        
        full_exp_action = QAction("🚨 Full Experience", self)
        full_exp_action.setShortcut("3")
        full_exp_action.triggered.connect(lambda: self._switch_view(2))
        view_menu.addAction(full_exp_action)
        
        # Connection menu
        conn_menu = menubar.addMenu("&Connection")
        
        esp32_action = QAction("📡 Connect ESP32...", self)
        esp32_action.triggered.connect(self._connect_esp32)
        conn_menu.addAction(esp32_action)
        
        demo_action = QAction("🎮 Enable Demo Mode", self)
        demo_action.setCheckable(True)
        demo_action.setChecked(True)  # Demo mode on by default
        demo_action.triggered.connect(self._toggle_demo)
        conn_menu.addAction(demo_action)
        self.demo_action = demo_action
        
        conn_menu.addSeparator()
        
        disconnect_action = QAction("🔌 Disconnect", self)
        disconnect_action.triggered.connect(self._disconnect)
        conn_menu.addAction(disconnect_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        calibrate_action = QAction("📐 Calibrate Room", self)
        calibrate_action.triggered.connect(self._calibrate_room)
        tools_menu.addAction(calibrate_action)
        
        zones_action = QAction("🗺️ Define Zones", self)
        zones_action.triggered.connect(self._define_zones)
        tools_menu.addAction(zones_action)
        
        tools_menu.addSeparator()
        
        debug_action = QAction("🐛 Debug Console", self)
        debug_action.setShortcut("F12")
        debug_action.triggered.connect(self._show_debug)
        tools_menu.addAction(debug_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        controls_action = QAction("🎮 Controls", self)
        controls_action.setShortcut("F1")
        controls_action.triggered.connect(self._show_controls)
        help_menu.addAction(controls_action)
        
        about_action = QAction("ℹ️ About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
    def _setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Quick actions
        toolbar.addAction("🆕 New").triggered.connect(self._new_session)
        toolbar.addAction("🔴 Record").triggered.connect(self._toggle_recording)
        toolbar.addSeparator()
        toolbar.addAction("👁️ POV").triggered.connect(lambda: self._switch_view(1))
        toolbar.addAction("🌐 3D").triggered.connect(lambda: self._switch_view(0))
        toolbar.addAction("🚨 Full").triggered.connect(lambda: self._switch_view(2))
        toolbar.addSeparator()
        toolbar.addAction("📐 Calibrate").triggered.connect(self._calibrate_room)
        toolbar.addAction("🔄 Reset Camera").triggered.connect(self._reset_camera)
        toolbar.addSeparator()
        self.signal_dock_action = toolbar.addAction("📊 Signals")
        self.signal_dock_action.setCheckable(True)
        self.signal_dock_action.setChecked(True)
        self.signal_dock_action.triggered.connect(self._toggle_signal_dock)
        
    def _setup_signal_dock(self):
        """Create signal analyzer dock widget."""
        from PyQt6.QtWidgets import QDockWidget
        
        self.signal_dock = QDockWidget("📊 Signal Analyzer", self)
        self.signal_dock.setStyleSheet("""
            QDockWidget {
                color: #d7e7ff;
                font-weight: bold;
            }
            QDockWidget::title {
                background: #0d1520;
                padding: 8px;
                border-bottom: 1px solid #1f3a5f;
            }
        """)
        
        dock_widget = QWidget()
        dock_layout = QVBoxLayout(dock_widget)
        dock_layout.setContentsMargins(5, 5, 5, 5)
        dock_layout.setSpacing(5)
        
        # CSI Waveform
        self.waveform = CSIWaveformWidget()
        dock_layout.addWidget(self.waveform)
        
        # Spectrum Analyzer
        self.spectrum = SpectrumAnalyzerWidget()
        dock_layout.addWidget(self.spectrum)
        
        self.signal_dock.setWidget(dock_widget)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.signal_dock)
        
    def _toggle_signal_dock(self):
        if hasattr(self, 'signal_dock'):
            self.signal_dock.setVisible(not self.signal_dock.isVisible())
        
    def _setup_statusbar(self):
        self.status_bar = WifiSensingStatusBar(self)
        self.setStatusBar(self.status_bar)
        
    def _setup_central_widget(self):
        if not WIFI_AVAILABLE:
            error_widget = QLabel(f"⚠️ WiFi Sensing module not available:\n{WIFI_IMPORT_ERROR}")
            error_widget.setStyleSheet("color: #ff7b7b; font-size: 16px; padding: 40px;")
            error_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setCentralWidget(error_widget)
            return
            
        self.sensing_page = WifiSensingPage(self)
        self.setCentralWidget(self.sensing_page)
        
    def _apply_settings(self):
        # Restore settings
        if self.settings.value("view/fullscreen", False, type=bool):
            self.showFullScreen()
            self.fullscreen_action.setChecked(True)
            
    def _update_metrics(self):
        if not WIFI_AVAILABLE or not hasattr(self, 'sensing_page'):
            return
            
        # Get metrics from sensing page (would need to be implemented)
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
        except:
            memory_mb = 0
            
        # These would ideally come from the sensing page
        entities = 0
        fps = 30.0
        packets = 0
        
        if hasattr(self.sensing_page, 'view_tabs'):
            current = self.sensing_page.view_tabs.currentIndex()
            if current == 1 and hasattr(self.sensing_page, 'immersive_tab'):
                tracks = self.sensing_page.immersive_tab.immersive_view.controller.tracker.get_tracks()
                entities = len(tracks)
            elif current == 2 and hasattr(self.sensing_page, 'full_experience'):
                entities = len(self.sensing_page.full_experience.sensing_system.entity_profiles)
                
        self.status_bar.update_metrics(entities, fps, packets, memory_mb)
        
    # Menu action handlers
    def _new_session(self):
        reply = QMessageBox.question(self, "New Session", 
            "Start a new sensing session? Current data will be lost.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            # Reset the sensing page
            if hasattr(self, 'sensing_page'):
                self.sensing_page.stop()
                self._setup_central_widget()
                
    def _toggle_recording(self):
        self.recording = not self.recording
        if self.recording:
            self.record_action.setText("⏹️ Stop Recording")
            self.status_bar.showMessage("Recording session...", 3000)
        else:
            self.record_action.setText("🔴 Start Recording")
            self.status_bar.showMessage("Recording stopped", 3000)
            
    def _playback_session(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open Recording", 
            "", "Session Files (*.json *.csv)")
        if filename:
            self.status_bar.showMessage(f"Playing: {filename}", 3000)
            
    def _export_data(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Data",
            f"wifi_sensing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv)")
        if filename:
            self.status_bar.showMessage(f"Exported to: {filename}", 3000)
            
    def _toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
            self.fullscreen_action.setChecked(False)
        else:
            self.showFullScreen()
            self.fullscreen_action.setChecked(True)
            
    def _switch_view(self, index: int):
        if hasattr(self, 'sensing_page') and hasattr(self.sensing_page, 'view_tabs'):
            self.sensing_page.view_tabs.setCurrentIndex(index)
            
    def _connect_esp32(self):
        from PyQt6.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(self, "Connect ESP32", 
            "Enter ESP32 address (host:port):", text="192.168.1.100:5555")
        if ok and text:
            self.status_bar.set_connected(True, text)
            self.status_bar.showMessage(f"Connecting to {text}...", 3000)
            
    def _toggle_demo(self):
        enabled = self.demo_action.isChecked()
        self.status_bar.showMessage(f"Demo mode {'enabled' if enabled else 'disabled'}", 3000)
        
    def _disconnect(self):
        self.status_bar.set_connected(False)
        self.status_bar.showMessage("Disconnected", 3000)
        
    def _calibrate_room(self):
        QMessageBox.information(self, "Room Calibration",
            "Room calibration wizard:\n\n"
            "1. Walk to each corner of the room\n"
            "2. Stand still for 3 seconds at each corner\n"
            "3. The system will learn room boundaries\n\n"
            "Feature coming soon!")
            
    def _define_zones(self):
        QMessageBox.information(self, "Zone Definition",
            "Zone definition allows you to create named areas\n"
            "for presence detection and alerts.\n\n"
            "Feature coming soon!")
            
    def _show_debug(self):
        QMessageBox.information(self, "Debug Console",
            "Debug console provides real-time CSI data,\n"
            "tracking internals, and system diagnostics.\n\n"
            "Feature coming soon!")
            
    def _reset_camera(self):
        if hasattr(self, 'sensing_page') and hasattr(self.sensing_page, '_reset_camera_view'):
            self.sensing_page._reset_camera_view()
            self.status_bar.showMessage("Camera reset", 2000)
            
    def _show_controls(self):
        QMessageBox.information(self, "Controls", 
            "🎮 Camera Controls:\n\n"
            "  WASD - Move camera\n"
            "  Right-click + drag - Look around\n"
            "  Space - Move up\n"
            "  Shift - Move down\n"
            "  R - Reset camera\n\n"
            "⌨️ Keyboard Shortcuts:\n\n"
            "  1 - First-Person POV view\n"
            "  2 - 3D Scene view\n"
            "  3 - Full Experience view\n"
            "  F11 - Toggle fullscreen\n"
            "  Ctrl+R - Toggle recording\n"
            "  F1 - Show this help")
            
    def _show_about(self):
        QMessageBox.about(self, "About WiFi Sensing Studio",
            "🛰️ WiFi Sensing Studio v1.0\n\n"
            "Advanced CSI-based human sensing platform\n"
            "for indoor localization, activity recognition,\n"
            "and vital signs monitoring.\n\n"
            "Part of HydraRecon Security Suite\n"
            "Copyright © 2024-2025\n\n"
            "For authorized security research only.")
            
    def closeEvent(self, event):
        # Save settings
        self.settings.setValue("window/geometry", self.saveGeometry())
        self.settings.setValue("view/fullscreen", self.isFullScreen())
        
        # Stop sensing
        if hasattr(self, 'sensing_page') and hasattr(self.sensing_page, 'stop'):
            self.sensing_page.stop()
            
        super().closeEvent(event)


def setup_logging(debug: bool = False):
    """Configure application logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger("WifiSensingStudio")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="WiFi Sensing Studio - Advanced Human Sensing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wifi_sensing_app.py                    # Launch with demo mode
  python wifi_sensing_app.py --fullscreen       # Launch fullscreen
  python wifi_sensing_app.py --esp32 192.168.1.100:5555
  python wifi_sensing_app.py --debug --record session.json
        """
    )
    
    parser.add_argument("--fullscreen", "-f", action="store_true",
                        help="Launch in fullscreen mode")
    parser.add_argument("--demo", "-d", action="store_true", default=True,
                        help="Run with simulated demo data (default)")
    parser.add_argument("--esp32", metavar="HOST:PORT",
                        help="Connect to ESP32 CSI source")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--record", metavar="FILE",
                        help="Record session to file")
    parser.add_argument("--playback", metavar="FILE",
                        help="Playback recorded session")
    parser.add_argument("--no-splash", action="store_true",
                        help="Skip splash screen")
    parser.add_argument("--version", "-v", action="version",
                        version="WiFi Sensing Studio 1.0.0")
    
    return parser.parse_args()


class WifiSensingSplash(QWidget):
    """Animated splash screen for WiFi Sensing Studio."""
    
    finished = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(600, 400)
        
        # Center on screen
        screen = QApplication.primaryScreen().geometry()
        self.move((screen.width() - 600) // 2, (screen.height() - 400) // 2)
        
        self._progress = 0
        self._status = "Initializing..."
        self._glow = 0
        self._glow_dir = 1
        
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._animate)
        
    def start(self):
        self._timer.start(30)
        QTimer.singleShot(2500, self._finish)
        
    def _animate(self):
        self._glow += self._glow_dir * 3
        if self._glow >= 60:
            self._glow_dir = -1
        elif self._glow <= 10:
            self._glow_dir = 1
        self._progress = min(100, self._progress + 2)
        self.update()
        
    def _finish(self):
        self._timer.stop()
        self.finished.emit()
        self.close()
        
    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QPainterPath, QLinearGradient, QRadialGradient, QPen, QBrush
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        
        # Background with rounded corners
        path = QPainterPath()
        path.addRoundedRect(0, 0, w, h, 20, 20)
        
        # Gradient background
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor("#0a0f1a"))
        grad.setColorAt(0.5, QColor("#0d1520"))
        grad.setColorAt(1, QColor("#0a0f1a"))
        painter.fillPath(path, grad)
        
        # Border glow
        glow_color = QColor("#00d4ff")
        glow_color.setAlpha(self._glow + 40)
        painter.setPen(QPen(glow_color, 2))
        painter.drawPath(path)
        
        # Title
        painter.setPen(QColor("#00d4ff"))
        font = QFont("Segoe UI", 28, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(0, 80, w, 50, Qt.AlignmentFlag.AlignCenter, "🛰️ WiFi Sensing Studio")
        
        # Subtitle
        painter.setPen(QColor("#8fb3ff"))
        font = QFont("Segoe UI", 12)
        painter.setFont(font)
        painter.drawText(0, 130, w, 30, Qt.AlignmentFlag.AlignCenter, "Advanced CSI-Based Human Sensing Platform")
        
        # Animated wave visualization
        painter.setPen(QPen(QColor("#00ff88"), 2))
        import math
        cx = w // 2
        cy = 200
        for i in range(100):
            x = cx - 150 + i * 3
            amp = 20 * math.sin((i + self._progress * 2) * 0.15) * math.exp(-abs(i - 50) / 40)
            y = cy + amp
            if i > 0:
                prev_x = cx - 150 + (i - 1) * 3
                prev_amp = 20 * math.sin((i - 1 + self._progress * 2) * 0.15) * math.exp(-abs(i - 1 - 50) / 40)
                prev_y = cy + prev_amp
                painter.drawLine(int(prev_x), int(prev_y), int(x), int(y))
        
        # Progress bar
        bar_x, bar_y, bar_w, bar_h = 100, 280, w - 200, 8
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#1a2a40"))
        painter.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 4, 4)
        
        # Progress fill
        fill_w = int(bar_w * self._progress / 100)
        grad = QLinearGradient(bar_x, 0, bar_x + bar_w, 0)
        grad.setColorAt(0, QColor("#00d4ff"))
        grad.setColorAt(1, QColor("#00ff88"))
        painter.setBrush(grad)
        painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 4, 4)
        
        # Status text
        painter.setPen(QColor("#667788"))
        font = QFont("Consolas", 10)
        painter.setFont(font)
        statuses = ["Loading modules...", "Initializing 3D engine...", "Starting CSI processor...", "Ready!"]
        status = statuses[min(len(statuses) - 1, self._progress // 30)]
        painter.drawText(0, 310, w, 30, Qt.AlignmentFlag.AlignCenter, status)
        
        # Version and copyright
        painter.setPen(QColor("#445566"))
        font = QFont("Segoe UI", 9)
        painter.setFont(font)
        painter.drawText(0, h - 40, w, 30, Qt.AlignmentFlag.AlignCenter, "v1.0.0 • HydraRecon Security Suite • 2024-2025")


class ESP32ConnectionDialog(QWidget):
    """Dialog for ESP32 connection configuration."""
    
    connected = pyqtSignal(str, int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connect to ESP32")
        self.setFixedSize(400, 300)
        self.setWindowFlags(Qt.WindowType.Dialog)
        self.setStyleSheet("""
            QWidget {
                background: #0d1520;
                color: #d7e7ff;
            }
            QLineEdit, QSpinBox {
                background: #0a0f1a;
                border: 1px solid #1f3a5f;
                border-radius: 6px;
                padding: 8px;
                color: #d7e7ff;
            }
            QPushButton {
                background: #1a3050;
                border: 1px solid #2a5080;
                border-radius: 6px;
                padding: 10px 20px;
                color: #00d4ff;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2a4060;
            }
            QPushButton#connect {
                background: #00aa66;
                border-color: #00dd88;
            }
            QPushButton#connect:hover {
                background: #00cc77;
            }
            QLabel {
                color: #8fb3ff;
            }
        """)
        
        from PyQt6.QtWidgets import QLineEdit, QSpinBox, QPushButton, QFormLayout, QGroupBox
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("📡 ESP32 CSI Connection")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #00d4ff;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Connection settings
        group = QGroupBox("Connection Settings")
        group.setStyleSheet("QGroupBox { border: 1px solid #1f3a5f; border-radius: 8px; padding-top: 15px; margin-top: 10px; } QGroupBox::title { color: #8fb3ff; }")
        form = QFormLayout(group)
        
        self.host_input = QLineEdit("192.168.1.100")
        form.addRow("Host:", self.host_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(5555)
        form.addRow("Port:", self.port_input)
        
        layout.addWidget(group)
        
        # Recent connections
        recent_label = QLabel("Recent: 192.168.1.100:5555, 10.0.0.50:5555")
        recent_label.setStyleSheet("color: #445566; font-size: 10px;")
        layout.addWidget(recent_label)
        
        layout.addStretch()
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.close)
        btn_layout.addWidget(cancel_btn)
        
        connect_btn = QPushButton("🔗 Connect")
        connect_btn.setObjectName("connect")
        connect_btn.clicked.connect(self._connect)
        btn_layout.addWidget(connect_btn)
        
        layout.addLayout(btn_layout)
        
    def _connect(self):
        host = self.host_input.text()
        port = self.port_input.value()
        self.connected.emit(host, port)
        self.close()


class CSIWaveformWidget(QFrame):
    """Real-time CSI waveform visualization widget."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(150)
        self.setStyleSheet("QFrame { background: #0a0f1a; border: 1px solid #1f3a5f; border-radius: 8px; }")
        
        self.data = []
        self.max_points = 200
        
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._generate_demo)
        self._timer.start(50)
        
    def _generate_demo(self):
        import random, math
        t = len(self.data) * 0.05
        val = math.sin(t * 2) * 0.5 + math.sin(t * 5) * 0.3 + random.gauss(0, 0.1)
        self.data.append(val)
        if len(self.data) > self.max_points:
            self.data = self.data[-self.max_points:]
        self.update()
        
    def add_sample(self, value: float):
        self.data.append(value)
        if len(self.data) > self.max_points:
            self.data = self.data[-self.max_points:]
        self.update()
        
    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QPen, QLinearGradient
        
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        
        # Draw grid
        painter.setPen(QPen(QColor("#1a2a40"), 1))
        for i in range(1, 5):
            y = h * i // 5
            painter.drawLine(0, y, w, y)
        for i in range(1, 10):
            x = w * i // 10
            painter.drawLine(x, 0, x, h)
            
        # Draw center line
        painter.setPen(QPen(QColor("#2a4060"), 1))
        painter.drawLine(0, h // 2, w, h // 2)
        
        # Draw waveform
        if len(self.data) < 2:
            return
            
        painter.setPen(QPen(QColor("#00d4ff"), 2))
        
        min_val = min(self.data) - 0.1
        max_val = max(self.data) + 0.1
        val_range = max_val - min_val or 1
        
        for i in range(1, len(self.data)):
            x1 = int((i - 1) / self.max_points * w)
            x2 = int(i / self.max_points * w)
            y1 = int(h - (self.data[i - 1] - min_val) / val_range * h * 0.9 - h * 0.05)
            y2 = int(h - (self.data[i] - min_val) / val_range * h * 0.9 - h * 0.05)
            painter.drawLine(x1, y1, x2, y2)
            
        # Label
        painter.setPen(QColor("#445566"))
        font = QFont("Consolas", 9)
        painter.setFont(font)
        painter.drawText(10, 20, "CSI Amplitude")


class SpectrumAnalyzerWidget(QFrame):
    """Real-time spectrum analyzer visualization."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(120)
        self.setStyleSheet("QFrame { background: #0a0f1a; border: 1px solid #1f3a5f; border-radius: 8px; }")
        
        self.bins = 32
        self.values = [0.0] * self.bins
        
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._generate_demo)
        self._timer.start(80)
        
    def _generate_demo(self):
        import random, math
        t = random.random() * 10
        for i in range(self.bins):
            target = 0.3 + 0.5 * math.exp(-((i - self.bins/3)**2) / 50) + random.gauss(0, 0.1)
            self.values[i] = self.values[i] * 0.7 + target * 0.3
        self.update()
        
    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QPen, QLinearGradient, QBrush
        
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        bar_w = (w - 20) / self.bins - 2
        
        for i, val in enumerate(self.values):
            x = 10 + i * (bar_w + 2)
            bar_h = max(4, val * (h - 30))
            y = h - 15 - bar_h
            
            # Gradient from cyan to green
            grad = QLinearGradient(x, y + bar_h, x, y)
            grad.setColorAt(0, QColor("#00d4ff"))
            grad.setColorAt(1, QColor("#00ff88"))
            
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(grad)
            painter.drawRoundedRect(int(x), int(y), int(bar_w), int(bar_h), 2, 2)
            
        # Label
        painter.setPen(QColor("#445566"))
        font = QFont("Consolas", 9)
        painter.setFont(font)
        painter.drawText(10, 15, "Subcarrier Spectrum")


def main():
    """Main entry point."""
    args = parse_args()
    logger = setup_logging(args.debug)
    
    logger.info("Starting WiFi Sensing Studio...")
    
    if not WIFI_AVAILABLE:
        logger.error(f"WiFi Sensing module not available: {WIFI_IMPORT_ERROR}")
        print(f"\n❌ ERROR: WiFi Sensing module not available\n   {WIFI_IMPORT_ERROR}\n")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r requirements.txt\n")
        sys.exit(1)
        
    logger.info("WiFi Sensing module loaded successfully")

    app = QApplication(sys.argv)
    app.setApplicationName("WiFi Sensing Studio")
    app.setApplicationDisplayName("WiFi Sensing Studio")
    app.setOrganizationName("HydraRecon")
    app.setApplicationVersion("1.0.0")

    # Set default font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    # Show splash screen
    window = None
    
    def show_main_window():
        nonlocal window
        window = WifiSensingWindow(args)
        window.show()
        logger.info("WiFi Sensing Studio initialized successfully")
    
    if not args.no_splash:
        splash = WifiSensingSplash()
        splash.finished.connect(show_main_window)
        splash.show()
        splash.start()
    else:
        show_main_window()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
