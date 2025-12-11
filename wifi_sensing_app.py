#!/usr/bin/env python3
"""
Standalone WiFi Sensing Application
Launch the WiFi Sensing 3D visualization without the full HydraRecon suite.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from gui.pages.wifi_sensing_page import WifiSensingPage, WIFI_AVAILABLE, WIFI_IMPORT_ERROR


class WifiSensingWindow(QMainWindow):
    """Standalone WiFi Sensing window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛰️ WiFi Sensing Studio")
        self.setMinimumSize(1400, 900)
        self.resize(1600, 1000)

        # Dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0f1a;
            }
            QWidget {
                color: #e6f1ff;
                font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
            }
            QLabel {
                color: #d7e7ff;
            }
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
            QPushButton:pressed {
                background-color: #1a2a4c;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #0f1726;
                border: 1px solid #1f2e47;
                border-radius: 6px;
                padding: 6px 10px;
                color: #d7e7ff;
            }
            QTextEdit {
                background-color: #0b1320;
                border: 1px solid #1f2e47;
                border-radius: 8px;
                color: #cfe2ff;
            }
            QProgressBar {
                background-color: #0f1726;
                border: 1px solid #1f2e47;
                border-radius: 6px;
                text-align: center;
                color: #d7e7ff;
            }
            QProgressBar::chunk {
                background-color: #1e8fff;
                border-radius: 4px;
            }
            QCheckBox {
                color: #d7e7ff;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 1px solid #2a3a5a;
                background-color: #0f1726;
            }
            QCheckBox::indicator:checked {
                background-color: #1e8fff;
                border-color: #1e8fff;
            }
            QSplitter::handle {
                background-color: #1f2e47;
            }
            QFrame {
                border-radius: 10px;
            }
        """)

        # Central widget
        self.sensing_page = WifiSensingPage(self)
        self.setCentralWidget(self.sensing_page)

    def closeEvent(self, event):
        self.sensing_page.stop()
        super().closeEvent(event)


def main():
    if not WIFI_AVAILABLE:
        print(f"ERROR: WiFi Sensing module not available: {WIFI_IMPORT_ERROR}")
        print("Please ensure all dependencies are installed.")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("WiFi Sensing Studio")
    app.setApplicationDisplayName("WiFi Sensing Studio")

    # Set default font
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = WifiSensingWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
