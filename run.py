#!/usr/bin/env python3
"""
HydraRecon - Enterprise Security Assessment Suite
Launch script with splash screen and initialization.
"""

import sys
import os

# Add the project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import (
    QApplication, QSplashScreen, QProgressBar, QLabel, QVBoxLayout, QWidget
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QPainter, QColor, QFont, QLinearGradient


class SplashScreen(QSplashScreen):
    """Custom splash screen with progress"""
    
    def __init__(self):
        # Create a custom pixmap for splash
        pixmap = QPixmap(600, 400)
        pixmap.fill(QColor("#0d1117"))
        
        # Paint on the pixmap
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background gradient
        gradient = QLinearGradient(0, 0, 600, 400)
        gradient.setColorAt(0, QColor("#0d1117"))
        gradient.setColorAt(1, QColor("#161b22"))
        painter.fillRect(0, 0, 600, 400, gradient)
        
        # Draw border glow
        painter.setPen(QColor("#00ff88"))
        painter.drawRect(2, 2, 596, 396)
        
        # Logo text
        painter.setFont(QFont("Segoe UI", 48, QFont.Weight.Bold))
        painter.setPen(QColor("#00ff88"))
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "🔒 HydraRecon")
        
        # Subtitle
        painter.setFont(QFont("Segoe UI", 14))
        painter.setPen(QColor("#8b949e"))
        subtitle_rect = pixmap.rect()
        subtitle_rect.setTop(subtitle_rect.center().y() + 40)
        painter.drawText(subtitle_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                        "Enterprise Security Assessment Suite")
        
        # Version
        painter.setFont(QFont("Segoe UI", 10))
        painter.setPen(QColor("#484f58"))
        painter.drawText(10, 380, "Version 1.0.0")
        
        painter.end()
        
        super().__init__(pixmap)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        
        self.progress = 0
        self.message = "Initializing..."
    
    def drawContents(self, painter):
        """Draw progress text"""
        painter.setFont(QFont("Segoe UI", 11))
        painter.setPen(QColor("#00ff88"))
        
        # Progress bar background
        bar_rect = self.rect()
        bar_rect.setTop(bar_rect.bottom() - 50)
        bar_rect.setBottom(bar_rect.bottom() - 30)
        bar_rect.setLeft(50)
        bar_rect.setRight(bar_rect.right() - 50)
        
        painter.fillRect(bar_rect, QColor("#21262d"))
        
        # Progress bar fill
        fill_rect = bar_rect
        fill_rect.setRight(int(bar_rect.left() + (bar_rect.width() * self.progress / 100)))
        painter.fillRect(fill_rect, QColor("#238636"))
        
        # Message
        painter.setPen(QColor("#e6e6e6"))
        msg_rect = self.rect()
        msg_rect.setTop(msg_rect.bottom() - 25)
        painter.drawText(msg_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                        f"{self.message} ({self.progress}%)")
    
    def setProgress(self, value, message=""):
        """Update progress"""
        self.progress = value
        if message:
            self.message = message
        self.repaint()


def main():
    """Main entry point"""
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("HydraRecon")
    app.setOrganizationName("HydraRecon")
    app.setApplicationVersion("1.0.0")
    
    # Show splash screen
    splash = SplashScreen()
    splash.show()
    app.processEvents()
    
    # Initialize components
    def update_progress(value, message):
        splash.setProgress(value, message)
        app.processEvents()
    
    update_progress(10, "Loading configuration...")
    
    try:
        from core.config import AppConfig
        config = AppConfig()
        update_progress(25, "Configuration loaded")
    except ImportError:
        config = None
        update_progress(25, "Using default configuration")
    
    update_progress(40, "Initializing database...")
    
    try:
        from core.database import Database
        db = Database()
        update_progress(55, "Database ready")
    except ImportError:
        db = None
        update_progress(55, "Database skipped")
    
    update_progress(70, "Loading GUI components...")
    
    try:
        from gui.main_window import HydraReconMainWindow
        update_progress(85, "Creating main window...")
    except ImportError as e:
        print(f"Failed to import GUI: {e}")
        splash.close()
        return 1
    
    update_progress(95, "Finalizing...")
    
    # Create main window
    window = HydraReconMainWindow(config, db)
    
    update_progress(100, "Ready!")
    
    # Close splash and show main window
    QTimer.singleShot(500, lambda: (splash.close(), window.show()))
    
    # Run application
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
