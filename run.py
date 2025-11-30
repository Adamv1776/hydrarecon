#!/usr/bin/env python3
"""
HydraRecon - Enterprise Security Assessment Suite
████████████████████████████████████████████████████████████████████████████████
█  Launch script with cyberpunk splash screen and initialization               █
████████████████████████████████████████████████████████████████████████████████
"""

import sys
import os

# Add the project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont


def main():
    """Main entry point"""
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("HydraRecon")
    app.setOrganizationName("HydraRecon")
    app.setApplicationVersion("1.0.0")
    
    # Set application-wide font
    font = QFont("SF Pro Display", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)
    
    # Apply dark palette
    app.setStyle("Fusion")
    
    # Import and show splash screen
    from gui.splash_screen import SplashScreen
    splash = SplashScreen()
    splash.show()
    splash.start_loading()
    app.processEvents()
    
    # Background initialization
    config = None
    db = None
    
    def initialize_step1():
        """Load configuration"""
        nonlocal config
        try:
            from core.config import AppConfig
            config = AppConfig()
        except ImportError:
            pass
    
    def initialize_step2():
        """Initialize database"""
        nonlocal db
        try:
            from core.database import Database
            db = Database()
        except ImportError:
            pass
    
    def initialize_step3():
        """Create and show main window"""
        try:
            from gui.main_window import HydraReconMainWindow
            window = HydraReconMainWindow(config, db)
            
            # Fade out splash and show main window
            splash.finish()
            window.show()
            
            # Store window reference to prevent garbage collection
            app.main_window = window
            
        except ImportError as e:
            print(f"Failed to import GUI: {e}")
            splash.finish()
            app.quit()
    
    # Schedule initialization
    QTimer.singleShot(100, initialize_step1)
    QTimer.singleShot(500, initialize_step2)
    QTimer.singleShot(3500, initialize_step3)  # Wait for splash animation
    
    # Run application
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
