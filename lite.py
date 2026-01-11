#!/usr/bin/env python3
"""
HydraRecon - Lite Mode
═══════════════════════════════════════════════════════════════════════════════
Lightweight version that loads only essential modules for faster startup.
Perfect for quick tasks and systems with limited resources.
═══════════════════════════════════════════════════════════════════════════════
"""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def main():
    """Launch HydraRecon in Lite mode"""
    
    # Disable heavy optional features
    os.environ['HYDRARECON_LITE_MODE'] = '1'
    os.environ['HYDRARECON_DISABLE_3D'] = '1'
    os.environ['HYDRARECON_DISABLE_WIFI_SENSING'] = '1'
    
    print("="*60)
    print("HydraRecon LITE MODE")
    print("="*60)
    print("Loading core modules only for faster startup...")
    print("Some advanced features are disabled in this mode.")
    print("="*60)
    
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QFont
    from PyQt6.QtCore import qInstallMessageHandler
    
    # Suppress Qt warnings
    def suppress_warnings(msg_type, context, message):
        if 'QLayout' not in message:
            print(f"Qt: {message}")
    qInstallMessageHandler(suppress_warnings)
    
    app = QApplication(sys.argv)
    app.setApplicationName("HydraRecon Lite")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    
    # Import lite window
    from gui.lite_window import HydraReconLiteWindow
    from core.config import Config
    from core.database import DatabaseManager
    
    config = Config()
    db = DatabaseManager(config.database_path)
    db.initialize()
    
    window = HydraReconLiteWindow(config, db)
    window.show()
    
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
