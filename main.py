#!/usr/bin/env python3
"""
HydraRecon - Enterprise Security Assessment Suite
A next-generation penetration testing and OSINT platform
combining Hydra, Nmap, and comprehensive reconnaissance capabilities.

Copyright (c) 2024 - Professional Security Assessment Tool
For authorized security testing only.
"""

import sys
import os
import asyncio
import signal

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QThread
from PyQt6.QtGui import QFont, QIcon

# Import custom modules
from gui.main_window import HydraReconMainWindow
from core.config import Config
from core.database import DatabaseManager
from core.logger import setup_logging

def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    import logging
    logger = logging.getLogger('HydraRecon')
    logger.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

def main():
    """Main entry point for HydraRecon"""
    
    # Setup exception handling
    sys.excepthook = handle_exception
    
    # Setup logging
    logger = setup_logging()
    logger.info("Starting HydraRecon - Enterprise Security Assessment Suite")
    
    # Initialize configuration
    config = Config()
    
    # Initialize database
    db = DatabaseManager(config.database_path)
    db.initialize()
    
    # Create Qt Application
    app = QApplication(sys.argv)
    app.setApplicationName("HydraRecon")
    app.setOrganizationName("SecuritySuite")
    app.setOrganizationDomain("hydrarecon.security")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Set default font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    # Create and show main window
    main_window = HydraReconMainWindow(config, db)
    main_window.show()
    
    logger.info("HydraRecon GUI initialized successfully")
    
    # Run the application
    exit_code = app.exec()
    
    # Cleanup
    logger.info("HydraRecon shutting down")
    db.close()
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
