#!/usr/bin/env python3
"""
HydraRecon - Enterprise Security Assessment Suite
═══════════════════════════════════════════════════════════════════════════════
A professional-grade penetration testing and OSINT platform combining
Hydra, Nmap, and comprehensive reconnaissance capabilities.

Copyright (c) 2024-2026 HydraRecon Security Software
Licensed for AUTHORIZED SECURITY TESTING ONLY.
See LICENSE and DISCLAIMER.md for terms and conditions.
═══════════════════════════════════════════════════════════════════════════════
"""

import sys
import os
import traceback
import logging
from datetime import datetime

# Add the project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def setup_crash_logging():
    """Setup crash logging before anything else"""
    crash_log_dir = os.path.join(PROJECT_ROOT, "logs")
    os.makedirs(crash_log_dir, exist_ok=True)
    
    crash_log_file = os.path.join(
        crash_log_dir, 
        f"crash_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(crash_log_file),
            logging.StreamHandler(sys.stderr)
        ]
    )
    
    return logging.getLogger('HydraRecon')


def check_dependencies():
    """Verify all required dependencies are available"""
    missing = []
    
    required_modules = [
        ('PyQt6.QtWidgets', 'PyQt6'),
        ('PyQt6.QtCore', 'PyQt6'),
        ('PyQt6.QtGui', 'PyQt6'),
    ]
    
    optional_modules = [
        ('numpy', 'numpy'),
        ('scipy', 'scipy'),
        ('requests', 'requests'),
    ]
    
    for module_path, package_name in required_modules:
        try:
            __import__(module_path)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print("="*60)
        print("ERROR: Missing required dependencies")
        print("="*60)
        print(f"\nPlease install: {', '.join(set(missing))}")
        print(f"\nRun: pip install {' '.join(set(missing))}")
        print("="*60)
        sys.exit(1)
    
    # Check optional modules and warn
    for module_path, package_name in optional_modules:
        try:
            __import__(module_path)
        except ImportError:
            print(f"⚠️  Optional module '{package_name}' not found. Some features may be limited.")


def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler for uncaught exceptions"""
    if issubclass(exc_type, KeyboardInterrupt):
        # Handle Ctrl+C gracefully
        print("\n\n⚠️  HydraRecon interrupted by user. Shutting down gracefully...")
        sys.exit(0)
    
    logger = logging.getLogger('HydraRecon')
    logger.critical("="*60)
    logger.critical("UNCAUGHT EXCEPTION - HydraRecon Crash Report")
    logger.critical("="*60)
    logger.critical(f"Exception Type: {exc_type.__name__}")
    logger.critical(f"Exception Value: {exc_value}")
    logger.critical("Traceback:")
    
    tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    for line in tb_lines:
        logger.critical(line.rstrip())
    
    logger.critical("="*60)
    logger.critical("Please report this crash at: https://github.com/hydrarecon/issues")
    logger.critical("="*60)
    
    # Also print to stderr for immediate visibility
    sys.stderr.write("\n" + "="*60 + "\n")
    sys.stderr.write("❌ HydraRecon has encountered an error\n")
    sys.stderr.write("="*60 + "\n")
    sys.stderr.write(f"Error: {exc_value}\n")
    sys.stderr.write("Check logs/ directory for detailed crash report\n")
    sys.stderr.write("="*60 + "\n")


def check_license_acceptance():
    """Verify user has accepted license terms"""
    try:
        from core.license_acceptance import check_license_on_startup
        
        if not check_license_on_startup():
            print("\n❌ License terms must be accepted to use HydraRecon.")
            print("   Please restart and accept the license agreement.")
            sys.exit(1)
            
    except ImportError as e:
        print(f"⚠️  Could not load license module: {e}")
        print("   Continuing without license check...")


def main():
    """Main entry point for HydraRecon"""
    
    # Setup crash logging first
    logger = setup_crash_logging()
    logger.info("="*60)
    logger.info("HydraRecon - Enterprise Security Assessment Suite")
    logger.info("Starting up...")
    logger.info("="*60)
    
    # Install global exception handler
    sys.excepthook = handle_exception
    
    # Check dependencies
    logger.info("Checking dependencies...")
    check_dependencies()
    
    # Check license acceptance
    logger.info("Verifying license acceptance...")
    check_license_acceptance()
    
    # Now import Qt components (after dependency check)
    from PyQt6.QtWidgets import QApplication, QMessageBox
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QFont, QIcon
    
    # Import custom modules
    try:
        from gui.main_window import HydraReconMainWindow
        from core.config import Config
        from core.database import DatabaseManager
        from core.logger import setup_logging as setup_app_logging
    except ImportError as e:
        logger.critical(f"Failed to import core modules: {e}")
        traceback.print_exc()
        sys.exit(1)
    
    # Setup application logging
    setup_app_logging()
    logger.info("Application logging configured")
    
    # Initialize configuration
    try:
        config = Config()
        logger.info(f"Configuration loaded from: {config.config_file}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        config = Config()  # Use defaults
    
    # Initialize database
    try:
        db = DatabaseManager(config.database_path)
        db.initialize()
        logger.info(f"Database initialized: {config.database_path}")
    except Exception as e:
        logger.critical(f"Failed to initialize database: {e}")
        traceback.print_exc()
        sys.exit(1)
    
    # Create Qt Application
    logger.info("Initializing Qt application...")
    app = QApplication(sys.argv)
    app.setApplicationName("HydraRecon")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("HydraRecon Security")
    app.setOrganizationDomain("hydrarecon.security")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Set default font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    # Handle Qt errors
    def qt_message_handler(msg_type, context, message):
        if "QLayout" in message:
            # Suppress layout warnings (cosmetic, not critical)
            return
        logger.warning(f"Qt: {message}")
    
    from PyQt6.QtCore import qInstallMessageHandler, QtMsgType
    qInstallMessageHandler(qt_message_handler)
    
    # Create and show main window
    try:
        logger.info("Creating main window...")
        main_window = HydraReconMainWindow(config, db)
        main_window.show()
        logger.info("HydraRecon GUI initialized successfully")
    except Exception as e:
        logger.critical(f"Failed to create main window: {e}")
        traceback.print_exc()
        
        # Show error dialog
        QMessageBox.critical(
            None, 
            "HydraRecon - Startup Error",
            f"Failed to initialize the application:\n\n{str(e)}\n\n"
            "Please check the logs/ directory for details."
        )
        sys.exit(1)
    
    # Run the application
    logger.info("Entering main event loop...")
    exit_code = app.exec()
    
    # Cleanup
    logger.info("HydraRecon shutting down...")
    try:
        db.close()
        logger.info("Database connection closed")
    except Exception as e:
        logger.warning(f"Error closing database: {e}")
    
    logger.info(f"HydraRecon exited with code: {exit_code}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
