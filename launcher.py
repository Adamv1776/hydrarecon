#!/usr/bin/env python3
"""
HydraRecon - Professional Launcher with Health Checks
═══════════════════════════════════════════════════════════════════════════════
Production-grade launcher with:
- Dependency verification
- Memory checks
- Lazy module loading
- Crash recovery
- Telemetry (optional)
═══════════════════════════════════════════════════════════════════════════════
"""

import sys
import os
import gc
import time
import platform
import traceback
import logging
from datetime import datetime
from pathlib import Path

# Constants
MIN_PYTHON_VERSION = (3, 10)
MIN_MEMORY_MB = 512
RECOMMENDED_MEMORY_MB = 2048

PROJECT_ROOT = Path(__file__).parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)


class StartupHealthCheck:
    """Performs pre-launch health checks"""
    
    def __init__(self):
        self.issues = []
        self.warnings = []
        self.info = []
        
    def check_python_version(self) -> bool:
        """Check Python version meets requirements"""
        current = sys.version_info[:2]
        if current < MIN_PYTHON_VERSION:
            self.issues.append(
                f"Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}+ required, "
                f"found {current[0]}.{current[1]}"
            )
            return False
        self.info.append(f"Python {current[0]}.{current[1]} ✓")
        return True
    
    def check_memory(self) -> bool:
        """Check available system memory"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            available_mb = mem.available / (1024 * 1024)
            total_mb = mem.total / (1024 * 1024)
            
            if available_mb < MIN_MEMORY_MB:
                self.issues.append(
                    f"Low memory: {available_mb:.0f}MB available, "
                    f"minimum {MIN_MEMORY_MB}MB required"
                )
                return False
            elif available_mb < RECOMMENDED_MEMORY_MB:
                self.warnings.append(
                    f"Low memory: {available_mb:.0f}MB available, "
                    f"recommended {RECOMMENDED_MEMORY_MB}MB+"
                )
            
            self.info.append(f"Memory: {available_mb:.0f}MB available / {total_mb:.0f}MB total ✓")
            return True
        except ImportError:
            self.warnings.append("psutil not installed - cannot check memory")
            return True
    
    def check_display(self) -> bool:
        """Check display is available"""
        if sys.platform == 'linux':
            display = os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')
            if not display:
                self.warnings.append(
                    "No DISPLAY or WAYLAND_DISPLAY set - GUI may not work"
                )
                return False
        self.info.append("Display available ✓")
        return True
    
    def check_qt(self) -> bool:
        """Check PyQt6 is available and functional"""
        try:
            from PyQt6.QtWidgets import QApplication
            from PyQt6.QtCore import QT_VERSION_STR
            self.info.append(f"PyQt6 (Qt {QT_VERSION_STR}) ✓")
            return True
        except ImportError as e:
            self.issues.append(f"PyQt6 not available: {e}")
            return False
        except Exception as e:
            self.issues.append(f"PyQt6 error: {e}")
            return False
    
    def check_dependencies(self) -> bool:
        """Check critical dependencies"""
        required = ['numpy']
        optional = ['scipy', 'requests', 'aiohttp']
        
        for mod in required:
            try:
                __import__(mod)
                self.info.append(f"{mod} ✓")
            except ImportError:
                self.issues.append(f"Required module missing: {mod}")
                return False
        
        for mod in optional:
            try:
                __import__(mod)
                self.info.append(f"{mod} ✓")
            except ImportError:
                self.warnings.append(f"Optional module missing: {mod}")
        
        return True
    
    def run_all_checks(self) -> bool:
        """Run all health checks"""
        checks = [
            ("Python Version", self.check_python_version),
            ("Memory", self.check_memory),
            ("Display", self.check_display),
            ("Qt Framework", self.check_qt),
            ("Dependencies", self.check_dependencies),
        ]
        
        all_passed = True
        for name, check_fn in checks:
            try:
                if not check_fn():
                    all_passed = False
            except Exception as e:
                self.issues.append(f"{name} check failed: {e}")
                all_passed = False
        
        return all_passed
    
    def print_report(self):
        """Print health check report"""
        print("\n" + "="*60)
        print("HydraRecon Startup Health Check")
        print("="*60)
        
        if self.info:
            print("\n✅ Passed:")
            for item in self.info:
                print(f"   • {item}")
        
        if self.warnings:
            print("\n⚠️  Warnings:")
            for item in self.warnings:
                print(f"   • {item}")
        
        if self.issues:
            print("\n❌ Issues:")
            for item in self.issues:
                print(f"   • {item}")
        
        print("="*60)


class LazyModuleLoader:
    """Lazy load heavy modules to improve startup time"""
    
    _modules = {}
    
    @classmethod
    def get_main_window(cls):
        """Lazy load main window"""
        if 'main_window' not in cls._modules:
            print("Loading GUI modules...")
            from gui.main_window import HydraReconMainWindow
            cls._modules['main_window'] = HydraReconMainWindow
        return cls._modules['main_window']
    
    @classmethod
    def get_config(cls):
        """Lazy load config"""
        if 'config' not in cls._modules:
            from core.config import Config
            cls._modules['config'] = Config()
        return cls._modules['config']
    
    @classmethod
    def get_database(cls, db_path: str):
        """Lazy load database"""
        if 'database' not in cls._modules:
            from core.database import DatabaseManager
            db = DatabaseManager(db_path)
            db.initialize()
            cls._modules['database'] = db
        return cls._modules['database']


class CrashRecovery:
    """Handles crash recovery and reporting"""
    
    CRASH_FILE = LOG_DIR / "last_crash.json"
    
    @classmethod
    def check_previous_crash(cls) -> bool:
        """Check if previous session crashed"""
        return cls.CRASH_FILE.exists()
    
    @classmethod
    def record_crash(cls, exc_type, exc_value, exc_tb):
        """Record crash information"""
        import json
        
        crash_data = {
            "timestamp": datetime.now().isoformat(),
            "exception_type": str(exc_type.__name__),
            "exception_value": str(exc_value),
            "traceback": traceback.format_exception(exc_type, exc_value, exc_tb),
            "python_version": sys.version,
            "platform": platform.platform(),
        }
        
        with open(cls.CRASH_FILE, 'w') as f:
            json.dump(crash_data, f, indent=2)
    
    @classmethod
    def clear_crash(cls):
        """Clear crash record on successful exit"""
        if cls.CRASH_FILE.exists():
            cls.CRASH_FILE.unlink()
    
    @classmethod
    def get_crash_info(cls) -> dict:
        """Get previous crash info"""
        import json
        if cls.CRASH_FILE.exists():
            with open(cls.CRASH_FILE) as f:
                return json.load(f)
        return {}


def setup_logging():
    """Setup application logging"""
    log_file = LOG_DIR / f"hydrarecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger('HydraRecon')


def suppress_qt_warnings():
    """Suppress non-critical Qt warnings"""
    from PyQt6.QtCore import qInstallMessageHandler, QtMsgType
    
    def handler(msg_type, context, message):
        # Suppress layout warnings (cosmetic only)
        if 'QLayout' in message:
            return
        # Suppress Wayland warnings
        if 'wayland' in message.lower():
            return
        # Log others
        if msg_type == QtMsgType.QtWarningMsg:
            logging.getLogger('Qt').warning(message)
        elif msg_type == QtMsgType.QtCriticalMsg:
            logging.getLogger('Qt').error(message)
    
    qInstallMessageHandler(handler)


def check_license():
    """Check license acceptance"""
    try:
        from core.license_acceptance import LicenseAcceptance
        la = LicenseAcceptance()
        
        if not la.check_acceptance():
            print("\n" + "="*60)
            print("LICENSE ACCEPTANCE REQUIRED")
            print("="*60)
            print("\nYou must accept the license agreement to use HydraRecon.")
            print("This software is for AUTHORIZED SECURITY TESTING ONLY.")
            print("\n" + "="*60)
            
            if not la.show_disclaimer_gui():
                print("\n❌ License not accepted. Exiting.")
                return False
    except ImportError:
        pass  # License module not available
    
    return True


def main():
    """Main entry point with all safety checks"""
    
    # Add project root to path
    sys.path.insert(0, str(PROJECT_ROOT))
    
    # Setup logging
    logger = setup_logging()
    logger.info("="*60)
    logger.info("HydraRecon Professional Edition Starting")
    logger.info("="*60)
    
    # Check for previous crash
    if CrashRecovery.check_previous_crash():
        crash_info = CrashRecovery.get_crash_info()
        logger.warning("Previous session crashed!")
        logger.warning(f"Crash time: {crash_info.get('timestamp')}")
        logger.warning(f"Error: {crash_info.get('exception_value')}")
    
    # Run health checks
    health = StartupHealthCheck()
    health_ok = health.run_all_checks()
    health.print_report()
    
    if not health_ok and health.issues:
        logger.error("Health check failed - cannot start")
        print("\n❌ Cannot start HydraRecon due to critical issues.")
        print("   Please resolve the issues above and try again.")
        return 1
    
    # Check license
    if not check_license():
        return 1
    
    # Install crash handler
    def crash_handler(exc_type, exc_value, exc_tb):
        logger.critical("CRASH!", exc_info=(exc_type, exc_value, exc_tb))
        CrashRecovery.record_crash(exc_type, exc_value, exc_tb)
        sys.__excepthook__(exc_type, exc_value, exc_tb)
    
    sys.excepthook = crash_handler
    
    # Start Qt application
    try:
        from PyQt6.QtWidgets import QApplication, QSplashScreen
        from PyQt6.QtGui import QPixmap, QFont
        from PyQt6.QtCore import Qt
        
        logger.info("Creating Qt application...")
        app = QApplication(sys.argv)
        app.setApplicationName("HydraRecon")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("HydraRecon Security")
        app.setStyle("Fusion")
        
        # Suppress Qt warnings
        suppress_qt_warnings()
        
        # Show splash screen
        splash = QSplashScreen()
        splash.setFont(QFont("Segoe UI", 12))
        splash.showMessage(
            "Loading HydraRecon...\n\nPreparing security assessment modules",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignHCenter
        )
        splash.show()
        app.processEvents()
        
        # Force garbage collection before loading heavy modules
        gc.collect()
        
        # Load modules
        splash.showMessage("Loading configuration...")
        app.processEvents()
        config = LazyModuleLoader.get_config()
        
        splash.showMessage("Initializing database...")
        app.processEvents()
        db = LazyModuleLoader.get_database(config.database_path)
        
        splash.showMessage("Loading GUI (this may take a moment)...")
        app.processEvents()
        
        MainWindow = LazyModuleLoader.get_main_window()
        
        splash.showMessage("Creating main window...")
        app.processEvents()
        
        window = MainWindow(config, db)
        
        # Close splash and show main window
        splash.finish(window)
        window.show()
        
        logger.info("HydraRecon started successfully")
        
        # Run event loop
        exit_code = app.exec()
        
        # Clean shutdown
        CrashRecovery.clear_crash()
        logger.info(f"HydraRecon exited with code {exit_code}")
        
        return exit_code
        
    except Exception as e:
        logger.critical(f"Failed to start: {e}")
        traceback.print_exc()
        CrashRecovery.record_crash(type(e), e, e.__traceback__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
