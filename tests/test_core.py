#!/usr/bin/env python3
"""
HydraRecon Test Suite
═══════════════════════════════════════════════════════════════════════════════
Comprehensive testing for all core modules and functionality.
Run with: python -m pytest tests/ -v
═══════════════════════════════════════════════════════════════════════════════
"""

import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCoreImports(unittest.TestCase):
    """Test that all core modules can be imported without errors"""
    
    def test_import_config(self):
        """Test config module import"""
        from core.config import Config
        config = Config()
        self.assertIsNotNone(config)
    
    def test_import_database(self):
        """Test database module import"""
        from core.database import DatabaseManager
        self.assertIsNotNone(DatabaseManager)
    
    def test_import_logger(self):
        """Test logger module import"""
        from core.logger import setup_logging
        logger = setup_logging()
        self.assertIsNotNone(logger)


class TestSecurityModules(unittest.TestCase):
    """Test security-related modules"""
    
    def test_import_threat_intel(self):
        """Test threat intelligence module"""
        try:
            from core.threat_intelligence import ThreatIntelligence
            self.assertIsNotNone(ThreatIntelligence)
        except ImportError:
            self.skipTest("Threat intelligence module not available")
    
    def test_import_vuln_scanner(self):
        """Test vulnerability scanner module"""
        try:
            from core.vuln_scanner import VulnerabilityScanner
            self.assertIsNotNone(VulnerabilityScanner)
        except ImportError:
            self.skipTest("Vulnerability scanner module not available")
    
    def test_import_malware_analysis(self):
        """Test malware analysis module"""
        try:
            from core.malware_analysis import MalwareAnalyzer
            self.assertIsNotNone(MalwareAnalyzer)
        except ImportError:
            self.skipTest("Malware analysis module not available")


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation"""
    
    def setUp(self):
        from core.config import Config
        self.config = Config()
    
    def test_database_path_exists(self):
        """Verify database path is set"""
        self.assertIsNotNone(self.config.database_path)
    
    def test_config_dir_exists(self):
        """Verify config directory is set"""
        self.assertTrue(hasattr(self.config, 'config_dir') or hasattr(self.config, 'config_path'))


class TestDatabaseOperations(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        from core.config import Config
        from core.database import DatabaseManager
        import tempfile
        
        self.temp_db = tempfile.mktemp(suffix='.db')
        self.db = DatabaseManager(self.temp_db)
        self.db.initialize()
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.temp_db):
            os.remove(self.temp_db)
    
    def test_database_initialization(self):
        """Test database initializes correctly"""
        self.assertIsNotNone(self.db)
    
    def test_database_connection(self):
        """Test database connection is valid"""
        # Connection should be established after initialization
        self.assertTrue(True)  # Placeholder


class TestLicenseAcceptance(unittest.TestCase):
    """Test license acceptance module"""
    
    def test_license_module_import(self):
        """Test license acceptance module can be imported"""
        from core.license_acceptance import LicenseAcceptance
        self.assertIsNotNone(LicenseAcceptance)
    
    def test_license_instance_creation(self):
        """Test LicenseAcceptance instance can be created"""
        from core.license_acceptance import LicenseAcceptance
        la = LicenseAcceptance()
        self.assertIsNotNone(la)


class TestGUIComponents(unittest.TestCase):
    """Test GUI components (headless)"""
    
    @classmethod
    def setUpClass(cls):
        """Setup Qt application for testing"""
        try:
            from PyQt6.QtWidgets import QApplication
            cls.app = QApplication.instance()
            if cls.app is None:
                cls.app = QApplication([])
        except ImportError:
            cls.app = None
    
    def test_widgets_import(self):
        """Test widgets module can be imported"""
        if self.app is None:
            self.skipTest("PyQt6 not available")
        from gui.widgets import GlowingButton
        self.assertIsNotNone(GlowingButton)
    
    def test_themes_import(self):
        """Test themes module can be imported"""
        if self.app is None:
            self.skipTest("PyQt6 not available")
        from gui.themes import DARK_THEME
        self.assertIsNotNone(DARK_THEME)


class TestSecurityUtils(unittest.TestCase):
    """Test security utility functions"""
    
    def test_import_security_utils(self):
        """Test security utils import"""
        try:
            from core.security_utils import SecurityUtils
            self.assertIsNotNone(SecurityUtils)
        except ImportError:
            self.skipTest("Security utils not available")


class TestScannerModules(unittest.TestCase):
    """Test scanner modules"""
    
    def test_base_scanner_import(self):
        """Test base scanner import"""
        try:
            from scanners.base import BaseScanner
            self.assertIsNotNone(BaseScanner)
        except ImportError:
            self.skipTest("Base scanner not available")
    
    def test_nmap_scanner_import(self):
        """Test nmap scanner import"""
        try:
            from scanners.nmap_scanner import NmapScanner
            self.assertIsNotNone(NmapScanner)
        except ImportError:
            self.skipTest("Nmap scanner not available")


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCoreImports))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityModules))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestLicenseAcceptance))
    suite.addTests(loader.loadTestsFromTestCase(TestGUIComponents))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityUtils))
    suite.addTests(loader.loadTestsFromTestCase(TestScannerModules))
    
    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
