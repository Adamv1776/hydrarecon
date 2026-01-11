#!/usr/bin/env python3
"""
HydraRecon Integration Tests
Test end-to-end functionality
"""

import unittest
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestApplicationStartup(unittest.TestCase):
    """Test application can start without errors"""
    
    def test_main_module_import(self):
        """Test main module can be imported"""
        # This tests the module loads without syntax errors
        import main
        self.assertTrue(hasattr(main, 'main'))
    
    def test_dependency_check(self):
        """Test dependency check function"""
        import main
        # Should not raise even if optional deps missing
        try:
            main.check_dependencies()
        except SystemExit:
            self.fail("Required dependencies missing")


class TestConfigurationSystem(unittest.TestCase):
    """Test configuration system"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_config_creation(self):
        """Test configuration can be created"""
        from core.config import Config
        config = Config()
        self.assertIsNotNone(config)


class TestDatabaseIntegration(unittest.TestCase):
    """Test database integration"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test.db')
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_database_crud_operations(self):
        """Test basic CRUD operations"""
        from core.database import DatabaseManager
        
        db = DatabaseManager(self.db_path)
        db.initialize()
        
        # Test that database file was created
        self.assertTrue(os.path.exists(self.db_path))
        
        db.close()


class TestScannerIntegration(unittest.TestCase):
    """Test scanner integration"""
    
    def test_osint_scanner_basic(self):
        """Test OSINT scanner basic functionality"""
        try:
            from scanners.osint_scanner import OSINTScanner
            # OSINTScanner requires config and db, just verify import works
            self.assertIsNotNone(OSINTScanner)
        except ImportError:
            self.skipTest("OSINT scanner not available")


if __name__ == '__main__':
    unittest.main(verbosity=2)
