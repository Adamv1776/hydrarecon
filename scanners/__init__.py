# Scanners module initialization
from .base import BaseScanner, ScanResult, ScanStatus, ScanProgress, ScanQueue, ScanPriority
from .nmap_scanner import NmapScanner
from .hydra_scanner import HydraScanner
from .osint_scanner import OSINTScanner

# Try to import advanced OSINT scanner
try:
    from .osint_advanced import AdvancedOSINTScanner
    HAS_ADVANCED_OSINT = True
except ImportError:
    HAS_ADVANCED_OSINT = False
    AdvancedOSINTScanner = None

__all__ = [
    'BaseScanner', 'ScanResult', 'ScanStatus', 'ScanProgress', 'ScanQueue', 'ScanPriority',
    'NmapScanner', 'HydraScanner', 'OSINTScanner', 'AdvancedOSINTScanner', 'HAS_ADVANCED_OSINT'
]
