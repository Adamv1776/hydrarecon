# Core module initialization
from .config import Config
from .database import DatabaseManager
from .logger import setup_logging, get_logger

# Enterprise modules - import with graceful fallback
try:
    from .ai_engine import AIEngine
except ImportError:
    AIEngine = None

try:
    from .ai_assistant import AIAssistant
except ImportError:
    AIAssistant = None

try:
    from .automation import AutomationEngine
except ImportError:
    AutomationEngine = None

try:
    from .exploit_framework import ExploitFramework
except ImportError:
    ExploitFramework = None

try:
    from .reporting import ReportingEngine
except ImportError:
    ReportingEngine = None

try:
    from .session_manager import SessionManager
except ImportError:
    SessionManager = None

try:
    from .api_discovery import APIDiscoveryEngine
except ImportError:
    APIDiscoveryEngine = None

try:
    from .credential_spray import CredentialSprayEngine
except ImportError:
    CredentialSprayEngine = None

try:
    from .network_mapper import NetworkMapper
except ImportError:
    NetworkMapper = None

try:
    from .c2_framework import C2Framework
except ImportError:
    C2Framework = None

try:
    from .exploit_browser import ExploitBrowser
except ImportError:
    ExploitBrowser = None

try:
    from .forensics import ForensicsEngine
except ImportError:
    ForensicsEngine = None

__all__ = [
    'Config', 
    'DatabaseManager', 
    'setup_logging', 
    'get_logger',
    # Enterprise modules
    'AIEngine',
    'AIAssistant',
    'AutomationEngine',
    'ExploitFramework',
    'ReportingEngine',
    'SessionManager',
    'APIDiscoveryEngine',
    'CredentialSprayEngine',
    'NetworkMapper',
    'C2Framework',
    'ExploitBrowser',
    'ForensicsEngine',
]
