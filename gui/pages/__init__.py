#!/usr/bin/env python3
"""
HydraRecon GUI Pages Module
"""

from .dashboard import DashboardPage
from .nmap_page import NmapPage
from .hydra_page import HydraPage
from .osint_page import OSINTPage
from .targets_page import TargetsPage
from .credentials_page import CredentialsPage
from .vulnerabilities_page import VulnerabilitiesPage
from .reports_page import ReportsPage
from .settings_page import SettingsPage

# Enterprise modules
try:
    from .automation_page import AutomationPage
except ImportError:
    AutomationPage = None
    
try:
    from .attack_surface_page import AttackSurfacePage
except ImportError:
    AttackSurfacePage = None

try:
    from .api_discovery_page import APIDiscoveryPage
except ImportError:
    APIDiscoveryPage = None

try:
    from .credential_spray_page import CredentialSprayPage
except ImportError:
    CredentialSprayPage = None

try:
    from .network_mapper_page import NetworkMapperPage
except ImportError:
    NetworkMapperPage = None

try:
    from .c2_page import C2Page
except ImportError:
    C2Page = None

try:
    from .exploit_browser_page import ExploitBrowserPage
except ImportError:
    ExploitBrowserPage = None

try:
    from .forensics_page import ForensicsPage
except ImportError:
    ForensicsPage = None

try:
    from .hash_cracker_page import HashCrackerPage
except ImportError:
    HashCrackerPage = None

__all__ = [
    'DashboardPage',
    'NmapPage',
    'HydraPage',
    'OSINTPage',
    'TargetsPage',
    'CredentialsPage',
    'VulnerabilitiesPage',
    'ReportsPage',
    'SettingsPage',
    # Enterprise modules
    'AutomationPage',
    'AttackSurfacePage',
    'APIDiscoveryPage',
    'CredentialSprayPage',
    'NetworkMapperPage',
    'C2Page',
    'ExploitBrowserPage',
    'ForensicsPage',
    'HashCrackerPage',
]
