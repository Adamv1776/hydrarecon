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

__all__ = [
    'DashboardPage',
    'NmapPage',
    'HydraPage',
    'OSINTPage',
    'TargetsPage',
    'CredentialsPage',
    'VulnerabilitiesPage',
    'ReportsPage',
    'SettingsPage'
]
