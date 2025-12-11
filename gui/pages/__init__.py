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

# Advanced AI/ML modules
try:
    from .neural_fingerprint_page import NeuralFingerprintPage
except ImportError:
    NeuralFingerprintPage = None

try:
    from .quantum_c2_page import QuantumC2Page
except ImportError:
    QuantumC2Page = None

try:
    from .stego_exfil_page import StegoExfilPage
except ImportError:
    StegoExfilPage = None

try:
    from .evolutionary_exploit_page import EvolutionaryExploitPage
except ImportError:
    EvolutionaryExploitPage = None

try:
    from .hardware_implant_page import HardwareImplantPage
except ImportError:
    HardwareImplantPage = None

# Revolutionary AI-Powered Security Modules
try:
    from .autonomous_attack_page import AutonomousAttackPage
except ImportError:
    AutonomousAttackPage = None

try:
    from .cognitive_threat_page import CognitiveThreatPage
except ImportError:
    CognitiveThreatPage = None

try:
    from .polymorphic_engine_page import PolymorphicEnginePage
except ImportError:
    PolymorphicEnginePage = None

# Premium Experience Modules
try:
    from .attack_map_page import LiveAttackMapPage
except ImportError:
    LiveAttackMapPage = None

try:
    from .ai_narrator_page import AIThreatNarratorPage
except ImportError:
    AIThreatNarratorPage = None

try:
    from .exploit_chain_page import ExploitChainBuilderPage
except ImportError:
    ExploitChainBuilderPage = None

try:
    from .gamification_page import GamificationPage
except ImportError:
    GamificationPage = None

try:
    from .attack_replay_page import AttackReplayPage
except ImportError:
    AttackReplayPage = None

try:
    from .collaboration_hub_page import CollaborationHubPage
except ImportError:
    CollaborationHubPage = None

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
    # Advanced AI/ML modules
    'NeuralFingerprintPage',
    'QuantumC2Page',
    'StegoExfilPage',
    'EvolutionaryExploitPage',
    'HardwareImplantPage',
    # Revolutionary AI-Powered Security Modules
    'AutonomousAttackPage',
    'CognitiveThreatPage',
    'PolymorphicEnginePage',
    # Premium Experience Modules
    'LiveAttackMapPage',
    'AIThreatNarratorPage',
    'ExploitChainBuilderPage',
    'GamificationPage',
    'AttackReplayPage',
    'CollaborationHubPage',
]
