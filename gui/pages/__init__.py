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

# Revolutionary Security Modules (v3.0)
try:
    from .predictive_threat_intel_page import PredictiveThreatIntelPage
except ImportError:
    PredictiveThreatIntelPage = None

try:
    from .security_digital_twin_page import SecurityDigitalTwinPage
except ImportError:
    SecurityDigitalTwinPage = None

try:
    from .autonomous_healing_page import AutonomousHealingPage
except ImportError:
    AutonomousHealingPage = None

try:
    from .supply_chain_graph_page import SupplyChainGraphPage
except ImportError:
    SupplyChainGraphPage = None

try:
    from .zero_trust_validator_page import ZeroTrustValidatorPage
except ImportError:
    ZeroTrustValidatorPage = None

try:
    from .security_chaos_page import SecurityChaosPage
except ImportError:
    SecurityChaosPage = None

# Next-Generation Security Modules (v4.0)
try:
    from .deception_network_page import DeceptionNetworkPage
except ImportError:
    DeceptionNetworkPage = None

try:
    from .autonomous_redteam_page import AutonomousRedTeamPage
except ImportError:
    AutonomousRedTeamPage = None

try:
    from .adversarial_simulator_page import AdversarialSimulatorPage
except ImportError:
    AdversarialSimulatorPage = None

try:
    from .threat_intel_fusion_page import ThreatIntelFusionPage
except ImportError:
    ThreatIntelFusionPage = None

# Hyperdimensional Computing Module (v5.0)
try:
    from .hyperdimensional_security_page import HyperdimensionalSecurityPage
except ImportError:
    HyperdimensionalSecurityPage = None

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
    # Revolutionary Security Modules (v3.0)
    'PredictiveThreatIntelPage',
    'SecurityDigitalTwinPage',
    'AutonomousHealingPage',
    'SupplyChainGraphPage',
    'ZeroTrustValidatorPage',
    'SecurityChaosPage',
    # Next-Generation Security Modules (v4.0)
    'DeceptionNetworkPage',
    'AutonomousRedTeamPage',
    'AdversarialSimulatorPage',
    'ThreatIntelFusionPage',
    # Hyperdimensional Computing (v5.0)
    'HyperdimensionalSecurityPage',
]
