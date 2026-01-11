#!/usr/bin/env python3
"""
HydraRecon Core Module
═══════════════════════════════════════════════════════════════════════════════
LAZY LOADING ARCHITECTURE - Modules are only imported when first accessed.
This dramatically improves startup time from ~30s to ~3s.
═══════════════════════════════════════════════════════════════════════════════
"""

import importlib
import sys
from typing import Any, Dict, List, Optional

# Version
__version__ = "1.0.0"

# =============================================================================
# CORE MODULES - Always loaded (lightweight, required for basic operation)
# =============================================================================
from .config import Config
from .database import DatabaseManager

# Try to import logger (lightweight)
try:
    from .logger import setup_logging, get_logger
except ImportError:
    def setup_logging():
        pass
    def get_logger(name: str = "hydrarecon"):
        import logging
        return logging.getLogger(name)


# =============================================================================
# LAZY MODULE REGISTRY
# =============================================================================
# Maps attribute names to (module_path, attribute_name) tuples
# Modules are only loaded when accessed via __getattr__

_LAZY_MODULES: Dict[str, tuple] = {
    # AI/ML Modules
    'AIEngine': ('.ai_engine', 'AIEngine'),
    'AIAssistant': ('.ai_assistant', 'AIAssistant'),
    'AdvancedMLEngine': ('.advanced_ml_engine', 'AdvancedMLEngine'),
    'AdversarialMLEngine': ('.adversarial_ml', 'AdversarialMLEngine'),
    'CognitiveThreatEngine': ('.cognitive_threat_engine', 'CognitiveThreatEngine'),
    'AnomalyDetectionEngine': ('.anomaly_detection', 'AnomalyDetectionEngine'),
    'AIThreatNarrator': ('.ai_threat_narrator', 'AIThreatNarrator'),
    'DeepfakeDetector': ('.deepfake_detection', 'DeepfakeDetector'),
    
    # Network Scanning
    'NetworkMapper': ('.network_mapper', 'NetworkMapper'),
    'PortScanner': ('.port_scanner', 'PortScanner'),
    'VulnerabilityScanner': ('.vulnerability_scanner', 'VulnerabilityScanner'),
    'ServiceDiscovery': ('.service_discovery', 'ServiceDiscovery'),
    
    # Web Security
    'APIDiscoveryEngine': ('.api_discovery', 'APIDiscoveryEngine'),
    'AdvancedAPISecurityEngine': ('.advanced_api_security', 'AdvancedAPISecurityEngine'),
    'WebApplicationScanner': ('.web_scanner', 'WebApplicationScanner'),
    'AdvancedHTTPClient': ('.advanced_http', 'AdvancedHTTPClient'),
    'GraphQLSecurityTester': ('.graphql_security', 'GraphQLSecurityTester'),
    'SubdomainEnumerator': ('.subdomain_enum', 'SubdomainEnumerator'),
    
    # Exploit/Attack
    'ExploitFramework': ('.exploit_framework', 'ExploitFramework'),
    'CredentialSprayEngine': ('.credential_spray', 'CredentialSprayEngine'),
    'AttackSimulator': ('.attack_simulation', 'AttackSimulator'),
    'AttackReplayEngine': ('.attack_replay', 'AttackReplayEngine'),
    'AutonomousAttackEngine': ('.autonomous_attack', 'AutonomousAttackEngine'),
    'AutonomousPentestEngine': ('.autonomous_pentest', 'AutonomousPentestEngine'),
    'ExploitChainBuilder': ('.exploit_chain', 'ExploitChainBuilder'),
    'ZeroDayResearcher': ('.zero_day_research', 'ZeroDayResearcher'),
    
    # Wireless Security
    'AdvancedWirelessSecurityEngine': ('.advanced_wireless_security', 'AdvancedWirelessSecurityEngine'),
    'WirelessPentestEngine': ('.wireless_pentest', 'WirelessPentestEngine'),
    'WiFiSecurityEngine': ('.wifi_security', 'WiFiSecurityEngine'),
    'DeauthDetector': ('.esp32_deauth_detector', 'DeauthDetector'),
    
    # Cloud Security
    'CloudSecurityScanner': ('.cloud_security', 'CloudSecurityScanner'),
    'CloudPostureManager': ('.cloud_posture_management', 'CloudPostureManager'),
    'ContainerSecurityScanner': ('.container_security', 'ContainerSecurityScanner'),
    'ServerlessSecurityEngine': ('.serverless_security', 'ServerlessSecurityEngine'),
    'KubernetesSecurityEngine': ('.kubernetes_security', 'KubernetesSecurityEngine'),
    
    # IoT/Hardware
    'AdvancedIoTSecurityEngine': ('.advanced_iot_security', 'AdvancedIoTSecurityEngine'),
    'IoTSecurityScanner': ('.iot_security', 'IoTSecurityScanner'),
    'FirmwareAnalyzer': ('.firmware_analysis', 'FirmwareAnalyzer'),
    'AdvancedFirmwareAnalyzer': ('.advanced_firmware_analysis', 'AdvancedFirmwareAnalyzer'),
    'HardwareHackingEngine': ('.hardware_hacking', 'HardwareHackingEngine'),
    'ScadaSecurityEngine': ('.scada_security', 'ScadaSecurityEngine'),
    'DroneIntegration': ('.drone_integration', 'DroneIntegration'),
    
    # Active Directory
    'ADSecurityScanner': ('.ad_attacks', 'ADSecurityScanner'),
    'AdvancedADSecurityEngine': ('.advanced_ad_security', 'AdvancedADSecurityEngine'),
    
    # Intelligence
    'DarkWebIntelligence': ('.dark_web_intelligence', 'DarkWebIntelligence'),
    'DarkWebIntel': ('.dark_web_intel', 'DarkWebIntel'),
    'ThreatIntelligence': ('.threat_intelligence', 'ThreatIntelligence'),
    'OSINTEngine': ('.osint', 'OSINTEngine'),
    
    # Forensics
    'AdvancedMemoryForensicsEngine': ('.advanced_memory_forensics', 'AdvancedMemoryForensicsEngine'),
    'BlockchainForensics': ('.blockchain_forensics', 'BlockchainForensics'),
    'BlockchainEvidenceEngine': ('.blockchain_evidence', 'BlockchainEvidenceEngine'),
    'MobileForensicsEngine': ('.mobile_forensics', 'MobileForensicsEngine'),
    
    # Malware
    'AdvancedMalwareSandbox': ('.advanced_malware_sandbox', 'AdvancedMalwareSandbox'),
    'MalwareAnalyzer': ('.malware_analysis', 'MalwareAnalyzer'),
    'EDREvasionEngine': ('.edr_evasion', 'EDREvasionEngine'),
    
    # Reporting/Compliance
    'ReportingEngine': ('.reporting', 'ReportingEngine'),
    'AdvancedReportingEngine': ('.advanced_reporting', 'AdvancedReportingEngine'),
    'ComplianceAuditor': ('.compliance_audit', 'ComplianceAuditor'),
    'RegulatoryComplianceEngine': ('.regulatory_compliance', 'RegulatoryComplianceEngine'),
    
    # Automation
    'AutomationEngine': ('.automation', 'AutomationEngine'),
    'SessionManager': ('.session_manager', 'SessionManager'),
    'ScheduledScanner': ('.scheduled_scanner', 'ScheduledScanner'),
    'EventCorrelator': ('.event_correlation', 'EventCorrelator'),
    'IncidentResponseEngine': ('.incident_response', 'IncidentResponseEngine'),
    
    # Security Tools
    'PhishingSimulator': ('.phishing_simulator', 'PhishingSimulator'),
    'RedTeamToolkit': ('.red_team_tools', 'RedTeamToolkit'),
    'SocialEngineeringEngine': ('.social_engineering', 'SocialEngineeringEngine'),
    'PasswordAuditor': ('.password_audit', 'PasswordAuditor'),
    'DeceptionEngine': ('.deception', 'DeceptionEngine'),
    
    # Database Security
    'AdvancedDatabaseSecurityEngine': ('.advanced_database_security', 'AdvancedDatabaseSecurityEngine'),
    'SQLInjectionEngine': ('.sql_injection', 'SQLInjectionEngine'),
    
    # SSL/TLS
    'AdvancedSSLSecurityEngine': ('.advanced_ssl_security', 'AdvancedSSLSecurityEngine'),
    'SSLScanner': ('.ssl_scanner', 'SSLScanner'),
    
    # DNS
    'AdvancedDNSSecurityEngine': ('.advanced_dns_security', 'AdvancedDNSSecurityEngine'),
    'DNSReconEngine': ('.dns_recon', 'DNSReconEngine'),
    
    # Traffic Analysis
    'AdvancedTrafficAnalyzer': ('.advanced_traffic_analysis', 'AdvancedTrafficAnalyzer'),
    'NetworkTrafficAnalyzer': ('.traffic_analysis', 'NetworkTrafficAnalyzer'),
    
    # Mobile
    'AdvancedMobileSecurityEngine': ('.advanced_mobile_security', 'AdvancedMobileSecurityEngine'),
    'MobileSecurityScanner': ('.mobile_security', 'MobileSecurityScanner'),
    
    # Browser
    'BrowserExploitationEngine': ('.browser_exploitation', 'BrowserExploitationEngine'),
    
    # C2/Evasion
    'C2Framework': ('.c2_framework', 'C2Framework'),
    'ProtocolObfuscator': ('.protocol_obfuscation', 'ProtocolObfuscator'),
    
    # Supply Chain
    'SupplyChainSecurityEngine': ('.supply_chain_security', 'SupplyChainSecurityEngine'),
    
    # Asset Management
    'AssetInventory': ('.asset_inventory', 'AssetInventory'),
    'CMDBIntegration': ('.cmdb', 'CMDBIntegration'),
    
    # Access Control
    'AccessControlAnalyzer': ('.access_control', 'AccessControlAnalyzer'),
    'BiometricSecurityEngine': ('.biometric_security', 'BiometricSecurityEngine'),
    'BehavioralBiometrics': ('.behavioral_biometrics', 'BehavioralBiometrics'),
    
    # Collaboration
    'CollaborationHub': ('.collaboration_hub', 'CollaborationHub'),
    'CollaborationEngine': ('.collaboration', 'CollaborationEngine'),
    
    # VPN/Privacy
    'VPNSecurityScanner': ('.vpn_security', 'VPNSecurityScanner'),
    'PrivacyEngine': ('.privacy_engine', 'PrivacyEngine'),
    
    # DLP
    'DLPEngine': ('.dlp', 'DLPEngine'),
    
    # Backup
    'BackupAssessmentEngine': ('.backup_assessment', 'BackupAssessmentEngine'),
    
    # BCP
    'BCPEngine': ('.bcp', 'BCPEngine'),
    
    # Blue Team
    'BlueTeamToolkit': ('.blue_team', 'BlueTeamToolkit'),
    
    # Bug Bounty
    'BugBountyCopilot': ('.bug_bounty_copilot', 'BugBountyCopilot'),
    
    # Audit
    'AuditLogger': ('.audit_log', 'AuditLogger'),
    'ConfigBaseline': ('.config_baseline', 'ConfigBaseline'),
    
    # Data Sources
    'DataSourceManager': ('.data_sources', 'DataSourceManager'),
    
    # Quantum
    'QuantumSecurityEngine': ('.quantum_security', 'QuantumSecurityEngine'),
    
    # Performance (these are also lazy-loaded)
    'MemoryManager': ('.performance', 'MemoryManager'),
    'PerformanceProfiler': ('.performance', 'PerformanceProfiler'),
    
    # Telemetry
    'TelemetryClient': ('.telemetry', 'TelemetryClient'),
}

# Track what's been loaded
_loaded_modules: Dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    """
    Lazy load modules when they're first accessed.
    This is the magic that makes `from core import SomeEngine` fast.
    """
    if name in _LAZY_MODULES:
        if name not in _loaded_modules:
            module_path, attr_name = _LAZY_MODULES[name]
            try:
                # Import the module
                module = importlib.import_module(module_path, package='core')
                # Get the attribute
                _loaded_modules[name] = getattr(module, attr_name)
            except (ImportError, AttributeError) as e:
                # Return None for missing optional modules
                _loaded_modules[name] = None
        
        return _loaded_modules[name]
    
    raise AttributeError(f"module 'core' has no attribute '{name}'")


def __dir__() -> List[str]:
    """Return list of available attributes for tab completion"""
    return list(_LAZY_MODULES.keys()) + [
        'Config', 'DatabaseManager', 'setup_logging', 'get_logger',
        '__version__', 'get_loaded_modules', 'preload_modules'
    ]


def get_loaded_modules() -> List[str]:
    """Return list of modules that have been loaded"""
    return list(_loaded_modules.keys())


def preload_modules(modules: List[str] = None):
    """
    Preload specific modules if needed for performance.
    Call this after startup if you want certain modules ready.
    """
    if modules is None:
        # Preload commonly used modules
        modules = ['ReportingEngine', 'NetworkMapper', 'OSINTEngine']
    
    for name in modules:
        if name in _LAZY_MODULES:
            _ = __getattr__(name)  # Trigger lazy load


# =============================================================================
# MODULE GROUPS - For bulk imports when needed
# =============================================================================

def get_ai_modules() -> Dict[str, Any]:
    """Get all AI/ML related modules"""
    ai_names = [
        'AIEngine', 'AIAssistant', 'AdvancedMLEngine', 
        'CognitiveThreatEngine', 'AnomalyDetectionEngine'
    ]
    return {name: __getattr__(name) for name in ai_names}


def get_network_modules() -> Dict[str, Any]:
    """Get all network scanning modules"""
    net_names = [
        'NetworkMapper', 'PortScanner', 'VulnerabilityScanner',
        'ServiceDiscovery'
    ]
    return {name: __getattr__(name) for name in net_names}


def get_web_modules() -> Dict[str, Any]:
    """Get all web security modules"""
    web_names = [
        'APIDiscoveryEngine', 'WebApplicationScanner', 
        'GraphQLSecurityTester', 'SubdomainEnumerator'
    ]
    return {name: __getattr__(name) for name in web_names}


# =============================================================================
# COMPATIBILITY - Old-style imports still work via __getattr__
# =============================================================================
# The following patterns are all supported:
#
# from core import Config  # Direct (always loaded)
# from core import AIEngine  # Lazy loaded
# 
# import core
# engine = core.AIEngine  # Also lazy loaded
#
# from core import get_ai_modules
# modules = get_ai_modules()  # Bulk lazy load
# =============================================================================
