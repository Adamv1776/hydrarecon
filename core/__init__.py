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

# Advanced 3D Visualization modules
try:
    from .visualization_3d_engine import Visualization3DEngine
except ImportError:
    Visualization3DEngine = None

try:
    from .network_topology_3d import NetworkTopology3D
except ImportError:
    NetworkTopology3D = None

try:
    from .attack_path_visualizer import AttackPathVisualizer
except ImportError:
    AttackPathVisualizer = None

try:
    from .threat_globe import ThreatGlobe
except ImportError:
    ThreatGlobe = None

try:
    from .wifi_sensing_3d import WiFiSensing3D
except ImportError:
    WiFiSensing3D = None

try:
    from .particle_system import ParticleSystem
except ImportError:
    ParticleSystem = None

try:
    from .data_flow_visualizer import DataFlowVisualizer
except ImportError:
    DataFlowVisualizer = None

try:
    from .exploit_chain_visualizer import ExploitChainVisualizer
except ImportError:
    ExploitChainVisualizer = None

try:
    from .vulnerability_landscape import VulnerabilityLandscape
except ImportError:
    VulnerabilityLandscape = None

# Advanced Interface modules
try:
    from .vr_ar_interface import VRARInterface
except ImportError:
    VRARInterface = None

try:
    from .voice_control import VoiceControlSystem
except ImportError:
    VoiceControlSystem = None

try:
    from .holographic_display import HolographicDisplay
except ImportError:
    HolographicDisplay = None

try:
    from .neural_interface import NeuralInterface
except ImportError:
    NeuralInterface = None

# Advanced Security modules
try:
    from .realtime_collaboration import RealtimeCollaboration
except ImportError:
    RealtimeCollaboration = None

try:
    from .advanced_ml_engine import AdvancedMLEngine
except ImportError:
    AdvancedMLEngine = None

try:
    from .hardware_integration import HardwareIntegration
except ImportError:
    HardwareIntegration = None

try:
    from .blockchain_evidence import BlockchainEvidence
except ImportError:
    BlockchainEvidence = None

try:
    from .quantum_security import QuantumSecurity
except ImportError:
    QuantumSecurity = None

try:
    from .drone_integration import DroneIntegration
except ImportError:
    DroneIntegration = None

try:
    from .biometric_security import BiometricSecurity
except ImportError:
    BiometricSecurity = None

# Additional Advanced Modules
try:
    from .advanced_reporting import AdvancedReportingEngine, Finding, ReportFormat, ReportType
except ImportError:
    AdvancedReportingEngine = None
    Finding = None
    ReportFormat = None
    ReportType = None

try:
    from .autonomous_pentest import AutonomousPenTestEngine, AttackPhase, AttackPath
except ImportError:
    AutonomousPenTestEngine = None
    AttackPhase = None
    AttackPath = None

try:
    from .dark_web_intelligence import DarkWebIntelligence, DarkWebMention, ThreatActor
except ImportError:
    DarkWebIntelligence = None
    DarkWebMention = None
    ThreatActor = None

try:
    from .supply_chain_security import SupplyChainSecurity, SBOM, SupplyChainThreat
except ImportError:
    SupplyChainSecurity = None
    SBOM = None
    SupplyChainThreat = None

# Advanced IoT Security
try:
    from .advanced_iot_security import (
        AdvancedIoTSecurity, IoTDevice, IoTVulnerability, 
        FirmwareAnalysis, IoTDeviceDiscovery, IoTVulnerabilityScanner
    )
except ImportError:
    AdvancedIoTSecurity = None
    IoTDevice = None
    IoTVulnerability = None
    FirmwareAnalysis = None
    IoTDeviceDiscovery = None
    IoTVulnerabilityScanner = None

# Cloud Security Posture Management
try:
    from .cloud_posture_management import (
        CloudSecurityPostureManager, SecurityFinding, CloudResource,
        ComplianceReport, AWSSecurityAnalyzer
    )
except ImportError:
    CloudSecurityPostureManager = None
    SecurityFinding = None
    CloudResource = None
    ComplianceReport = None
    AWSSecurityAnalyzer = None

# Advanced Wireless Security
try:
    from .advanced_wireless_security import (
        AdvancedWirelessSecurity, WirelessNetwork, BluetoothDevice,
        WirelessVulnerability, WiFiScanner, BluetoothScanner
    )
except ImportError:
    AdvancedWirelessSecurity = None
    WirelessNetwork = None
    BluetoothDevice = None
    WirelessVulnerability = None
    WiFiScanner = None
    BluetoothScanner = None

# Social Engineering Defense
try:
    from .social_engineering_defense import (
        SocialEngineeringDefense, EmailSecurityAnalyzer, PhishingTemplate,
        PhishingCampaign, SecurityAwarenessTraining, EmailAnalysis
    )
except ImportError:
    SocialEngineeringDefense = None
    EmailSecurityAnalyzer = None
    PhishingTemplate = None
    PhishingCampaign = None
    SecurityAwarenessTraining = None
    EmailAnalysis = None

# Advanced Memory Forensics
try:
    from .advanced_memory_forensics import (
        AdvancedMemoryForensics, MemoryDumpAnalyzer, MemoryProcess,
        MalwareIndicator, ExtractedCredential, MalwareDetector
    )
except ImportError:
    AdvancedMemoryForensics = None
    MemoryDumpAnalyzer = None
    MemoryProcess = None
    MalwareIndicator = None
    ExtractedCredential = None
    MalwareDetector = None

# Advanced API Security Testing
try:
    from .advanced_api_security import (
        AdvancedAPISecurityTesting, APIDiscovery, JWTAnalyzer,
        APISecurityScanner, GraphQLSecurityScanner, APIEndpoint, APIVulnerability
    )
except ImportError:
    AdvancedAPISecurityTesting = None
    APIDiscovery = None
    JWTAnalyzer = None
    APISecurityScanner = None
    GraphQLSecurityScanner = None
    APIEndpoint = None
    APIVulnerability = None

# Network Attack Simulation
try:
    from .network_attack_simulation import (
        AdvancedNetworkAttackSimulation, NetworkRecon, VulnerabilityAnalyzer,
        AttackSimulator, RedTeamAutomation, AdversaryEmulation, AttackTechniqueLibrary
    )
except ImportError:
    AdvancedNetworkAttackSimulation = None
    NetworkRecon = None
    VulnerabilityAnalyzer = None
    AttackSimulator = None
    RedTeamAutomation = None
    AdversaryEmulation = None
    AttackTechniqueLibrary = None

# Advanced Mobile Security
try:
    from .advanced_mobile_security import (
        AdvancedMobileSecurity, AndroidAnalyzer, IOSAnalyzer,
        MobileSecurityScanner, DynamicAnalyzer, MobileTrafficAnalyzer
    )
except ImportError:
    AdvancedMobileSecurity = None
    AndroidAnalyzer = None
    IOSAnalyzer = None
    MobileSecurityScanner = None
    DynamicAnalyzer = None
    MobileTrafficAnalyzer = None

# ICS/SCADA Security
try:
    from .ics_scada_security import (
        ICSSecurityModule, ModbusScanner, S7CommScanner, DNP3Scanner,
        ICSVulnerabilityScanner, ICSSecurityAssessment, ICSAnomalyDetection
    )
except ImportError:
    ICSSecurityModule = None
    ModbusScanner = None
    S7CommScanner = None
    DNP3Scanner = None
    ICSVulnerabilityScanner = None
    ICSSecurityAssessment = None
    ICSAnomalyDetection = None

# Advanced Firmware Analysis
try:
    from .advanced_firmware_analysis import (
        AdvancedFirmwareAnalysis, FirmwareAnalysisEngine, BinaryAnalyzer,
        FilesystemExtractor, CredentialScanner, CryptoAnalyzer
    )
except ImportError:
    AdvancedFirmwareAnalysis = None
    FirmwareAnalysisEngine = None
    BinaryAnalyzer = None
    FilesystemExtractor = None
    CredentialScanner = None
    CryptoAnalyzer = None

# Advanced Malware Sandbox
try:
    from .advanced_malware_sandbox import (
        AdvancedMalwareAnalysis, MalwareSandbox, PEAnalyzer,
        ELFAnalyzer, YaraEngine, BehaviorAnalyzer, NetworkAnalyzer
    )
except ImportError:
    AdvancedMalwareAnalysis = None
    MalwareSandbox = None
    PEAnalyzer = None
    ELFAnalyzer = None
    YaraEngine = None
    BehaviorAnalyzer = None
    NetworkAnalyzer = None

# Advanced AD Security
try:
    from .advanced_ad_security import (
        AdvancedADSecurity, ADSecurityAssessment, KerberosSecurityAnalyzer,
        DelegationAnalyzer, ACLAnalyzer, AttackPathFinder, GPOSecurityAnalyzer
    )
except ImportError:
    AdvancedADSecurity = None
    ADSecurityAssessment = None
    KerberosSecurityAnalyzer = None
    DelegationAnalyzer = None
    ACLAnalyzer = None
    AttackPathFinder = None
    GPOSecurityAnalyzer = None

# Advanced Network Traffic Analysis
try:
    from .advanced_traffic_analysis import (
        AdvancedNetworkTrafficAnalysis, TrafficAnalyzer, PacketParser,
        PcapReader, ConnectionTracker, ThreatDetector
    )
except ImportError:
    AdvancedNetworkTrafficAnalysis = None
    TrafficAnalyzer = None
    PacketParser = None
    PcapReader = None
    ConnectionTracker = None
    ThreatDetector = None

# Advanced DNS Security
try:
    from .advanced_dns_security import (
        AdvancedDNSSecurity, DNSTunnelingDetector, DGADetector,
        DNSRebindingDetector, DNSSECValidator, SubdomainTakeoverScanner
    )
except ImportError:
    AdvancedDNSSecurity = None
    DNSTunnelingDetector = None
    DGADetector = None
    DNSRebindingDetector = None
    DNSSECValidator = None
    SubdomainTakeoverScanner = None

# Advanced SSL/TLS Security
try:
    from .advanced_ssl_security import (
        AdvancedSSLSecurity, SSLScanner, CertificateValidator,
        VulnerabilityScanner as SSLVulnerabilityScanner, CipherSuiteAnalyzer
    )
except ImportError:
    AdvancedSSLSecurity = None
    SSLScanner = None
    CertificateValidator = None
    SSLVulnerabilityScanner = None
    CipherSuiteAnalyzer = None

# Advanced Database Security
try:
    from .advanced_database_security import (
        AdvancedDatabaseSecurity, SQLInjectionTester, NoSQLInjectionTester,
        DatabaseScanner, PrivilegeAnalyzer, ConfigurationAuditor, SensitiveDataScanner
    )
except ImportError:
    AdvancedDatabaseSecurity = None
    SQLInjectionTester = None
    NoSQLInjectionTester = None
    DatabaseScanner = None
    PrivilegeAnalyzer = None
    ConfigurationAuditor = None
    SensitiveDataScanner = None

# Incident Response Automation
try:
    from .incident_response_automation import (
        AdvancedIncidentResponse, EvidenceCollector, ContainmentEngine,
        IncidentTriager, PlaybookExecutor, TimelineBuilder
    )
except ImportError:
    AdvancedIncidentResponse = None
    EvidenceCollector = None
    ContainmentEngine = None
    IncidentTriager = None
    PlaybookExecutor = None
    TimelineBuilder = None

# Threat Hunting Automation
try:
    from .threat_hunting_automation import (
        ThreatHuntingAutomation, ThreatHunter, HuntingPlaybook,
        IOCCorrelator, BehaviorAnalytics, HuntingHypothesis
    )
except ImportError:
    ThreatHuntingAutomation = None
    ThreatHunter = None
    HuntingPlaybook = None
    IOCCorrelator = None
    BehaviorAnalytics = None
    HuntingHypothesis = None

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
    # 3D Visualization
    'Visualization3DEngine',
    'NetworkTopology3D',
    'AttackPathVisualizer',
    'ThreatGlobe',
    'WiFiSensing3D',
    'ParticleSystem',
    'DataFlowVisualizer',
    'ExploitChainVisualizer',
    'VulnerabilityLandscape',
    # Advanced Interfaces
    'VRARInterface',
    'VoiceControlSystem',
    'HolographicDisplay',
    'NeuralInterface',
    # Advanced Security
    'RealtimeCollaboration',
    'AdvancedMLEngine',
    'HardwareIntegration',
    'BlockchainEvidence',
    'QuantumSecurity',
    'DroneIntegration',
    'BiometricSecurity',
    # Additional Advanced Modules
    'AdvancedReportingEngine',
    'Finding',
    'ReportFormat',
    'ReportType',
    'AutonomousPenTestEngine',
    'AttackPhase',
    'AttackPath',
    'DarkWebIntelligence',
    'DarkWebMention',
    'ThreatActor',
    'SupplyChainSecurity',
    'SBOM',
    'SupplyChainThreat',
    # Advanced IoT Security
    'AdvancedIoTSecurity',
    'IoTDevice',
    'IoTVulnerability',
    'FirmwareAnalysis',
    'IoTDeviceDiscovery',
    'IoTVulnerabilityScanner',
    # Cloud Security Posture Management
    'CloudSecurityPostureManager',
    'SecurityFinding',
    'CloudResource',
    'ComplianceReport',
    'AWSSecurityAnalyzer',
    # Advanced Wireless Security
    'AdvancedWirelessSecurity',
    'WirelessNetwork',
    'BluetoothDevice',
    'WirelessVulnerability',
    'WiFiScanner',
    'BluetoothScanner',
    # Social Engineering Defense
    'SocialEngineeringDefense',
    'EmailSecurityAnalyzer',
    'PhishingTemplate',
    'PhishingCampaign',
    'SecurityAwarenessTraining',
    'EmailAnalysis',
    # Advanced Memory Forensics
    'AdvancedMemoryForensics',
    'MemoryDumpAnalyzer',
    'MemoryProcess',
    'MalwareIndicator',
    'ExtractedCredential',
    'MalwareDetector',
    # Advanced API Security Testing
    'AdvancedAPISecurityTesting',
    'APIDiscovery',
    'JWTAnalyzer',
    'APISecurityScanner',
    'GraphQLSecurityScanner',
    'APIEndpoint',
    'APIVulnerability',
    # Network Attack Simulation
    'AdvancedNetworkAttackSimulation',
    'NetworkRecon',
    'VulnerabilityAnalyzer',
    'AttackSimulator',
    'RedTeamAutomation',
    'AdversaryEmulation',
    'AttackTechniqueLibrary',
    # Advanced Mobile Security
    'AdvancedMobileSecurity',
    'AndroidAnalyzer',
    'IOSAnalyzer',
    'MobileSecurityScanner',
    'DynamicAnalyzer',
    'MobileTrafficAnalyzer',
    # ICS/SCADA Security
    'ICSSecurityModule',
    'ModbusScanner',
    'S7CommScanner',
    'DNP3Scanner',
    'ICSVulnerabilityScanner',
    'ICSSecurityAssessment',
    'ICSAnomalyDetection',
    # Advanced Firmware Analysis
    'AdvancedFirmwareAnalysis',
    'FirmwareAnalysisEngine',
    'BinaryAnalyzer',
    'FilesystemExtractor',
    'CredentialScanner',
    'CryptoAnalyzer',
    # Advanced Malware Sandbox
    'AdvancedMalwareAnalysis',
    'MalwareSandbox',
    'PEAnalyzer',
    'ELFAnalyzer',
    'YaraEngine',
    'BehaviorAnalyzer',
    'NetworkAnalyzer',
    # Advanced AD Security
    'AdvancedADSecurity',
    'ADSecurityAssessment',
    'KerberosSecurityAnalyzer',
    'DelegationAnalyzer',
    'ACLAnalyzer',
    'AttackPathFinder',
    'GPOSecurityAnalyzer',
    # Advanced Network Traffic Analysis
    'AdvancedNetworkTrafficAnalysis',
    'TrafficAnalyzer',
    'PacketParser',
    'PcapReader',
    'ConnectionTracker',
    'ThreatDetector',
    # Advanced DNS Security
    'AdvancedDNSSecurity',
    'DNSTunnelingDetector',
    'DGADetector',
    'DNSRebindingDetector',
    'DNSSECValidator',
    'SubdomainTakeoverScanner',
    # Advanced SSL/TLS Security
    'AdvancedSSLSecurity',
    'SSLScanner',
    'CertificateValidator',
    'SSLVulnerabilityScanner',
    'CipherSuiteAnalyzer',
    # Advanced Database Security
    'AdvancedDatabaseSecurity',
    'SQLInjectionTester',
    'NoSQLInjectionTester',
    'DatabaseScanner',
    'PrivilegeAnalyzer',
    'ConfigurationAuditor',
    'SensitiveDataScanner',
    # Incident Response Automation
    'AdvancedIncidentResponse',
    'EvidenceCollector',
    'ContainmentEngine',
    'IncidentTriager',
    'PlaybookExecutor',
    'TimelineBuilder',
    # Threat Hunting Automation
    'ThreatHuntingAutomation',
    'ThreatHunter',
    'HuntingPlaybook',
    'IOCCorrelator',
    'BehaviorAnalytics',
    'HuntingHypothesis',
]
