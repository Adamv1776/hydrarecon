#!/usr/bin/env python3
"""
HydraRecon Main Window
The primary application window with modern sidebar navigation.
"""

import asyncio
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QFrame, QLabel, QPushButton, QSplitter, QToolBar, QStatusBar,
    QMenuBar, QMenu, QMessageBox, QFileDialog, QApplication, QScrollArea
)
from PyQt6.QtCore import Qt, QSize, QTimer
from PyQt6.QtGui import QAction, QIcon, QFont, QKeySequence

from .themes import DARK_THEME, COLORS
from .widgets import NavButton, GlowingButton, CollapsibleMenuGroup
from .pages.dashboard import DashboardPage
from .pages.nmap_page import NmapPage
from .pages.hydra_page import HydraPage
from .pages.osint_page import OSINTPage
from .pages.targets_page import TargetsPage
from .pages.credentials_page import CredentialsPage
from .pages.vulnerabilities_page import VulnerabilitiesPage
from .pages.reports_page import ReportsPage
from .pages.settings_page import SettingsPage
from .pages.automation_page import AutomationPage
from .pages.attack_surface_page import AttackSurfacePage

# Import new advanced pages (will be created)
try:
    from .pages.api_discovery_page import APIDiscoveryPage
except ImportError:
    APIDiscoveryPage = None

try:
    from .pages.web_spider_page import WebSpiderPage
except ImportError:
    WebSpiderPage = None

try:
    from .pages.c2_page import C2Page
except ImportError:
    C2Page = None

try:
    from .pages.exploit_browser_page import ExploitBrowserPage
except ImportError:
    ExploitBrowserPage = None

try:
    from .pages.forensics_page import ForensicsPage
except ImportError:
    ForensicsPage = None

try:
    from .pages.network_mapper_page import NetworkMapperPage
except ImportError:
    NetworkMapperPage = None

try:
    from .pages.credential_spray_page import CredentialSprayPage
except ImportError:
    CredentialSprayPage = None

try:
    from .pages.hash_cracker_page import HashCrackerPage
except ImportError:
    HashCrackerPage = None

try:
    from .pages.threat_intel_page import ThreatIntelPage
except ImportError:
    ThreatIntelPage = None

try:
    from .pages.plugin_manager_page import PluginManagerPage
except ImportError:
    PluginManagerPage = None

try:
    from .pages.wireless_attacks_page import WirelessAttacksPage
except ImportError:
    WirelessAttacksPage = None

try:
    from .pages.wifi_sensing_page import WifiSensingPage
except ImportError:
    WifiSensingPage = None

try:
    from .pages.drone_detection_page import DroneDetectionPage
except ImportError:
    DroneDetectionPage = None

try:
    from .pages.payload_generator_page import PayloadGeneratorPage
except ImportError:
    PayloadGeneratorPage = None

try:
    from .pages.vuln_scanner_page import VulnScannerPage
except ImportError:
    VulnScannerPage = None

try:
    from .pages.social_engineering_page import SocialEngineeringPage
except ImportError:
    SocialEngineeringPage = None

try:
    from .pages.browser_exploitation_page import BrowserExploitationPage
except ImportError:
    BrowserExploitationPage = None

try:
    from .pages.network_pivoting_page import NetworkPivotingPage
except ImportError:
    NetworkPivotingPage = None

try:
    from .pages.cloud_security_page import CloudSecurityPage
except ImportError:
    CloudSecurityPage = None

try:
    from .pages.zero_day_page import ZeroDayPage
except ImportError:
    ZeroDayPage = None

try:
    from .pages.edr_evasion_page import EDREvasionPage
except ImportError:
    EDREvasionPage = None

try:
    from .pages.ad_attacks_page import ADAttacksPage
except ImportError:
    ADAttacksPage = None

try:
    from .pages.malware_analysis_page import MalwareAnalysisPage
except ImportError:
    MalwareAnalysisPage = None

try:
    from .pages.container_security_page import ContainerSecurityPage
except ImportError:
    ContainerSecurityPage = None

try:
    from .pages.threat_hunting_page import ThreatHuntingPage
except ImportError:
    ThreatHuntingPage = None

try:
    from .pages.iot_exploitation_page import IoTExploitationPage
except ImportError:
    IoTExploitationPage = None

try:
    from .pages.mobile_security_page import MobileSecurityPage
except ImportError:
    MobileSecurityPage = None

try:
    from .pages.api_security_page import APISecurityPage
except ImportError:
    APISecurityPage = None

try:
    from .pages.scada_security_page import SCADASecurityPage
except ImportError:
    SCADASecurityPage = None

try:
    from .pages.red_team_page import RedTeamPage
except ImportError:
    RedTeamPage = None

try:
    from .pages.blue_team_page import BlueTeamPage
except ImportError:
    BlueTeamPage = None

try:
    from .pages.password_audit_page import PasswordAuditPage
except ImportError:
    PasswordAuditPage = None

try:
    from .pages.network_traffic_page import NetworkTrafficPage
except ImportError:
    NetworkTrafficPage = None

try:
    from .pages.compliance_audit_page import ComplianceAuditPage
except ImportError:
    ComplianceAuditPage = None

try:
    from .pages.vuln_management_page import VulnManagementPage
except ImportError:
    VulnManagementPage = None

try:
    from .pages.asset_inventory_page import AssetInventoryPage
except ImportError:
    AssetInventoryPage = None

try:
    from .pages.attack_simulation_page import AttackSimulationPage
except ImportError:
    AttackSimulationPage = None

try:
    from .pages.security_dashboard_page import SecurityDashboardPage
except ImportError:
    SecurityDashboardPage = None

try:
    from .pages.ai_analysis_page import AIAnalysisPage
except ImportError:
    AIAnalysisPage = None

try:
    from .pages.incident_response_page import IncidentResponsePage
except ImportError:
    IncidentResponsePage = None

try:
    from .pages.soar_page import SOARPage
except ImportError:
    SOARPage = None

try:
    from .pages.deception_page import DeceptionPage
except ImportError:
    DeceptionPage = None

try:
    from .pages.dlp_page import DLPPage
except ImportError:
    DLPPage = None

try:
    from .pages.backup_assessment_page import BackupAssessmentPage
except ImportError:
    BackupAssessmentPage = None

try:
    from .pages.risk_scoring_page import RiskScoringPage
except ImportError:
    RiskScoringPage = None

try:
    from .pages.remediation_tracking_page import RemediationTrackingPage
except ImportError:
    RemediationTrackingPage = None

try:
    from .pages.third_party_risk_page import ThirdPartyRiskPage
except ImportError:
    ThirdPartyRiskPage = None

try:
    from .pages.security_awareness_page import SecurityAwarenessPage
except ImportError:
    SecurityAwarenessPage = None

try:
    from .pages.patch_management_page import PatchManagementPage
except ImportError:
    PatchManagementPage = None

try:
    from .pages.security_metrics_page import SecurityMetricsPage
except ImportError:
    SecurityMetricsPage = None

try:
    from .pages.audit_log_page import AuditLogPage
except ImportError:
    AuditLogPage = None

try:
    from .pages.cmdb_page import CMDBPage
except ImportError:
    CMDBPage = None

try:
    from .pages.pentest_report_page import PentestReportPage
except ImportError:
    PentestReportPage = None

try:
    from .pages.security_policy_page import SecurityPolicyPage
except ImportError:
    SecurityPolicyPage = None

try:
    from .pages.access_control_page import AccessControlPage
except ImportError:
    AccessControlPage = None

try:
    from .pages.bcp_page import BCPPage
except ImportError:
    BCPPage = None

try:
    from .pages.vuln_correlation_page import VulnCorrelationPage
except ImportError:
    VulnCorrelationPage = None

try:
    from .pages.security_architecture_page import SecurityArchitecturePage
except ImportError:
    SecurityArchitecturePage = None

try:
    from .pages.threat_modeling_page import ThreatModelingPage
except ImportError:
    ThreatModelingPage = None

try:
    from .pages.config_baseline_page import ConfigBaselinePage
except ImportError:
    ConfigBaselinePage = None

# Cutting-edge AI/ML Security Modules
try:
    from .pages.zero_day_predictor_page import ZeroDayPredictorPage
except ImportError:
    ZeroDayPredictorPage = None

try:
    from .pages.quantum_crypto_page import QuantumCryptoPage
except ImportError:
    QuantumCryptoPage = None

try:
    from .pages.deepfake_detection_page import DeepfakeDetectionPage
except ImportError:
    DeepfakeDetectionPage = None

try:
    from .pages.blockchain_forensics_page import BlockchainForensicsPage
except ImportError:
    BlockchainForensicsPage = None

try:
    from .pages.neural_exploit_page import NeuralExploitPage
except ImportError:
    NeuralExploitPage = None

try:
    from .pages.dark_web_intel_page import DarkWebIntelPage
except ImportError:
    DarkWebIntelPage = None

try:
    from .pages.swarm_intelligence_page import SwarmIntelligencePage
except ImportError:
    SwarmIntelligencePage = None

try:
    from .pages.memory_forensics_page import MemoryForensicsPage
except ImportError:
    MemoryForensicsPage = None

try:
    from .pages.behavioral_biometrics_page import BehavioralBiometricsPage
except ImportError:
    BehavioralBiometricsPage = None

try:
    from .pages.adversarial_ml_page import AdversarialMLPage
except ImportError:
    AdversarialMLPage = None

try:
    from .pages.satellite_rf_intel_page import SatelliteRFIntelPage
except ImportError:
    SatelliteRFIntelPage = None

# Revolutionary AI-Powered Security Modules
try:
    from .pages.neural_fingerprint_page import NeuralFingerprintPage
except ImportError:
    NeuralFingerprintPage = None

try:
    from .pages.quantum_c2_page import QuantumC2Page
except ImportError:
    QuantumC2Page = None

try:
    from .pages.stego_exfil_page import StegoExfilPage
except ImportError:
    StegoExfilPage = None

try:
    from .pages.evolutionary_exploit_page import EvolutionaryExploitPage
except ImportError:
    EvolutionaryExploitPage = None

try:
    from .pages.hardware_implant_page import HardwareImplantPage
except ImportError:
    HardwareImplantPage = None

try:
    from .pages.autonomous_attack_page import AutonomousAttackPage
except ImportError:
    AutonomousAttackPage = None

try:
    from .pages.cognitive_threat_page import CognitiveThreatPage
except ImportError:
    CognitiveThreatPage = None

try:
    from .pages.polymorphic_engine_page import PolymorphicEnginePage
except ImportError:
    PolymorphicEnginePage = None

# Premium Experience Modules
try:
    from .pages.attack_map_page import LiveAttackMapPage
except ImportError:
    LiveAttackMapPage = None

try:
    from .pages.ai_narrator_page import AIThreatNarratorPage
except ImportError:
    AIThreatNarratorPage = None

try:
    from .pages.exploit_chain_page import ExploitChainBuilderPage
except ImportError:
    ExploitChainBuilderPage = None

try:
    from .pages.gamification_page import GamificationPage
except ImportError:
    GamificationPage = None

try:
    from .pages.attack_replay_page import AttackReplayPage
except ImportError:
    AttackReplayPage = None

try:
    from .pages.collaboration_hub_page import CollaborationHubPage
except ImportError:
    CollaborationHubPage = None

# New Feature Modules (v2.1)
try:
    from .pages.bug_bounty_page import BugBountyCopilotPage
except ImportError:
    BugBountyCopilotPage = None

try:
    from .pages.secrets_page import SecretsPage
except ImportError:
    SecretsPage = None

try:
    from .pages.graphql_page import GraphQLPage
except ImportError:
    GraphQLPage = None

try:
    from .pages.subdomain_takeover_page import SubdomainTakeoverPage
except ImportError:
    SubdomainTakeoverPage = None

try:
    from .pages.email_security_page import EmailSecurityPage
except ImportError:
    EmailSecurityPage = None

try:
    from .pages.word_scrubber_page import WordScrubberPage
except ImportError:
    WordScrubberPage = None

# 🎯 AI Attack Orchestrator - THE UNIQUE FEATURE
try:
    from .pages.attack_orchestrator_page import AttackOrchestratorPage
except ImportError:
    AttackOrchestratorPage = None

# 🌐 Live Threat Intelligence Feed - REAL-TIME THREAT MONITORING
try:
    from .pages.live_threat_feed_page import LiveThreatFeedPage
except ImportError:
    LiveThreatFeedPage = None

# 🔥 Vulnerability Intelligence - CVE TRACKING AND PRIORITIZATION
try:
    from .pages.vuln_intel_page import VulnIntelPage
except ImportError:
    VulnIntelPage = None

# 🤖 Autonomous Red Team Agent - AI-DRIVEN AUTONOMOUS PENTESTING
try:
    from .pages.autonomous_agent_page import AutonomousAgentPage
except ImportError:
    AutonomousAgentPage = None

# 🗺️ Network Topology Mapper - VISUAL NETWORK DISCOVERY
try:
    from .pages.topology_mapper_page import TopologyMapperPage
except ImportError:
    TopologyMapperPage = None

# 📋 Security Compliance Analyzer - MULTI-FRAMEWORK COMPLIANCE ASSESSMENT
try:
    from .pages.compliance_analyzer_page import ComplianceAnalyzerPage
except ImportError:
    ComplianceAnalyzerPage = None

# 💥 Breach Simulation Engine - REALISTIC ATTACK SCENARIO SIMULATION
try:
    from .pages.breach_simulation_page import BreachSimulationPage
except ImportError:
    BreachSimulationPage = None

# 📊 Executive Security Dashboard - C-SUITE SECURITY METRICS
try:
    from .pages.executive_dashboard_page import ExecutiveDashboardPage
except ImportError:
    ExecutiveDashboardPage = None

# 🛤️ Attack Path Analyzer - ATTACK PATH VISUALIZATION
try:
    from .pages.attack_path_page import AttackPathAnalyzerPage
except ImportError:
    AttackPathAnalyzerPage = None

# ============================================================================
# 🚀 REVOLUTIONARY SECURITY MODULES (v3.0) - NEXT-GEN SECURITY AUTOMATION
# ============================================================================

# 🔮 Predictive Threat Intelligence - AI-POWERED ATTACK PREDICTION
try:
    from .pages.predictive_threat_intel_page import PredictiveThreatIntelPage
except ImportError:
    PredictiveThreatIntelPage = None

# 🔄 Security Digital Twin - VIRTUAL NETWORK SIMULATION
try:
    from .pages.security_digital_twin_page import SecurityDigitalTwinPage
except ImportError:
    SecurityDigitalTwinPage = None

# 🔧 Autonomous Healing - SELF-HEALING SECURITY
try:
    from .pages.autonomous_healing_page import AutonomousHealingPage
except ImportError:
    AutonomousHealingPage = None

# 🔗 Supply Chain Graph - SOFTWARE SUPPLY CHAIN SECURITY
try:
    from .pages.supply_chain_graph_page import SupplyChainGraphPage
except ImportError:
    SupplyChainGraphPage = None

# 🛡️ Zero Trust Validator - NIST SP 800-207 VALIDATION
try:
    from .pages.zero_trust_validator_page import ZeroTrustValidatorPage
except ImportError:
    ZeroTrustValidatorPage = None

# 🔥 Security Chaos Engineering - NETFLIX-STYLE CHAOS TESTING
try:
    from .pages.security_chaos_page import SecurityChaosPage
except ImportError:
    SecurityChaosPage = None

# ============================================================================
# 🚀 NEXT-GENERATION SECURITY MODULES (v4.0) - AI-POWERED OFFENSIVE SECURITY
# ============================================================================

# 🕸️ Deception Network Fabric - AI-POWERED HONEYPOT ORCHESTRATION
try:
    from .pages.deception_network_page import DeceptionNetworkPage
except ImportError:
    DeceptionNetworkPage = None

# 🤖 Autonomous Red Team Orchestrator - MITRE ATT&CK AUTOMATED OPERATIONS
try:
    from .pages.autonomous_redteam_page import AutonomousRedTeamPage
except ImportError:
    AutonomousRedTeamPage = None

# 🧬 Adversarial Attack Simulator - GAN-INSPIRED ATTACK GENERATION
try:
    from .pages.adversarial_simulator_page import AdversarialSimulatorPage
except ImportError:
    AdversarialSimulatorPage = None

# 🔍 Threat Intelligence Fusion Center - MULTI-SOURCE INTEL AGGREGATION
try:
    from .pages.threat_intel_fusion_page import ThreatIntelFusionPage
except ImportError:
    ThreatIntelFusionPage = None


class HydraReconMainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, config, db):
        super().__init__()
        self.config = config
        self.db = db
        self.current_project = None
        
        self._setup_window()
        self._setup_ui()
        self._setup_menubar()
        self._setup_statusbar()
        self._connect_signals()
        self._apply_theme()
    
    def _setup_window(self):
        """Configure main window properties"""
        self.setWindowTitle("HydraRecon - Enterprise Security Assessment Suite")
        self.setMinimumSize(1400, 900)
        self.resize(1600, 1000)
        
        # Center on screen
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
    
    def _setup_ui(self):
        """Setup the main UI layout"""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        self.sidebar = self._create_sidebar()
        main_layout.addWidget(self.sidebar)
        
        # Content area
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack, stretch=1)
        
        # Initialize pages
        self._init_pages()
    
    def _create_sidebar(self) -> QWidget:
        """Create the navigation sidebar with collapsible menu groups"""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(280)
        sidebar.setStyleSheet("""
            QFrame#sidebar {
                background-color: #0d1117;
                border-right: 1px solid #21262d;
            }
        """)
        
        main_layout = QVBoxLayout(sidebar)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header section (fixed, not scrollable)
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(16, 20, 16, 16)
        header_layout.setSpacing(8)
        
        # Logo/Brand section
        brand_layout = QHBoxLayout()
        brand_layout.setSpacing(12)
        
        logo = QLabel("⚡")
        logo.setStyleSheet("font-size: 32px; color: #00ff88;")
        
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        
        title = QLabel("HydraRecon")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #e6e6e6;")
        
        subtitle = QLabel("Security Suite v2.0")
        subtitle.setStyleSheet("font-size: 11px; color: #8b949e;")
        
        brand_text.addWidget(title)
        brand_text.addWidget(subtitle)
        brand_layout.addWidget(logo)
        brand_layout.addLayout(brand_text)
        brand_layout.addStretch()
        header_layout.addLayout(brand_layout)
        
        main_layout.addWidget(header_widget)
        
        # Scrollable navigation area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background-color: #0d1117;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background-color: #21262d;
                border-radius: 4px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #30363d;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(8, 8, 8, 8)
        scroll_layout.setSpacing(4)
        
        # Navigation buttons dictionary
        self.nav_buttons = {}
        
        # Define menu groups with categories
        menu_groups = {
            "🏠 Dashboard": [
                ("dashboard", "Dashboard", "🏠"),
            ],
            "🎯 AI Attack Orchestrator": [
                ("attack_orchestrator", "🔥 Attack Orchestrator", "🎯"),
                ("autonomous_agent", "🤖 Autonomous Agent", "🤖"),
                ("topology_mapper", "🗺️ Network Topology", "🗺️"),
                ("breach_simulation", "💥 Breach Simulation", "💥"),
                ("attack_path", "🛤️ Attack Path Analyzer", "🛤️"),
            ],
            "🌐 Live Threat Intel": [
                ("live_threat_feed", "📡 Live Threat Feed", "🌐"),
                ("vuln_intel", "🔥 Vulnerability Intel", "🔥"),
            ],
            "🔍 Reconnaissance": [
                ("nmap", "Nmap Scanner", "🔍"),
                ("osint", "OSINT", "🌐"),
                ("attack_surface", "Attack Surface", "🗺️"),
                ("web_spider", "Web Spider", "🕷️"),
                ("api_discovery", "API Discovery", "🔌"),
                ("network_mapper", "Network Mapper", "🕸️"),
                ("threat_intel", "Threat Intel", "🛡️"),
                ("dark_web_intel", "Dark Web Intel", "🕳️"),
                ("subdomain_takeover", "Subdomain Takeover", "🔗"),
            ],
            "🔎 Advanced Scanners": [
                ("secrets_scanner", "Secrets Scanner", "🔐"),
                ("graphql_scanner", "GraphQL Scanner", "📊"),
                ("email_security", "Email Security", "📧"),
                ("bug_bounty", "Bug Bounty Copilot", "🎯"),
                ("word_scrubber", "Word Scrubber", "🧹"),
            ],
            "⚔️ Exploitation": [
                ("hydra", "Hydra Attack", "🔓"),
                ("exploit_browser", "Exploit Browser", "💀"),
                ("vuln_scanner", "Vuln Scanner", "🐛"),
                ("wireless", "Wireless Attacks", "📡"),
                ("wifi_sensing", "WiFi Sensing 3D", "🛰️"),
                ("drone_detection", "Drone Detection", "🚁"),
                ("payloads", "Payload Generator", "💣"),
                ("browser_exploit", "Browser Exploitation", "🌐"),
                ("zero_day", "Zero-Day Framework", "💀"),
                ("iot_exploit", "IoT Exploitation", "🔌"),
                ("scada_ics", "SCADA/ICS Security", "⚡"),
            ],
            "🔐 Credentials": [
                ("password_audit", "Password Audit", "🔑"),
                ("credential_spray", "Credential Spray", "🔐"),
                ("hash_cracker", "Hash Cracker", "🔨"),
                ("ad_attacks", "AD Attacks", "🏰"),
            ],
            "🎯 Red Team": [
                ("red_team", "Red Team Ops", "⚔️"),
                ("social_eng", "Social Engineering", "🎣"),
                ("pivoting", "Network Pivoting", "🔀"),
                ("c2", "C2 Framework", "🎮"),
                ("edr_evasion", "EDR Evasion", "🛡️"),
                ("attack_sim", "Attack Simulation", "💥"),
                ("deception", "Deception Tech", "🎭"),
            ],
            "🛡️ Blue Team": [
                ("blue_team", "Blue Team", "🛡️"),
                ("threat_hunting", "Threat Hunting", "🎯"),
                ("incident_response", "Incident Response", "🚨"),
                ("soar", "SOAR Platform", "🔄"),
                ("dlp", "Data Loss Prevention", "🔒"),
                ("network_traffic", "Traffic Analysis", "📡"),
            ],
            "🔬 Forensics": [
                ("forensics", "Forensics", "🔬"),
                ("malware_analysis", "Malware Analysis", "🔬"),
                ("memory_forensics", "Memory Forensics", "🔬"),
                ("blockchain_forensics", "Blockchain Forensics", "⛓️"),
            ],
            "☁️ Cloud & Container": [
                ("cloud_sec", "Cloud Security", "☁️"),
                ("container_sec", "Container Security", "🐳"),
                ("api_security", "API Security", "🔗"),
                ("mobile_sec", "Mobile Security", "📱"),
            ],
            "📋 Compliance & GRC": [
                ("compliance_analyzer", "📋 Compliance Analyzer", "📋"),
                ("compliance", "Compliance Audit", "📋"),
                ("risk_scoring", "Risk Scoring", "📊"),
                ("vuln_mgmt", "Vuln Management", "📊"),
                ("vuln_correlation", "Vuln Correlation", "🔗"),
                ("remediation", "Remediation Tracking", "🔧"),
                ("tprm", "Third-Party Risk", "🏢"),
                ("security_policy", "Security Policies", "📜"),
                ("bcp", "Business Continuity", "📋"),
            ],
            "🏢 Asset & Config": [
                ("asset_inv", "Asset Inventory", "🏢"),
                ("cmdb", "CMDB", "⚙️"),
                ("config_baseline", "Config Baselines", "📐"),
                ("patch_mgmt", "Patch Management", "📦"),
                ("backup_assessment", "Backup Assessment", "💾"),
            ],
            "📊 Dashboards & Reports": [
                ("executive_dashboard", "📊 Executive Dashboard", "📊"),
                ("sec_dashboard", "Security Dashboard", "📈"),
                ("security_metrics", "Security Metrics", "📊"),
                ("audit_log", "Audit Logs", "📜"),
                ("pentest_report", "Pentest Reports", "📋"),
                ("security_awareness", "Security Awareness", "🎓"),
            ],
            "🧠 AI/ML Security": [
                ("ai_analysis", "AI Analysis", "🧠"),
                ("neural_exploit", "Neural Exploit Engine", "🧠"),
                ("zero_day_predictor", "Zero-Day Predictor", "🔮"),
                ("adversarial_ml", "Adversarial ML", "🤖"),
                ("swarm_intelligence", "Swarm Intelligence", "🐝"),
                ("deepfake_detection", "Deepfake Detection", "🎭"),
                ("behavioral_biometrics", "Behavioral Biometrics", "🧬"),
            ],
            "🔐 Quantum & Advanced": [
                ("quantum_crypto", "Quantum Crypto", "⚛️"),
                ("quantum_c2", "Quantum C2", "🔐"),
                ("neural_fingerprint", "Neural Fingerprinting", "🧬"),
                ("satellite_rf_intel", "Satellite & RF Intel", "📡"),
            ],
            "🧬 Autonomous Ops": [
                ("autonomous_attack", "Autonomous Attack", "🤖"),
                ("cognitive_threat", "Cognitive Threat", "🧠"),
                ("polymorphic_engine", "Polymorphic Engine", "🧬"),
                ("evolutionary_exploit", "Evolutionary Exploits", "🧬"),
                ("stego_exfil", "Steganographic Exfil", "🖼️"),
                ("hardware_implant", "Hardware Implant", "🔧"),
            ],
            "⭐ Premium Experience": [
                ("attack_map", "Live Attack Map", "🌍"),
                ("ai_narrator", "AI Threat Narrator", "🎙️"),
                ("exploit_chain", "Exploit Chain Builder", "⛓️"),
                ("gamification", "Gamification Hub", "🏆"),
                ("threat_modeling", "Threat Modeling", "🎯"),
                ("access_control", "Access Control", "🔐"),
                ("automation", "Automation", "⚡"),
                ("plugins", "Plugins", "🧩"),
            ],
            "🚀 Revolutionary": [
                ("predictive_threat_intel", "Predictive Threat Intel", "🔮"),
                ("security_digital_twin", "Security Digital Twin", "🔄"),
                ("autonomous_healing", "Autonomous Healing", "🔧"),
                ("supply_chain_graph", "Supply Chain Graph", "🔗"),
                ("zero_trust_validator", "Zero Trust Validator", "🛡️"),
                ("security_chaos", "Security Chaos", "🔥"),
            ],
            "⚔️ Next-Gen Offensive": [
                ("deception_network", "Deception Network", "🕸️"),
                ("autonomous_redteam", "Autonomous Red Team", "🤖"),
                ("adversarial_simulator", "Adversarial Simulator", "🧬"),
                ("threat_intel_fusion", "Threat Intel Fusion", "🔍"),
            ],
        }
        
        # Create collapsible groups
        for group_title, items in menu_groups.items():
            group = CollapsibleMenuGroup(group_title)
            
            for key, text, icon in items:
                btn = NavButton(text, icon_char=icon)
                btn.clicked.connect(lambda checked, k=key: self._navigate(k))
                self.nav_buttons[key] = btn
                group.add_nav_button(btn)
            
            scroll_layout.addWidget(group)
        
        # Data section (separate group)
        data_group = CollapsibleMenuGroup("🎯 Data")
        data_items = [
            ("targets", "Targets", "🎯"),
            ("credentials", "Credentials", "🔑"),
            ("vulnerabilities", "Vulnerabilities", "⚠️"),
            ("reports", "Reports", "📊"),
        ]
        for key, text, icon in data_items:
            btn = NavButton(text, icon_char=icon)
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))
            self.nav_buttons[key] = btn
            data_group.add_nav_button(btn)
        scroll_layout.addWidget(data_group)
        
        scroll_layout.addStretch()
        
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area, 1)
        
        # Footer section (fixed, not scrollable)
        footer_widget = QWidget()
        footer_layout = QVBoxLayout(footer_widget)
        footer_layout.setContentsMargins(16, 8, 16, 16)
        footer_layout.setSpacing(8)
        
        # Settings button
        settings_btn = NavButton("Settings", icon_char="⚙️")
        settings_btn.clicked.connect(lambda: self._navigate("settings"))
        self.nav_buttons["settings"] = settings_btn
        footer_layout.addWidget(settings_btn)
        
        # Project info at bottom
        project_frame = QFrame()
        project_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
            }
        """)
        project_layout = QVBoxLayout(project_frame)
        project_layout.setContentsMargins(12, 12, 12, 12)
        project_layout.setSpacing(4)
        
        self.project_label = QLabel("No Project")
        self.project_label.setStyleSheet("font-size: 13px; font-weight: 600; color: #e6e6e6;")
        
        self.project_status = QLabel("Create or open a project")
        self.project_status.setStyleSheet("font-size: 11px; color: #8b949e;")
        
        project_layout.addWidget(self.project_label)
        project_layout.addWidget(self.project_status)
        footer_layout.addWidget(project_frame)
        
        main_layout.addWidget(footer_widget)
        
        # Set default active
        self.nav_buttons["dashboard"].setChecked(True)
        
        return sidebar
    
    def _init_pages(self):
        """Initialize all pages"""
        self.pages = {
            "dashboard": DashboardPage(self.config, self.db, self),
            "nmap": NmapPage(self.config, self.db, self),
            "hydra": HydraPage(self.config, self.db, self),
            "osint": OSINTPage(self.config, self.db, self),
            "targets": TargetsPage(self.config, self.db, self),
            "credentials": CredentialsPage(self.config, self.db, self),
            "vulnerabilities": VulnerabilitiesPage(self.config, self.db, self),
            "reports": ReportsPage(self.config, self.db, self),
            "settings": SettingsPage(self.config, self.db, self),
            "automation": AutomationPage(self),
            "attack_surface": AttackSurfacePage(self),
        }
        
        # Add advanced pages if available
        if APIDiscoveryPage:
            self.pages["api_discovery"] = APIDiscoveryPage(self)
        if WebSpiderPage:
            self.pages["web_spider"] = WebSpiderPage(self.config, self.db)
        if ExploitBrowserPage:
            self.pages["exploit_browser"] = ExploitBrowserPage(self)
        if C2Page:
            self.pages["c2"] = C2Page(self)
        if ForensicsPage:
            self.pages["forensics"] = ForensicsPage(self)
        if NetworkMapperPage:
            self.pages["network_mapper"] = NetworkMapperPage(self)
        if CredentialSprayPage:
            self.pages["credential_spray"] = CredentialSprayPage(self)
        if HashCrackerPage:
            self.pages["hash_cracker"] = HashCrackerPage(self)
        if ThreatIntelPage:
            self.pages["threat_intel"] = ThreatIntelPage(self)
        if PluginManagerPage:
            self.pages["plugins"] = PluginManagerPage(self)
        if WirelessAttacksPage:
            self.pages["wireless"] = WirelessAttacksPage(self)
        if WifiSensingPage:
            self.pages["wifi_sensing"] = WifiSensingPage(self)
        if DroneDetectionPage:
            self.pages["drone_detection"] = DroneDetectionPage(self)
        if PayloadGeneratorPage:
            self.pages["payloads"] = PayloadGeneratorPage(self)
        if VulnScannerPage:
            self.pages["vuln_scanner"] = VulnScannerPage(self)
        if SocialEngineeringPage:
            self.pages["social_eng"] = SocialEngineeringPage(self)
        if BrowserExploitationPage:
            self.pages["browser_exploit"] = BrowserExploitationPage(self)
        if NetworkPivotingPage:
            self.pages["pivoting"] = NetworkPivotingPage(self)
        if CloudSecurityPage:
            self.pages["cloud_sec"] = CloudSecurityPage(self)
        if ZeroDayPage:
            self.pages["zero_day"] = ZeroDayPage(self)
        if EDREvasionPage:
            self.pages["edr_evasion"] = EDREvasionPage(self)
        if ADAttacksPage:
            self.pages["ad_attacks"] = ADAttacksPage(self)
        if MalwareAnalysisPage:
            self.pages["malware_analysis"] = MalwareAnalysisPage(self)
        if ContainerSecurityPage:
            self.pages["container_sec"] = ContainerSecurityPage(self)
        if ThreatHuntingPage:
            self.pages["threat_hunting"] = ThreatHuntingPage(self)
        if IoTExploitationPage:
            self.pages["iot_exploit"] = IoTExploitationPage(self)
        if MobileSecurityPage:
            self.pages["mobile_sec"] = MobileSecurityPage(self)
        if APISecurityPage:
            self.pages["api_security"] = APISecurityPage(self)
        if SCADASecurityPage:
            self.pages["scada_ics"] = SCADASecurityPage(self)
        if RedTeamPage:
            self.pages["red_team"] = RedTeamPage(self)
        if BlueTeamPage:
            self.pages["blue_team"] = BlueTeamPage(self)
        if PasswordAuditPage:
            self.pages["password_audit"] = PasswordAuditPage(self)
        if NetworkTrafficPage:
            self.pages["network_traffic"] = NetworkTrafficPage(self)
        if ComplianceAuditPage:
            self.pages["compliance"] = ComplianceAuditPage(self)
        if VulnManagementPage:
            self.pages["vuln_mgmt"] = VulnManagementPage(self)
        if AssetInventoryPage:
            self.pages["asset_inv"] = AssetInventoryPage(self)
        if AttackSimulationPage:
            self.pages["attack_sim"] = AttackSimulationPage(self)
        if SecurityDashboardPage:
            self.pages["sec_dashboard"] = SecurityDashboardPage(self)
        if AIAnalysisPage:
            self.pages["ai_analysis"] = AIAnalysisPage(self)
        if IncidentResponsePage:
            self.pages["incident_response"] = IncidentResponsePage(self)
        if SOARPage:
            self.pages["soar"] = SOARPage(self)
        if DeceptionPage:
            self.pages["deception"] = DeceptionPage(self)
        if DLPPage:
            self.pages["dlp"] = DLPPage(self)
        if BackupAssessmentPage:
            self.pages["backup_assessment"] = BackupAssessmentPage(self)
        if RiskScoringPage:
            self.pages["risk_scoring"] = RiskScoringPage(self)
        if RemediationTrackingPage:
            self.pages["remediation"] = RemediationTrackingPage(self)
        if ThirdPartyRiskPage:
            self.pages["tprm"] = ThirdPartyRiskPage(self)
        if SecurityAwarenessPage:
            self.pages["security_awareness"] = SecurityAwarenessPage(self)
        if PatchManagementPage:
            self.pages["patch_mgmt"] = PatchManagementPage(self)
        if SecurityMetricsPage:
            self.pages["security_metrics"] = SecurityMetricsPage(self)
        if AuditLogPage:
            self.pages["audit_log"] = AuditLogPage(self)
        if CMDBPage:
            self.pages["cmdb"] = CMDBPage(self)
        if PentestReportPage:
            self.pages["pentest_report"] = PentestReportPage(self)
        if SecurityPolicyPage:
            self.pages["security_policy"] = SecurityPolicyPage(self)
        if AccessControlPage:
            self.pages["access_control"] = AccessControlPage(self)
        if BCPPage:
            self.pages["bcp"] = BCPPage(self)
        if VulnCorrelationPage:
            self.pages["vuln_correlation"] = VulnCorrelationPage(self)
        if SecurityArchitecturePage:
            self.pages["security_architecture"] = SecurityArchitecturePage(self)
        if ThreatModelingPage:
            self.pages["threat_modeling"] = ThreatModelingPage(self)
        if ConfigBaselinePage:
            self.pages["config_baseline"] = ConfigBaselinePage(self)
        
        # Initialize cutting-edge AI/ML security pages
        if ZeroDayPredictorPage:
            self.pages["zero_day_predictor"] = ZeroDayPredictorPage(self.config, self.db)
        if QuantumCryptoPage:
            self.pages["quantum_crypto"] = QuantumCryptoPage(self.config, self.db)
        if DeepfakeDetectionPage:
            self.pages["deepfake_detection"] = DeepfakeDetectionPage(self.config, self.db)
        if BlockchainForensicsPage:
            self.pages["blockchain_forensics"] = BlockchainForensicsPage(self.config, self.db)
        if NeuralExploitPage:
            self.pages["neural_exploit"] = NeuralExploitPage(self.config, self.db)
        if DarkWebIntelPage:
            self.pages["dark_web_intel"] = DarkWebIntelPage(self.config, self.db)
        if SwarmIntelligencePage:
            self.pages["swarm_intelligence"] = SwarmIntelligencePage(self.config, self.db)
        if MemoryForensicsPage:
            self.pages["memory_forensics"] = MemoryForensicsPage(self.config, self.db)
        if BehavioralBiometricsPage:
            self.pages["behavioral_biometrics"] = BehavioralBiometricsPage(self.config, self.db)
        if AdversarialMLPage:
            self.pages["adversarial_ml"] = AdversarialMLPage(self.config, self.db)
        if SatelliteRFIntelPage:
            self.pages["satellite_rf_intel"] = SatelliteRFIntelPage(self.config, self.db)
        
        # Initialize revolutionary AI-powered security pages
        if NeuralFingerprintPage:
            self.pages["neural_fingerprint"] = NeuralFingerprintPage(self)
        if QuantumC2Page:
            self.pages["quantum_c2"] = QuantumC2Page(self)
        if StegoExfilPage:
            self.pages["stego_exfil"] = StegoExfilPage(self)
        if EvolutionaryExploitPage:
            self.pages["evolutionary_exploit"] = EvolutionaryExploitPage(self)
        if HardwareImplantPage:
            self.pages["hardware_implant"] = HardwareImplantPage(self)
        if AutonomousAttackPage:
            self.pages["autonomous_attack"] = AutonomousAttackPage(self.config, self.db, self)
        if CognitiveThreatPage:
            self.pages["cognitive_threat"] = CognitiveThreatPage(self.config, self.db, self)
        if PolymorphicEnginePage:
            self.pages["polymorphic_engine"] = PolymorphicEnginePage(self.config, self.db, self)
        
        # Initialize premium experience pages
        if LiveAttackMapPage:
            self.pages["attack_map"] = LiveAttackMapPage(self)
        if AIThreatNarratorPage:
            self.pages["ai_narrator"] = AIThreatNarratorPage(self)
        if ExploitChainBuilderPage:
            self.pages["exploit_chain"] = ExploitChainBuilderPage(self)
        if GamificationPage:
            self.pages["gamification"] = GamificationPage(self)
        if AttackReplayPage:
            self.pages["attack_replay"] = AttackReplayPage(self)
        if CollaborationHubPage:
            self.pages["collaboration"] = CollaborationHubPage(self)
        
        # Initialize new v2.1 feature pages
        if BugBountyCopilotPage:
            self.pages["bug_bounty"] = BugBountyCopilotPage(self)
        if SecretsPage:
            self.pages["secrets_scanner"] = SecretsPage(self)
        if GraphQLPage:
            self.pages["graphql_scanner"] = GraphQLPage(self)
        if SubdomainTakeoverPage:
            self.pages["subdomain_takeover"] = SubdomainTakeoverPage(self)
        if EmailSecurityPage:
            self.pages["email_security"] = EmailSecurityPage(self)
        if WordScrubberPage:
            self.pages["word_scrubber"] = WordScrubberPage(self)
        
        # 🎯 AI Attack Orchestrator - THE UNIQUE FEATURE
        if AttackOrchestratorPage:
            self.pages["attack_orchestrator"] = AttackOrchestratorPage(self.config, self.db)
        
        # 🌐 Live Threat Intelligence Feed
        if LiveThreatFeedPage:
            self.pages["live_threat_feed"] = LiveThreatFeedPage(self.config, self.db)
        
        # 🔥 Vulnerability Intelligence
        if VulnIntelPage:
            self.pages["vuln_intel"] = VulnIntelPage(self.config, self.db)
        
        # 🤖 Autonomous Red Team Agent
        if AutonomousAgentPage:
            self.pages["autonomous_agent"] = AutonomousAgentPage(self)
        
        # 🗺️ Network Topology Mapper
        if TopologyMapperPage:
            self.pages["topology_mapper"] = TopologyMapperPage(self)
        
        # 📋 Security Compliance Analyzer
        if ComplianceAnalyzerPage:
            self.pages["compliance_analyzer"] = ComplianceAnalyzerPage(self)
        
        # 💥 Breach Simulation Engine
        if BreachSimulationPage:
            self.pages["breach_simulation"] = BreachSimulationPage(self)
        
        # 📊 Executive Security Dashboard
        if ExecutiveDashboardPage:
            self.pages["executive_dashboard"] = ExecutiveDashboardPage(self)
        
        # 🛤️ Attack Path Analyzer
        if AttackPathAnalyzerPage:
            self.pages["attack_path"] = AttackPathAnalyzerPage(self)
        
        # ============================================================================
        # 🚀 REVOLUTIONARY SECURITY MODULES (v3.0)
        # ============================================================================
        
        # 🔮 Predictive Threat Intelligence
        if PredictiveThreatIntelPage:
            self.pages["predictive_threat_intel"] = PredictiveThreatIntelPage(self)
        
        # 🔄 Security Digital Twin
        if SecurityDigitalTwinPage:
            self.pages["security_digital_twin"] = SecurityDigitalTwinPage(self)
        
        # 🔧 Autonomous Healing
        if AutonomousHealingPage:
            self.pages["autonomous_healing"] = AutonomousHealingPage(self)
        
        # 🔗 Supply Chain Graph
        if SupplyChainGraphPage:
            self.pages["supply_chain_graph"] = SupplyChainGraphPage(self)
        
        # 🛡️ Zero Trust Validator
        if ZeroTrustValidatorPage:
            self.pages["zero_trust_validator"] = ZeroTrustValidatorPage(self)
        
        # 🔥 Security Chaos Engineering
        if SecurityChaosPage:
            self.pages["security_chaos"] = SecurityChaosPage(self)
        
        # ============================================================================
        # 🚀 NEXT-GENERATION SECURITY MODULES (v4.0)
        # ============================================================================
        
        # 🕸️ Deception Network Fabric
        if DeceptionNetworkPage:
            self.pages["deception_network"] = DeceptionNetworkPage(self)
        
        # 🤖 Autonomous Red Team Orchestrator
        if AutonomousRedTeamPage:
            self.pages["autonomous_redteam"] = AutonomousRedTeamPage(self)
        
        # 🧬 Adversarial Attack Simulator
        if AdversarialSimulatorPage:
            self.pages["adversarial_simulator"] = AdversarialSimulatorPage(self)
        
        # 🔍 Threat Intelligence Fusion Center
        if ThreatIntelFusionPage:
            self.pages["threat_intel_fusion"] = ThreatIntelFusionPage(self)
        
        for page in self.pages.values():
            self.content_stack.addWidget(page)
    
    def _setup_menubar(self):
        """Setup the menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_project = QAction("New Project", self)
        new_project.setShortcut(QKeySequence.StandardKey.New)
        new_project.triggered.connect(self._new_project)
        file_menu.addAction(new_project)
        
        open_project = QAction("Open Project", self)
        open_project.setShortcut(QKeySequence.StandardKey.Open)
        open_project.triggered.connect(self._open_project)
        file_menu.addAction(open_project)
        
        file_menu.addSeparator()
        
        import_action = QAction("Import Scan Results", self)
        import_action.triggered.connect(self._import_results)
        file_menu.addAction(import_action)
        
        export_action = QAction("Export Project", self)
        export_action.triggered.connect(self._export_project)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan menu
        scan_menu = menubar.addMenu("Scan")
        
        quick_scan = QAction("Quick Scan", self)
        quick_scan.setShortcut("Ctrl+Shift+Q")
        quick_scan.triggered.connect(lambda: self._navigate("nmap"))
        scan_menu.addAction(quick_scan)
        
        full_scan = QAction("Full Audit", self)
        full_scan.setShortcut("Ctrl+Shift+F")
        scan_menu.addAction(full_scan)
        
        scan_menu.addSeparator()
        
        vuln_scan = QAction("Vulnerability Scan", self)
        scan_menu.addAction(vuln_scan)
        
        brute_force = QAction("Brute Force Attack", self)
        brute_force.triggered.connect(lambda: self._navigate("hydra"))
        scan_menu.addAction(brute_force)
        
        osint_gather = QAction("OSINT Gathering", self)
        osint_gather.triggered.connect(lambda: self._navigate("osint"))
        scan_menu.addAction(osint_gather)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        dns_lookup = QAction("DNS Lookup", self)
        tools_menu.addAction(dns_lookup)
        
        whois_lookup = QAction("WHOIS Lookup", self)
        tools_menu.addAction(whois_lookup)
        
        port_checker = QAction("Port Checker", self)
        tools_menu.addAction(port_checker)
        
        tools_menu.addSeparator()
        
        hash_analyzer = QAction("Hash Analyzer", self)
        tools_menu.addAction(hash_analyzer)
        
        encoder = QAction("Encoder/Decoder", self)
        tools_menu.addAction(encoder)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        toggle_sidebar = QAction("Toggle Sidebar", self)
        toggle_sidebar.setShortcut("Ctrl+B")
        toggle_sidebar.triggered.connect(self._toggle_sidebar)
        view_menu.addAction(toggle_sidebar)
        
        view_menu.addSeparator()
        
        zoom_in = QAction("Zoom In", self)
        zoom_in.setShortcut(QKeySequence.StandardKey.ZoomIn)
        view_menu.addAction(zoom_in)
        
        zoom_out = QAction("Zoom Out", self)
        zoom_out.setShortcut(QKeySequence.StandardKey.ZoomOut)
        view_menu.addAction(zoom_out)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        documentation = QAction("Documentation", self)
        documentation.setShortcut(QKeySequence.StandardKey.HelpContents)
        help_menu.addAction(documentation)
        
        shortcuts = QAction("Keyboard Shortcuts", self)
        help_menu.addAction(shortcuts)
        
        help_menu.addSeparator()
        
        check_updates = QAction("Check for Updates", self)
        help_menu.addAction(check_updates)
        
        about = QAction("About HydraRecon", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)
    
    def _setup_statusbar(self):
        """Setup the status bar"""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        
        # Status sections
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #8b949e;")
        
        self.scan_status = QLabel("")
        self.scan_status.setStyleSheet("color: #00ff88;")
        
        self.connection_status = QLabel("● Connected")
        self.connection_status.setStyleSheet("color: #238636;")
        
        self.statusbar.addWidget(self.status_label)
        self.statusbar.addPermanentWidget(self.scan_status)
        self.statusbar.addPermanentWidget(self.connection_status)
    
    def _connect_signals(self):
        """Connect signals between components"""
        pass
    
    def _apply_theme(self):
        """Apply the dark theme"""
        self.setStyleSheet(DARK_THEME)
    
    def _navigate(self, page_key: str):
        """Navigate to a specific page"""
        # Update nav buttons
        for key, btn in self.nav_buttons.items():
            btn.setChecked(key == page_key)
        
        # Show page
        if page_key in self.pages:
            self.content_stack.setCurrentWidget(self.pages[page_key])
    
    def _toggle_sidebar(self):
        """Toggle sidebar visibility"""
        self.sidebar.setVisible(not self.sidebar.isVisible())
    
    def _new_project(self):
        """Create a new project"""
        from .dialogs import NewProjectDialog
        dialog = NewProjectDialog(self)
        if dialog.exec():
            # Project data is emitted via signal
            pass
    
    def _open_project(self):
        """Open an existing project"""
        from .dialogs import OpenProjectDialog
        dialog = OpenProjectDialog([], self)
        if dialog.exec():
            # Project data is emitted via signal
            pass
    
    def _update_project_display(self):
        """Update project display in sidebar"""
        if self.current_project:
            self.project_label.setText(self.current_project['name'])
            self.project_status.setText(f"Status: {self.current_project['status']}")
    
    def _import_results(self):
        """Import scan results from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Scan Results", "",
            "XML Files (*.xml);;JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.status_label.setText(f"Importing {file_path}...")
    
    def _export_project(self):
        """Export current project"""
        if not self.current_project:
            QMessageBox.warning(self, "Warning", "No project is currently open.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Project", f"{self.current_project['name']}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.status_label.setText(f"Exporting to {file_path}...")
    
    def _show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About HydraRecon",
            """<h2>HydraRecon v1.0</h2>
            <p>Enterprise Security Assessment Suite</p>
            <p>A professional-grade penetration testing platform combining 
            Nmap, Hydra, and comprehensive OSINT capabilities.</p>
            <p><b>Features:</b></p>
            <ul>
                <li>Advanced Nmap Integration</li>
                <li>Hydra Brute-Force Attacks</li>
                <li>Comprehensive OSINT Gathering</li>
                <li>Real-time Visualization</li>
                <li>Professional Reporting</li>
            </ul>
            <p><small>For authorized security testing only.</small></p>
            """
        )
    
    def closeEvent(self, event):
        """Handle window close"""
        reply = QMessageBox.question(
            self, "Confirm Exit",
            "Are you sure you want to exit HydraRecon?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()
