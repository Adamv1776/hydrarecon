"""
HydraRecon Predictive Threat Intelligence Engine
================================================
AI-powered attack prediction that forecasts threats BEFORE they happen.

Features:
- Threat trend analysis and prediction
- Vulnerability-to-exploit timeline modeling
- Organization-specific risk forecasting
- Dark web intelligence correlation
- Attack probability scoring
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
import random
import math


class ThreatCategory(Enum):
    RANSOMWARE = "ransomware"
    APT = "advanced_persistent_threat"
    PHISHING = "phishing"
    ZERO_DAY = "zero_day"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER = "insider_threat"
    DDOS = "ddos"
    DATA_EXFIL = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    CRYPTOMINING = "cryptomining"


class ThreatSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PredictionConfidence(Enum):
    VERY_HIGH = "very_high"  # 90%+
    HIGH = "high"            # 75-90%
    MEDIUM = "medium"        # 50-75%
    LOW = "low"              # 25-50%
    SPECULATIVE = "speculative"  # <25%


@dataclass
class ThreatIndicator:
    """Individual threat indicator from intelligence sources"""
    indicator_id: str
    source: str  # dark_web, osint, vendor_feeds, internal
    indicator_type: str  # ip, domain, hash, behavior, vulnerability
    value: str
    category: ThreatCategory
    first_seen: datetime
    last_seen: datetime
    mentions: int
    relevance_score: float  # 0-1
    
    
@dataclass
class VulnerabilityExploitTimeline:
    """Prediction of when a vulnerability will be exploited"""
    cve_id: str
    cvss_score: float
    disclosure_date: datetime
    exploit_available: bool
    exploit_in_wild: bool
    days_to_exploit: int  # Predicted days until weaponized
    probability: float
    affected_assets: List[str]
    

@dataclass
class ThreatPrediction:
    """A predicted future threat"""
    prediction_id: str
    threat_category: ThreatCategory
    severity: ThreatSeverity
    confidence: PredictionConfidence
    probability: float  # 0-1
    predicted_date: datetime
    prediction_window_days: int
    title: str
    description: str
    attack_vector: str
    target_assets: List[str]
    indicators: List[ThreatIndicator]
    mitre_techniques: List[str]
    recommended_actions: List[str]
    evidence: List[str]
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ThreatTrend:
    """Trending threat pattern"""
    trend_id: str
    category: ThreatCategory
    trend_name: str
    velocity: float  # Rate of change
    momentum: float  # Acceleration
    current_level: float
    predicted_peak: datetime
    affected_industries: List[str]
    geographic_regions: List[str]
    

@dataclass
class OrganizationProfile:
    """Organization's threat profile"""
    org_id: str
    industry: str
    size: str  # small, medium, large, enterprise
    public_assets: List[str]
    technology_stack: List[str]
    compliance_requirements: List[str]
    historical_incidents: List[Dict]
    threat_exposure_score: float
    

@dataclass
class PredictiveAnalysis:
    """Complete predictive analysis result"""
    analysis_id: str
    timestamp: datetime
    organization: OrganizationProfile
    predictions: List[ThreatPrediction]
    trends: List[ThreatTrend]
    exploit_timelines: List[VulnerabilityExploitTimeline]
    overall_threat_level: str
    threat_score: float
    time_to_next_attack: timedelta
    recommended_priorities: List[str]


class PredictiveThreatIntel:
    """
    AI-powered predictive threat intelligence engine.
    Forecasts attacks before they happen using ML and intelligence correlation.
    """
    
    def __init__(self):
        self.threat_indicators: List[ThreatIndicator] = []
        self.predictions: List[ThreatPrediction] = []
        self.trends: List[ThreatTrend] = []
        self.organization: Optional[OrganizationProfile] = None
        
        # Intelligence sources
        self.intel_sources = {
            "dark_web_monitoring": {"enabled": True, "weight": 0.9},
            "osint_feeds": {"enabled": True, "weight": 0.7},
            "vendor_advisories": {"enabled": True, "weight": 0.8},
            "honeypot_network": {"enabled": True, "weight": 0.85},
            "threat_exchanges": {"enabled": True, "weight": 0.75},
            "social_media": {"enabled": True, "weight": 0.5},
            "paste_sites": {"enabled": True, "weight": 0.6},
            "vulnerability_databases": {"enabled": True, "weight": 0.95},
        }
        
        # Threat models with base probabilities by industry
        self.industry_threat_models = {
            "finance": {
                ThreatCategory.RANSOMWARE: 0.75,
                ThreatCategory.CREDENTIAL_THEFT: 0.85,
                ThreatCategory.APT: 0.70,
                ThreatCategory.INSIDER: 0.60,
            },
            "healthcare": {
                ThreatCategory.RANSOMWARE: 0.85,
                ThreatCategory.DATA_EXFIL: 0.70,
                ThreatCategory.PHISHING: 0.75,
            },
            "technology": {
                ThreatCategory.SUPPLY_CHAIN: 0.80,
                ThreatCategory.ZERO_DAY: 0.65,
                ThreatCategory.APT: 0.75,
            },
            "government": {
                ThreatCategory.APT: 0.90,
                ThreatCategory.ZERO_DAY: 0.70,
                ThreatCategory.INSIDER: 0.65,
            },
            "retail": {
                ThreatCategory.CREDENTIAL_THEFT: 0.80,
                ThreatCategory.DATA_EXFIL: 0.75,
                ThreatCategory.DDOS: 0.60,
            },
            "manufacturing": {
                ThreatCategory.RANSOMWARE: 0.80,
                ThreatCategory.SUPPLY_CHAIN: 0.70,
            },
        }
        
        # MITRE ATT&CK technique mappings
        self.mitre_mappings = {
            ThreatCategory.RANSOMWARE: ["T1486", "T1490", "T1489", "T1547", "T1059"],
            ThreatCategory.APT: ["T1071", "T1105", "T1055", "T1003", "T1078"],
            ThreatCategory.PHISHING: ["T1566", "T1598", "T1204", "T1534"],
            ThreatCategory.ZERO_DAY: ["T1190", "T1211", "T1212", "T1068"],
            ThreatCategory.SUPPLY_CHAIN: ["T1195", "T1199", "T1072"],
            ThreatCategory.INSIDER: ["T1078", "T1213", "T1530", "T1052"],
            ThreatCategory.DDOS: ["T1498", "T1499"],
            ThreatCategory.DATA_EXFIL: ["T1041", "T1048", "T1567", "T1537"],
            ThreatCategory.CREDENTIAL_THEFT: ["T1110", "T1555", "T1558", "T1539"],
            ThreatCategory.CRYPTOMINING: ["T1496", "T1059", "T1053"],
        }
        
        self._initialize_demo_data()
        
    def _initialize_demo_data(self):
        """Initialize with realistic threat intelligence data"""
        now = datetime.now()
        
        # Simulated threat indicators from various sources
        self.threat_indicators = [
            ThreatIndicator(
                indicator_id="IOC-001",
                source="dark_web",
                indicator_type="behavior",
                value="Ransomware group discussing new campaign targeting healthcare",
                category=ThreatCategory.RANSOMWARE,
                first_seen=now - timedelta(days=3),
                last_seen=now - timedelta(hours=2),
                mentions=47,
                relevance_score=0.92
            ),
            ThreatIndicator(
                indicator_id="IOC-002",
                source="vendor_feeds",
                indicator_type="vulnerability",
                value="CVE-2026-0001 actively exploited in the wild",
                category=ThreatCategory.ZERO_DAY,
                first_seen=now - timedelta(days=1),
                last_seen=now,
                mentions=156,
                relevance_score=0.98
            ),
            ThreatIndicator(
                indicator_id="IOC-003",
                source="honeypot_network",
                indicator_type="ip",
                value="185.220.101.0/24 - Increased scanning activity",
                category=ThreatCategory.APT,
                first_seen=now - timedelta(days=7),
                last_seen=now - timedelta(hours=1),
                mentions=892,
                relevance_score=0.85
            ),
            ThreatIndicator(
                indicator_id="IOC-004",
                source="osint_feeds",
                indicator_type="domain",
                value="Phishing kit targeting Microsoft 365 credentials",
                category=ThreatCategory.PHISHING,
                first_seen=now - timedelta(days=2),
                last_seen=now - timedelta(hours=6),
                mentions=234,
                relevance_score=0.88
            ),
            ThreatIndicator(
                indicator_id="IOC-005",
                source="threat_exchanges",
                indicator_type="hash",
                value="Supply chain malware in npm packages",
                category=ThreatCategory.SUPPLY_CHAIN,
                first_seen=now - timedelta(days=5),
                last_seen=now - timedelta(hours=12),
                mentions=78,
                relevance_score=0.91
            ),
        ]
        
        # Current threat trends
        self.trends = [
            ThreatTrend(
                trend_id="TREND-001",
                category=ThreatCategory.RANSOMWARE,
                trend_name="LockBit 4.0 Campaign Wave",
                velocity=2.3,
                momentum=0.8,
                current_level=0.87,
                predicted_peak=now + timedelta(days=14),
                affected_industries=["healthcare", "manufacturing", "finance"],
                geographic_regions=["North America", "Europe"]
            ),
            ThreatTrend(
                trend_id="TREND-002",
                category=ThreatCategory.SUPPLY_CHAIN,
                trend_name="CI/CD Pipeline Targeting",
                velocity=1.8,
                momentum=1.2,
                current_level=0.72,
                predicted_peak=now + timedelta(days=30),
                affected_industries=["technology", "saas"],
                geographic_regions=["Global"]
            ),
            ThreatTrend(
                trend_id="TREND-003",
                category=ThreatCategory.APT,
                trend_name="Nation-State Critical Infrastructure Campaign",
                velocity=0.9,
                momentum=0.3,
                current_level=0.65,
                predicted_peak=now + timedelta(days=60),
                affected_industries=["energy", "government", "defense"],
                geographic_regions=["North America", "Europe", "Asia Pacific"]
            ),
            ThreatTrend(
                trend_id="TREND-004",
                category=ThreatCategory.PHISHING,
                trend_name="AI-Generated Spear Phishing",
                velocity=3.1,
                momentum=1.5,
                current_level=0.81,
                predicted_peak=now + timedelta(days=7),
                affected_industries=["all"],
                geographic_regions=["Global"]
            ),
        ]
        
    def set_organization_profile(
        self,
        org_id: str,
        industry: str,
        size: str,
        public_assets: List[str],
        technology_stack: List[str],
        compliance_requirements: List[str] = None,
        historical_incidents: List[Dict] = None
    ) -> OrganizationProfile:
        """Set the organization profile for personalized predictions"""
        
        # Calculate threat exposure based on profile
        exposure_factors = {
            "size": {"small": 0.4, "medium": 0.6, "large": 0.8, "enterprise": 0.9},
            "industry_risk": self.industry_threat_models.get(industry.lower(), {})
        }
        
        base_exposure = exposure_factors["size"].get(size.lower(), 0.5)
        industry_modifier = sum(exposure_factors["industry_risk"].values()) / max(len(exposure_factors["industry_risk"]), 1)
        
        # Technology stack increases attack surface
        tech_modifier = min(len(technology_stack) * 0.02, 0.2)
        
        # Public assets increase exposure
        asset_modifier = min(len(public_assets) * 0.03, 0.15)
        
        threat_exposure = min(base_exposure + industry_modifier + tech_modifier + asset_modifier, 1.0)
        
        self.organization = OrganizationProfile(
            org_id=org_id,
            industry=industry,
            size=size,
            public_assets=public_assets,
            technology_stack=technology_stack,
            compliance_requirements=compliance_requirements or [],
            historical_incidents=historical_incidents or [],
            threat_exposure_score=round(threat_exposure, 2)
        )
        
        return self.organization
        
    async def collect_threat_intelligence(self) -> List[ThreatIndicator]:
        """Collect threat intelligence from all enabled sources"""
        collected = []
        
        for source, config in self.intel_sources.items():
            if config["enabled"]:
                # Simulate intelligence collection
                await asyncio.sleep(0.1)
                indicators = await self._collect_from_source(source, config["weight"])
                collected.extend(indicators)
                
        self.threat_indicators.extend(collected)
        return collected
        
    async def _collect_from_source(self, source: str, weight: float) -> List[ThreatIndicator]:
        """Collect indicators from a specific intelligence source"""
        # In production, this would connect to actual threat feeds
        # For demo, generate realistic indicators
        now = datetime.now()
        indicators = []
        
        source_categories = {
            "dark_web_monitoring": [ThreatCategory.RANSOMWARE, ThreatCategory.CREDENTIAL_THEFT, ThreatCategory.DATA_EXFIL],
            "osint_feeds": [ThreatCategory.PHISHING, ThreatCategory.APT],
            "vendor_advisories": [ThreatCategory.ZERO_DAY, ThreatCategory.SUPPLY_CHAIN],
            "honeypot_network": [ThreatCategory.APT, ThreatCategory.DDOS],
            "threat_exchanges": [ThreatCategory.RANSOMWARE, ThreatCategory.SUPPLY_CHAIN],
            "social_media": [ThreatCategory.PHISHING],
            "paste_sites": [ThreatCategory.CREDENTIAL_THEFT, ThreatCategory.DATA_EXFIL],
            "vulnerability_databases": [ThreatCategory.ZERO_DAY],
        }
        
        categories = source_categories.get(source, [ThreatCategory.PHISHING])
        
        for category in categories:
            if random.random() > 0.3:  # 70% chance of finding indicators
                indicator = ThreatIndicator(
                    indicator_id=f"IOC-{source[:3].upper()}-{random.randint(1000, 9999)}",
                    source=source,
                    indicator_type=random.choice(["ip", "domain", "hash", "behavior"]),
                    value=f"Automated collection from {source}",
                    category=category,
                    first_seen=now - timedelta(hours=random.randint(1, 72)),
                    last_seen=now,
                    mentions=random.randint(5, 200),
                    relevance_score=round(random.uniform(0.5, 1.0) * weight, 2)
                )
                indicators.append(indicator)
                
        return indicators
        
    def predict_vulnerability_exploitation(self, vulnerabilities: List[Dict]) -> List[VulnerabilityExploitTimeline]:
        """Predict when vulnerabilities will be exploited"""
        timelines = []
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "CVE-UNKNOWN")
            cvss = vuln.get("cvss_score", 5.0)
            disclosure_date = vuln.get("disclosure_date", datetime.now())
            
            # Exploit prediction model based on CVSS and other factors
            # Higher CVSS = faster exploitation
            base_days = max(1, int(30 - (cvss * 2.5)))
            
            # Factor in exploit availability
            exploit_available = vuln.get("exploit_available", False)
            if exploit_available:
                base_days = max(1, base_days // 2)
                
            # Factor in vendor (some vendors are targeted more)
            vendor = vuln.get("vendor", "").lower()
            high_value_vendors = ["microsoft", "apple", "google", "cisco", "vmware", "fortinet"]
            if any(v in vendor for v in high_value_vendors):
                base_days = max(1, int(base_days * 0.7))
                
            # Calculate probability
            probability = min(0.95, 0.3 + (cvss / 10) * 0.6)
            
            timeline = VulnerabilityExploitTimeline(
                cve_id=cve_id,
                cvss_score=cvss,
                disclosure_date=disclosure_date if isinstance(disclosure_date, datetime) else datetime.now(),
                exploit_available=exploit_available,
                exploit_in_wild=vuln.get("exploit_in_wild", False),
                days_to_exploit=base_days,
                probability=round(probability, 2),
                affected_assets=vuln.get("affected_assets", [])
            )
            timelines.append(timeline)
            
        return sorted(timelines, key=lambda x: x.days_to_exploit)
        
    def generate_predictions(self, days_ahead: int = 30) -> List[ThreatPrediction]:
        """Generate threat predictions for the specified time window"""
        if not self.organization:
            # Create default organization profile
            self.set_organization_profile(
                org_id="default",
                industry="technology",
                size="medium",
                public_assets=["web-server", "api-gateway", "mail-server"],
                technology_stack=["python", "nodejs", "kubernetes", "aws"]
            )
            
        predictions = []
        now = datetime.now()
        
        # Get relevant threat models for this industry
        industry_threats = self.industry_threat_models.get(
            self.organization.industry.lower(),
            {ThreatCategory.PHISHING: 0.5, ThreatCategory.RANSOMWARE: 0.5}
        )
        
        # Analyze trends and indicators to generate predictions
        for category, base_prob in industry_threats.items():
            # Find relevant indicators
            relevant_indicators = [
                ind for ind in self.threat_indicators 
                if ind.category == category
            ]
            
            # Find relevant trends
            relevant_trends = [
                trend for trend in self.trends 
                if trend.category == category
            ]
            
            # Calculate adjusted probability
            indicator_boost = sum(ind.relevance_score for ind in relevant_indicators) * 0.1
            trend_boost = sum(trend.velocity * trend.momentum for trend in relevant_trends) * 0.05
            
            adjusted_prob = min(0.95, base_prob + indicator_boost + trend_boost)
            adjusted_prob *= self.organization.threat_exposure_score
            
            # Determine confidence
            if adjusted_prob >= 0.8:
                confidence = PredictionConfidence.VERY_HIGH
            elif adjusted_prob >= 0.65:
                confidence = PredictionConfidence.HIGH
            elif adjusted_prob >= 0.45:
                confidence = PredictionConfidence.MEDIUM
            elif adjusted_prob >= 0.25:
                confidence = PredictionConfidence.LOW
            else:
                confidence = PredictionConfidence.SPECULATIVE
                
            # Determine severity based on category
            severity_map = {
                ThreatCategory.RANSOMWARE: ThreatSeverity.CRITICAL,
                ThreatCategory.APT: ThreatSeverity.CRITICAL,
                ThreatCategory.ZERO_DAY: ThreatSeverity.CRITICAL,
                ThreatCategory.SUPPLY_CHAIN: ThreatSeverity.HIGH,
                ThreatCategory.INSIDER: ThreatSeverity.HIGH,
                ThreatCategory.DATA_EXFIL: ThreatSeverity.HIGH,
                ThreatCategory.CREDENTIAL_THEFT: ThreatSeverity.HIGH,
                ThreatCategory.PHISHING: ThreatSeverity.MEDIUM,
                ThreatCategory.DDOS: ThreatSeverity.MEDIUM,
                ThreatCategory.CRYPTOMINING: ThreatSeverity.LOW,
            }
            
            # Calculate predicted attack date
            urgency_factor = adjusted_prob * (1 + (indicator_boost * 2))
            days_until_attack = max(1, int(days_ahead * (1 - urgency_factor)))
            predicted_date = now + timedelta(days=days_until_attack)
            
            prediction = ThreatPrediction(
                prediction_id=f"PRED-{category.value[:4].upper()}-{random.randint(1000, 9999)}",
                threat_category=category,
                severity=severity_map.get(category, ThreatSeverity.MEDIUM),
                confidence=confidence,
                probability=round(adjusted_prob, 2),
                predicted_date=predicted_date,
                prediction_window_days=max(3, days_until_attack // 3),
                title=self._generate_prediction_title(category, relevant_trends),
                description=self._generate_prediction_description(category, relevant_indicators),
                attack_vector=self._get_attack_vector(category),
                target_assets=self._identify_target_assets(category),
                indicators=relevant_indicators[:5],  # Top 5 relevant indicators
                mitre_techniques=self.mitre_mappings.get(category, []),
                recommended_actions=self._generate_recommendations(category),
                evidence=self._compile_evidence(relevant_indicators, relevant_trends)
            )
            predictions.append(prediction)
            
        self.predictions = sorted(predictions, key=lambda x: (x.probability, x.severity.value), reverse=True)
        return self.predictions
        
    def _generate_prediction_title(self, category: ThreatCategory, trends: List[ThreatTrend]) -> str:
        """Generate a descriptive prediction title"""
        titles = {
            ThreatCategory.RANSOMWARE: "Imminent Ransomware Attack Campaign",
            ThreatCategory.APT: "Advanced Persistent Threat Activity Detected",
            ThreatCategory.PHISHING: "Sophisticated Phishing Campaign Likely",
            ThreatCategory.ZERO_DAY: "Zero-Day Exploitation Probable",
            ThreatCategory.SUPPLY_CHAIN: "Supply Chain Compromise Risk",
            ThreatCategory.INSIDER: "Elevated Insider Threat Indicators",
            ThreatCategory.DDOS: "DDoS Attack Preparation Observed",
            ThreatCategory.DATA_EXFIL: "Data Exfiltration Threat Detected",
            ThreatCategory.CREDENTIAL_THEFT: "Credential Harvesting Campaign Active",
            ThreatCategory.CRYPTOMINING: "Cryptomining Infection Risk",
        }
        
        base_title = titles.get(category, "Unknown Threat Detected")
        
        if trends:
            base_title += f" - {trends[0].trend_name}"
            
        return base_title
        
    def _generate_prediction_description(self, category: ThreatCategory, indicators: List[ThreatIndicator]) -> str:
        """Generate detailed prediction description"""
        base_descriptions = {
            ThreatCategory.RANSOMWARE: "Based on dark web intelligence and threat actor activity, a ransomware attack targeting organizations in your industry is predicted. Multiple indicators suggest active preparation by known ransomware groups.",
            ThreatCategory.APT: "Nation-state or sophisticated threat actor activity has been detected targeting your sector. Long-term persistent access and data theft are the primary objectives.",
            ThreatCategory.PHISHING: "AI-powered analysis indicates an upcoming phishing campaign targeting your organization. New phishing kits and techniques have been observed in threat actor communities.",
            ThreatCategory.ZERO_DAY: "Vulnerability intelligence suggests active exploitation of unpatched vulnerabilities in your technology stack. Immediate patching is recommended.",
            ThreatCategory.SUPPLY_CHAIN: "Indicators suggest potential compromise in software supply chain components used by your organization. Dependency auditing is critical.",
            ThreatCategory.INSIDER: "Behavioral analytics and threat indicators suggest elevated insider threat risk. Enhanced monitoring of privileged access is recommended.",
            ThreatCategory.DDOS: "Botnet activity and attack infrastructure preparation targeting your industry has been observed. DDoS mitigation should be validated.",
            ThreatCategory.DATA_EXFIL: "Threat intelligence indicates active campaigns targeting data exfiltration. Enhanced DLP and egress monitoring recommended.",
            ThreatCategory.CREDENTIAL_THEFT: "Credential harvesting infrastructure targeting your sector has been identified. MFA enforcement and credential monitoring critical.",
            ThreatCategory.CRYPTOMINING: "Cryptomining malware campaigns targeting cloud infrastructure in your industry have been observed.",
        }
        
        desc = base_descriptions.get(category, "Threat activity detected.")
        
        if indicators:
            desc += f" This prediction is supported by {len(indicators)} threat indicators from intelligence sources."
            
        return desc
        
    def _get_attack_vector(self, category: ThreatCategory) -> str:
        """Get likely attack vector for threat category"""
        vectors = {
            ThreatCategory.RANSOMWARE: "Phishing email with malicious attachment or RDP exploitation",
            ThreatCategory.APT: "Spear phishing, watering hole, or supply chain compromise",
            ThreatCategory.PHISHING: "Email with credential harvesting link",
            ThreatCategory.ZERO_DAY: "Exploitation of unpatched vulnerability",
            ThreatCategory.SUPPLY_CHAIN: "Compromised software update or dependency",
            ThreatCategory.INSIDER: "Privileged access abuse or data theft",
            ThreatCategory.DDOS: "Volumetric or application-layer attack",
            ThreatCategory.DATA_EXFIL: "Compromised credentials or malware C2",
            ThreatCategory.CREDENTIAL_THEFT: "Phishing, keylogger, or credential stuffing",
            ThreatCategory.CRYPTOMINING: "Container escape or cloud misconfiguration",
        }
        return vectors.get(category, "Unknown vector")
        
    def _identify_target_assets(self, category: ThreatCategory) -> List[str]:
        """Identify likely target assets based on threat category"""
        if not self.organization:
            return ["web-server", "database", "endpoints"]
            
        targets = []
        
        asset_mapping = {
            ThreatCategory.RANSOMWARE: ["file-server", "database", "backup-server", "domain-controller"],
            ThreatCategory.APT: ["domain-controller", "mail-server", "admin-workstation"],
            ThreatCategory.PHISHING: ["mail-server", "user-endpoints"],
            ThreatCategory.ZERO_DAY: ["web-server", "vpn-gateway", "firewall"],
            ThreatCategory.SUPPLY_CHAIN: ["ci-cd-pipeline", "package-manager", "build-server"],
            ThreatCategory.DDOS: ["web-server", "api-gateway", "load-balancer"],
            ThreatCategory.DATA_EXFIL: ["database", "file-server", "cloud-storage"],
            ThreatCategory.CREDENTIAL_THEFT: ["domain-controller", "sso-server", "mail-server"],
        }
        
        category_targets = asset_mapping.get(category, ["web-server"])
        
        # Match with organization's actual assets
        for asset in self.organization.public_assets:
            for target in category_targets:
                if target in asset.lower() or asset.lower() in target:
                    targets.append(asset)
                    
        return targets if targets else category_targets[:3]
        
    def _generate_recommendations(self, category: ThreatCategory) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = {
            ThreatCategory.RANSOMWARE: [
                "Validate offline backup integrity and recovery procedures",
                "Enforce MFA on all remote access points",
                "Segment critical systems from general network",
                "Deploy endpoint detection and response (EDR)",
                "Conduct phishing awareness training",
            ],
            ThreatCategory.APT: [
                "Enable enhanced logging on all critical systems",
                "Deploy network traffic analysis",
                "Implement zero trust network segmentation",
                "Conduct threat hunting exercises",
                "Review and rotate privileged credentials",
            ],
            ThreatCategory.PHISHING: [
                "Deploy email authentication (DMARC, DKIM, SPF)",
                "Enable link protection in email gateway",
                "Conduct simulated phishing exercises",
                "Implement browser isolation for high-risk users",
            ],
            ThreatCategory.ZERO_DAY: [
                "Prioritize patching of affected systems",
                "Deploy virtual patching via WAF/IPS",
                "Implement network segmentation",
                "Enable exploit prevention in EDR",
            ],
            ThreatCategory.SUPPLY_CHAIN: [
                "Audit all third-party dependencies",
                "Implement software bill of materials (SBOM)",
                "Enable dependency scanning in CI/CD",
                "Validate vendor security practices",
            ],
        }
        
        return recommendations.get(category, [
            "Enable enhanced monitoring",
            "Review access controls",
            "Update incident response procedures"
        ])
        
    def _compile_evidence(self, indicators: List[ThreatIndicator], trends: List[ThreatTrend]) -> List[str]:
        """Compile evidence supporting the prediction"""
        evidence = []
        
        for ind in indicators[:3]:
            evidence.append(f"[{ind.source}] {ind.value} (mentions: {ind.mentions}, relevance: {ind.relevance_score:.0%})")
            
        for trend in trends[:2]:
            evidence.append(f"[Trend] {trend.trend_name} - velocity: {trend.velocity:.1f}x, level: {trend.current_level:.0%}")
            
        return evidence
        
    async def run_analysis(self, days_ahead: int = 30) -> PredictiveAnalysis:
        """Run complete predictive analysis"""
        # Collect fresh intelligence
        await self.collect_threat_intelligence()
        
        # Generate predictions
        predictions = self.generate_predictions(days_ahead)
        
        # Calculate vulnerability exploitation timelines
        # Demo vulnerabilities
        demo_vulns = [
            {"cve_id": "CVE-2026-0001", "cvss_score": 9.8, "vendor": "Microsoft", "exploit_available": True},
            {"cve_id": "CVE-2026-0042", "cvss_score": 8.5, "vendor": "Apache", "exploit_available": False},
            {"cve_id": "CVE-2025-9999", "cvss_score": 7.2, "vendor": "OpenSSL", "exploit_available": True},
        ]
        exploit_timelines = self.predict_vulnerability_exploitation(demo_vulns)
        
        # Calculate overall threat level
        if predictions:
            avg_prob = sum(p.probability for p in predictions) / len(predictions)
            critical_count = sum(1 for p in predictions if p.severity == ThreatSeverity.CRITICAL)
            
            if avg_prob > 0.7 or critical_count >= 2:
                overall_level = "CRITICAL"
            elif avg_prob > 0.5 or critical_count >= 1:
                overall_level = "HIGH"
            elif avg_prob > 0.3:
                overall_level = "ELEVATED"
            else:
                overall_level = "GUARDED"
                
            threat_score = round(avg_prob * 100, 1)
        else:
            overall_level = "LOW"
            threat_score = 10.0
            
        # Calculate time to next predicted attack
        if predictions:
            next_attack = min(p.predicted_date for p in predictions)
            time_to_attack = next_attack - datetime.now()
        else:
            time_to_attack = timedelta(days=30)
            
        # Generate priority recommendations
        priorities = []
        for p in predictions[:3]:
            if p.recommended_actions:
                priorities.append(f"[{p.threat_category.value}] {p.recommended_actions[0]}")
                
        analysis = PredictiveAnalysis(
            analysis_id=f"ANALYSIS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            organization=self.organization,
            predictions=predictions,
            trends=self.trends,
            exploit_timelines=exploit_timelines,
            overall_threat_level=overall_level,
            threat_score=threat_score,
            time_to_next_attack=time_to_attack,
            recommended_priorities=priorities
        )
        
        return analysis
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            "total_indicators": len(self.threat_indicators),
            "total_predictions": len(self.predictions),
            "active_trends": len(self.trends),
            "intel_sources": sum(1 for s in self.intel_sources.values() if s["enabled"]),
            "organization_configured": self.organization is not None,
            "threat_categories_monitored": len(ThreatCategory),
        }


async def main():
    """Test the predictive threat intelligence engine"""
    print("=" * 60)
    print("HydraRecon Predictive Threat Intelligence Engine")
    print("=" * 60)
    
    engine = PredictiveThreatIntel()
    
    # Set organization profile
    print("\n[*] Configuring organization profile...")
    org = engine.set_organization_profile(
        org_id="acme-corp",
        industry="technology",
        size="large",
        public_assets=["web-server", "api-gateway", "mail-server", "vpn-gateway"],
        technology_stack=["python", "nodejs", "kubernetes", "aws", "postgresql"],
        compliance_requirements=["SOC2", "GDPR", "PCI-DSS"]
    )
    print(f"    Organization: {org.org_id}")
    print(f"    Industry: {org.industry}")
    print(f"    Threat Exposure Score: {org.threat_exposure_score:.0%}")
    
    # Run analysis
    print("\n[*] Collecting threat intelligence and generating predictions...")
    analysis = await engine.run_analysis(days_ahead=30)
    
    print(f"\n[+] Analysis Complete: {analysis.analysis_id}")
    print(f"    Overall Threat Level: {analysis.overall_threat_level}")
    print(f"    Threat Score: {analysis.threat_score}/100")
    print(f"    Time to Next Attack: {analysis.time_to_next_attack.days} days")
    
    print(f"\n[*] Threat Predictions ({len(analysis.predictions)}):")
    for pred in analysis.predictions[:5]:
        print(f"\n    [{pred.severity.value.upper()}] {pred.title}")
        print(f"    Category: {pred.threat_category.value}")
        print(f"    Probability: {pred.probability:.0%}")
        print(f"    Confidence: {pred.confidence.value}")
        print(f"    Predicted: {pred.predicted_date.strftime('%Y-%m-%d')} (±{pred.prediction_window_days} days)")
        print(f"    MITRE Techniques: {', '.join(pred.mitre_techniques[:3])}")
        
    print(f"\n[*] Vulnerability Exploitation Timelines:")
    for timeline in analysis.exploit_timelines:
        status = "🔴 IN WILD" if timeline.exploit_in_wild else ("🟡 EXPLOIT AVAILABLE" if timeline.exploit_available else "🟢 NO EXPLOIT")
        print(f"    {timeline.cve_id} (CVSS {timeline.cvss_score}) - {timeline.days_to_exploit} days to exploit ({timeline.probability:.0%}) {status}")
        
    print(f"\n[*] Active Threat Trends:")
    for trend in analysis.trends:
        print(f"    📈 {trend.trend_name}")
        print(f"       Level: {trend.current_level:.0%} | Velocity: {trend.velocity:.1f}x | Peak: {trend.predicted_peak.strftime('%Y-%m-%d')}")
        
    print(f"\n[*] Priority Recommendations:")
    for i, priority in enumerate(analysis.recommended_priorities, 1):
        print(f"    {i}. {priority}")
        
    stats = engine.get_statistics()
    print(f"\n[*] Engine Statistics:")
    print(f"    Indicators: {stats['total_indicators']}")
    print(f"    Predictions: {stats['total_predictions']}")
    print(f"    Intel Sources: {stats['intel_sources']}")
    
    print("\n" + "=" * 60)
    print("Predictive Threat Intelligence Engine Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
