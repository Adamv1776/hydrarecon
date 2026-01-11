#!/usr/bin/env python3
"""
Threat Intelligence Fusion Engine - HydraRecon v1.2.0

Multi-source threat intelligence correlation and enrichment platform.
Aggregates, normalizes, and correlates threat data from multiple sources.

Features:
- IOC (Indicators of Compromise) management
- STIX/TAXII integration patterns
- Threat actor profiling
- Kill chain mapping (MITRE ATT&CK)
- Confidence scoring and aging
- Automated indicator deduplication
- Context enrichment
- Alert correlation

Author: HydraRecon Team
"""

import asyncio
import hashlib
import json
import logging
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import defaultdict
import ipaddress
import urllib.parse

import numpy as np

logger = logging.getLogger(__name__)


class IOCType(Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    USER_AGENT = "user_agent"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    CERTIFICATE_HASH = "certificate_hash"
    JA3_HASH = "ja3"
    YARA_RULE = "yara"


class ThreatLevel(Enum):
    """Threat severity levels."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    UNKNOWN = 0


class ConfidenceLevel(Enum):
    """Confidence in threat intelligence."""
    CONFIRMED = 100
    HIGH = 80
    MEDIUM = 60
    LOW = 40
    UNKNOWN = 20


class IntelSource(Enum):
    """Intelligence source types."""
    COMMERCIAL = "commercial"
    OPEN_SOURCE = "open_source"
    INTERNAL = "internal"
    PARTNER = "partner"
    GOVERNMENT = "government"
    COMMUNITY = "community"


class TTPCategory(Enum):
    """MITRE ATT&CK Tactic categories."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class IOC:
    """Indicator of Compromise."""
    ioc_id: str
    ioc_type: IOCType
    value: str
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    source: IntelSource = IntelSource.INTERNAL
    source_name: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    expiration: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    related_iocs: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    
    def is_expired(self) -> bool:
        """Check if IOC has expired."""
        if self.expiration is None:
            return False
        return datetime.now() > self.expiration
    
    def age_days(self) -> int:
        """Get age of IOC in days."""
        return (datetime.now() - self.first_seen).days
    
    def to_dict(self) -> Dict:
        return {
            'ioc_id': self.ioc_id,
            'type': self.ioc_type.value,
            'value': self.value,
            'threat_level': self.threat_level.name,
            'confidence': self.confidence.value,
            'source': self.source.value,
            'source_name': self.source_name,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'tags': self.tags,
            'related_iocs': len(self.related_iocs),
            'campaigns': self.campaigns,
            'threat_actors': self.threat_actors,
            'ttps': self.ttps,
            'expired': self.is_expired(),
            'age_days': self.age_days()
        }


@dataclass
class ThreatActor:
    """Threat actor profile."""
    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    sophistication: str = "unknown"  # novice, practitioner, expert, advanced
    motivation: List[str] = field(default_factory=list)  # financial, espionage, etc
    targets: List[str] = field(default_factory=list)  # industries, countries
    ttps: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    
    def to_dict(self) -> Dict:
        return {
            'actor_id': self.actor_id,
            'name': self.name,
            'aliases': self.aliases,
            'description': self.description,
            'sophistication': self.sophistication,
            'motivation': self.motivation,
            'targets': self.targets,
            'ttps': len(self.ttps),
            'tools': self.tools,
            'iocs': len(self.iocs),
            'campaigns': self.campaigns,
            'first_seen': self.first_seen.isoformat(),
            'last_active': self.last_active.isoformat()
        }


@dataclass
class Campaign:
    """Threat campaign."""
    campaign_id: str
    name: str
    description: str = ""
    threat_actors: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    status: str = "active"  # active, dormant, concluded
    
    def to_dict(self) -> Dict:
        return {
            'campaign_id': self.campaign_id,
            'name': self.name,
            'description': self.description,
            'threat_actors': self.threat_actors,
            'targets': self.targets,
            'ttps': self.ttps,
            'iocs': len(self.iocs),
            'status': self.status,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }


@dataclass
class ThreatIntelReport:
    """Threat intelligence analysis report."""
    report_id: str
    generated_at: datetime
    total_iocs: int
    iocs_by_type: Dict[str, int]
    threat_level_distribution: Dict[str, int]
    active_campaigns: List[str]
    top_threat_actors: List[str]
    recent_iocs: List[IOC]
    expiring_iocs: List[IOC]
    correlation_alerts: List[Dict]
    risk_score: float


class IOCValidator:
    """
    Validates and normalizes IOC values.
    """
    
    # Regex patterns for IOC validation
    PATTERNS = {
        IOCType.IP_ADDRESS: re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ),
        IOCType.DOMAIN: re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        ),
        IOCType.FILE_HASH_MD5: re.compile(r'^[a-fA-F0-9]{32}$'),
        IOCType.FILE_HASH_SHA1: re.compile(r'^[a-fA-F0-9]{40}$'),
        IOCType.FILE_HASH_SHA256: re.compile(r'^[a-fA-F0-9]{64}$'),
        IOCType.EMAIL: re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        ),
        IOCType.CVE: re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE),
        IOCType.JA3_HASH: re.compile(r'^[a-fA-F0-9]{32}$'),
    }
    
    # Private/reserved IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
    ]
    
    @classmethod
    def validate(cls, ioc_type: IOCType, value: str) -> Tuple[bool, str]:
        """
        Validate an IOC value.
        
        Returns:
            Tuple of (is_valid, normalized_value)
        """
        value = value.strip()
        
        if ioc_type == IOCType.URL:
            return cls._validate_url(value)
        
        pattern = cls.PATTERNS.get(ioc_type)
        if pattern is None:
            return True, value  # No validation for unknown types
        
        # Normalize case for hashes
        if ioc_type in [IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, 
                       IOCType.FILE_HASH_SHA256, IOCType.JA3_HASH]:
            value = value.lower()
        
        if pattern.match(value):
            return True, value
        
        return False, value
    
    @classmethod
    def _validate_url(cls, url: str) -> Tuple[bool, str]:
        """Validate and normalize URL."""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme in ['http', 'https', 'ftp'] and parsed.netloc:
                return True, url
        except Exception:
            pass
        return False, url
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """Check if IP is in a private range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in cls.PRIVATE_RANGES)
        except ValueError:
            return False
    
    @classmethod
    def detect_type(cls, value: str) -> Optional[IOCType]:
        """Auto-detect IOC type from value."""
        value = value.strip()
        
        # Check URL first
        if value.startswith(('http://', 'https://', 'ftp://')):
            return IOCType.URL
        
        # Check each pattern
        for ioc_type, pattern in cls.PATTERNS.items():
            if pattern.match(value):
                return ioc_type
        
        # Check if it's a domain-like string
        if cls.PATTERNS[IOCType.DOMAIN].match(value):
            return IOCType.DOMAIN
        
        return None


class ConfidenceCalculator:
    """
    Calculate confidence scores for IOCs based on multiple factors.
    """
    
    # Weights for different factors
    WEIGHTS = {
        'source_reliability': 0.25,
        'corroboration': 0.25,
        'age': 0.15,
        'specificity': 0.15,
        'context_richness': 0.20
    }
    
    # Source reliability scores
    SOURCE_SCORES = {
        IntelSource.COMMERCIAL: 85,
        IntelSource.GOVERNMENT: 90,
        IntelSource.PARTNER: 75,
        IntelSource.INTERNAL: 70,
        IntelSource.COMMUNITY: 60,
        IntelSource.OPEN_SOURCE: 50
    }
    
    @classmethod
    def calculate(cls, ioc: IOC, corroborating_sources: int = 0,
                 total_sources: int = 1) -> int:
        """
        Calculate overall confidence score for an IOC.
        
        Args:
            ioc: The IOC to score
            corroborating_sources: Number of sources confirming this IOC
            total_sources: Total number of sources checked
            
        Returns:
            Confidence score (0-100)
        """
        scores = {}
        
        # Source reliability
        scores['source_reliability'] = cls.SOURCE_SCORES.get(ioc.source, 50)
        
        # Corroboration (more sources = higher confidence)
        if total_sources > 0:
            corroboration_ratio = corroborating_sources / total_sources
            scores['corroboration'] = min(100, corroboration_ratio * 100 + 
                                         (20 * corroborating_sources))
        else:
            scores['corroboration'] = 50
        
        # Age decay (newer = higher confidence)
        age_days = ioc.age_days()
        if age_days <= 7:
            scores['age'] = 100
        elif age_days <= 30:
            scores['age'] = 80
        elif age_days <= 90:
            scores['age'] = 60
        elif age_days <= 180:
            scores['age'] = 40
        else:
            scores['age'] = 20
        
        # Specificity (certain types are more specific)
        specificity_map = {
            IOCType.FILE_HASH_SHA256: 100,
            IOCType.FILE_HASH_SHA1: 90,
            IOCType.FILE_HASH_MD5: 80,
            IOCType.CERTIFICATE_HASH: 90,
            IOCType.JA3_HASH: 85,
            IOCType.URL: 75,
            IOCType.DOMAIN: 60,
            IOCType.IP_ADDRESS: 50,
            IOCType.EMAIL: 70,
            IOCType.CVE: 95
        }
        scores['specificity'] = specificity_map.get(ioc.ioc_type, 50)
        
        # Context richness (more context = higher confidence)
        context_score = 50
        if ioc.tags:
            context_score += min(20, len(ioc.tags) * 5)
        if ioc.threat_actors:
            context_score += 15
        if ioc.campaigns:
            context_score += 10
        if ioc.ttps:
            context_score += min(15, len(ioc.ttps) * 3)
        scores['context_richness'] = min(100, context_score)
        
        # Calculate weighted average
        total_score = sum(
            scores[factor] * weight 
            for factor, weight in cls.WEIGHTS.items()
        )
        
        return int(total_score)


class ThreatCorrelator:
    """
    Correlates IOCs, threat actors, and campaigns.
    """
    
    def __init__(self):
        self.ioc_graph: Dict[str, Set[str]] = defaultdict(set)  # IOC relationships
        self.actor_ioc_map: Dict[str, Set[str]] = defaultdict(set)
        self.campaign_ioc_map: Dict[str, Set[str]] = defaultdict(set)
    
    def add_relationship(self, ioc1_id: str, ioc2_id: str, 
                        relationship: str = "related"):
        """Add relationship between two IOCs."""
        self.ioc_graph[ioc1_id].add(ioc2_id)
        self.ioc_graph[ioc2_id].add(ioc1_id)
    
    def link_to_actor(self, ioc_id: str, actor_id: str):
        """Link IOC to threat actor."""
        self.actor_ioc_map[actor_id].add(ioc_id)
    
    def link_to_campaign(self, ioc_id: str, campaign_id: str):
        """Link IOC to campaign."""
        self.campaign_ioc_map[campaign_id].add(ioc_id)
    
    def find_related_iocs(self, ioc_id: str, depth: int = 2) -> Set[str]:
        """Find IOCs related to given IOC within specified depth."""
        related = set()
        to_explore = {ioc_id}
        
        for _ in range(depth):
            next_level = set()
            for current in to_explore:
                for neighbor in self.ioc_graph.get(current, set()):
                    if neighbor not in related and neighbor != ioc_id:
                        related.add(neighbor)
                        next_level.add(neighbor)
            to_explore = next_level
        
        return related
    
    def find_actors_for_iocs(self, ioc_ids: List[str]) -> Dict[str, int]:
        """Find threat actors associated with given IOCs."""
        actor_counts = defaultdict(int)
        
        ioc_set = set(ioc_ids)
        for actor, iocs in self.actor_ioc_map.items():
            overlap = len(iocs.intersection(ioc_set))
            if overlap > 0:
                actor_counts[actor] = overlap
        
        return dict(sorted(actor_counts.items(), key=lambda x: -x[1]))
    
    def find_campaigns_for_iocs(self, ioc_ids: List[str]) -> Dict[str, int]:
        """Find campaigns associated with given IOCs."""
        campaign_counts = defaultdict(int)
        
        ioc_set = set(ioc_ids)
        for campaign, iocs in self.campaign_ioc_map.items():
            overlap = len(iocs.intersection(ioc_set))
            if overlap > 0:
                campaign_counts[campaign] = overlap
        
        return dict(sorted(campaign_counts.items(), key=lambda x: -x[1]))
    
    def correlate_incident(self, observed_iocs: List[IOC]) -> Dict:
        """
        Correlate observed IOCs to known threats.
        
        Args:
            observed_iocs: List of IOCs observed in an incident
            
        Returns:
            Correlation results with potential actors, campaigns, and related IOCs
        """
        ioc_ids = [ioc.ioc_id for ioc in observed_iocs]
        
        # Find related IOCs
        all_related = set()
        for ioc_id in ioc_ids:
            all_related.update(self.find_related_iocs(ioc_id))
        
        # Find associated actors and campaigns
        potential_actors = self.find_actors_for_iocs(ioc_ids)
        potential_campaigns = self.find_campaigns_for_iocs(ioc_ids)
        
        # Calculate correlation confidence
        confidence = self._calculate_correlation_confidence(
            observed_iocs, potential_actors, potential_campaigns
        )
        
        return {
            'observed_iocs': len(observed_iocs),
            'related_iocs': list(all_related)[:20],
            'potential_actors': potential_actors,
            'potential_campaigns': potential_campaigns,
            'correlation_confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_correlation_confidence(self, observed: List[IOC],
                                          actors: Dict, campaigns: Dict) -> float:
        """Calculate confidence in correlation."""
        if not observed:
            return 0.0
        
        # Base on IOC confidence and correlation strength
        avg_ioc_confidence = np.mean([ioc.confidence.value for ioc in observed])
        
        # Boost for multiple actor/campaign matches
        actor_boost = min(30, len(actors) * 10)
        campaign_boost = min(20, len(campaigns) * 10)
        
        confidence = avg_ioc_confidence * 0.5 + actor_boost + campaign_boost
        
        return min(100, confidence)


class MITREMapper:
    """
    Maps threats to MITRE ATT&CK framework.
    """
    
    # Simplified ATT&CK technique mappings
    TECHNIQUES = {
        'T1566': {'name': 'Phishing', 'tactic': TTPCategory.INITIAL_ACCESS},
        'T1566.001': {'name': 'Spearphishing Attachment', 'tactic': TTPCategory.INITIAL_ACCESS},
        'T1566.002': {'name': 'Spearphishing Link', 'tactic': TTPCategory.INITIAL_ACCESS},
        'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': TTPCategory.EXECUTION},
        'T1059.001': {'name': 'PowerShell', 'tactic': TTPCategory.EXECUTION},
        'T1059.003': {'name': 'Windows Command Shell', 'tactic': TTPCategory.EXECUTION},
        'T1053': {'name': 'Scheduled Task/Job', 'tactic': TTPCategory.PERSISTENCE},
        'T1078': {'name': 'Valid Accounts', 'tactic': TTPCategory.DEFENSE_EVASION},
        'T1110': {'name': 'Brute Force', 'tactic': TTPCategory.CREDENTIAL_ACCESS},
        'T1003': {'name': 'OS Credential Dumping', 'tactic': TTPCategory.CREDENTIAL_ACCESS},
        'T1021': {'name': 'Remote Services', 'tactic': TTPCategory.LATERAL_MOVEMENT},
        'T1071': {'name': 'Application Layer Protocol', 'tactic': TTPCategory.COMMAND_AND_CONTROL},
        'T1071.001': {'name': 'Web Protocols', 'tactic': TTPCategory.COMMAND_AND_CONTROL},
        'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': TTPCategory.EXFILTRATION},
        'T1486': {'name': 'Data Encrypted for Impact', 'tactic': TTPCategory.IMPACT},
    }
    
    # IOC type to likely technique mappings
    IOC_TECHNIQUE_MAP = {
        IOCType.DOMAIN: ['T1071', 'T1071.001'],
        IOCType.IP_ADDRESS: ['T1071', 'T1071.001', 'T1048'],
        IOCType.URL: ['T1566.002', 'T1071.001'],
        IOCType.FILE_HASH_SHA256: ['T1059', 'T1486'],
        IOCType.EMAIL: ['T1566', 'T1566.001'],
    }
    
    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict]:
        """Get technique details by ID."""
        return cls.TECHNIQUES.get(technique_id)
    
    @classmethod
    def suggest_techniques(cls, ioc_type: IOCType) -> List[str]:
        """Suggest likely techniques based on IOC type."""
        return cls.IOC_TECHNIQUE_MAP.get(ioc_type, [])
    
    @classmethod
    def get_kill_chain_phase(cls, technique_id: str) -> Optional[TTPCategory]:
        """Get kill chain phase for technique."""
        tech = cls.TECHNIQUES.get(technique_id)
        if tech:
            return tech.get('tactic')
        return None
    
    @classmethod
    def map_to_kill_chain(cls, techniques: List[str]) -> Dict[str, List[str]]:
        """Map techniques to kill chain phases."""
        mapping = defaultdict(list)
        
        for tech_id in techniques:
            phase = cls.get_kill_chain_phase(tech_id)
            if phase:
                mapping[phase.value].append(tech_id)
        
        return dict(mapping)


class ThreatIntelligenceFusion:
    """
    Main threat intelligence fusion engine.
    """
    
    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self.actors: Dict[str, ThreatActor] = {}
        self.campaigns: Dict[str, Campaign] = {}
        
        self.validator = IOCValidator()
        self.confidence_calc = ConfidenceCalculator()
        self.correlator = ThreatCorrelator()
        self.mitre = MITREMapper()
        
        # Deduplication
        self.value_to_ioc: Dict[str, str] = {}  # value -> ioc_id
    
    def add_ioc(self, ioc_type: IOCType, value: str,
               source: IntelSource = IntelSource.INTERNAL,
               source_name: str = "",
               threat_level: ThreatLevel = ThreatLevel.UNKNOWN,
               tags: List[str] = None,
               context: Dict = None) -> Optional[IOC]:
        """
        Add or update an IOC.
        
        Returns:
            The IOC object (new or updated)
        """
        # Validate
        is_valid, normalized = self.validator.validate(ioc_type, value)
        if not is_valid:
            logger.warning(f"Invalid IOC value: {value}")
            return None
        
        # Check for private IPs
        if ioc_type == IOCType.IP_ADDRESS and self.validator.is_private_ip(normalized):
            logger.debug(f"Skipping private IP: {normalized}")
            return None
        
        # Check for duplicate
        existing_id = self.value_to_ioc.get(normalized)
        if existing_id and existing_id in self.iocs:
            # Update existing IOC
            existing = self.iocs[existing_id]
            existing.last_seen = datetime.now()
            
            # Update threat level if higher
            if threat_level.value > existing.threat_level.value:
                existing.threat_level = threat_level
            
            # Add new tags
            if tags:
                existing.tags = list(set(existing.tags + tags))
            
            return existing
        
        # Create new IOC
        ioc_id = hashlib.sha256(
            f"{ioc_type.value}:{normalized}".encode()
        ).hexdigest()[:16]
        
        ioc = IOC(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            value=normalized,
            threat_level=threat_level,
            source=source,
            source_name=source_name,
            tags=tags or [],
            context=context or {}
        )
        
        # Calculate initial confidence
        confidence_score = self.confidence_calc.calculate(ioc)
        ioc.confidence = self._score_to_level(confidence_score)
        
        # Suggest MITRE techniques
        ioc.ttps = self.mitre.suggest_techniques(ioc_type)
        
        self.iocs[ioc_id] = ioc
        self.value_to_ioc[normalized] = ioc_id
        
        logger.debug(f"Added IOC: {ioc_type.value}={normalized[:50]}")
        
        return ioc
    
    def add_threat_actor(self, name: str, 
                        aliases: List[str] = None,
                        description: str = "",
                        sophistication: str = "unknown",
                        motivation: List[str] = None,
                        targets: List[str] = None) -> ThreatActor:
        """Add a threat actor profile."""
        actor_id = hashlib.md5(name.lower().encode()).hexdigest()[:12]
        
        if actor_id in self.actors:
            # Update existing
            actor = self.actors[actor_id]
            actor.last_active = datetime.now()
            if aliases:
                actor.aliases = list(set(actor.aliases + aliases))
            return actor
        
        actor = ThreatActor(
            actor_id=actor_id,
            name=name,
            aliases=aliases or [],
            description=description,
            sophistication=sophistication,
            motivation=motivation or [],
            targets=targets or []
        )
        
        self.actors[actor_id] = actor
        return actor
    
    def add_campaign(self, name: str,
                    description: str = "",
                    threat_actors: List[str] = None,
                    targets: List[str] = None) -> Campaign:
        """Add a threat campaign."""
        campaign_id = hashlib.md5(name.lower().encode()).hexdigest()[:12]
        
        if campaign_id in self.campaigns:
            campaign = self.campaigns[campaign_id]
            campaign.last_seen = datetime.now()
            return campaign
        
        campaign = Campaign(
            campaign_id=campaign_id,
            name=name,
            description=description,
            threat_actors=threat_actors or [],
            targets=targets or []
        )
        
        self.campaigns[campaign_id] = campaign
        return campaign
    
    def link_ioc_to_actor(self, ioc_value: str, actor_name: str):
        """Link an IOC to a threat actor."""
        ioc_id = self.value_to_ioc.get(ioc_value)
        actor_id = hashlib.md5(actor_name.lower().encode()).hexdigest()[:12]
        
        if ioc_id and actor_id in self.actors:
            self.iocs[ioc_id].threat_actors.append(actor_name)
            self.actors[actor_id].iocs.append(ioc_id)
            self.correlator.link_to_actor(ioc_id, actor_id)
    
    def link_ioc_to_campaign(self, ioc_value: str, campaign_name: str):
        """Link an IOC to a campaign."""
        ioc_id = self.value_to_ioc.get(ioc_value)
        campaign_id = hashlib.md5(campaign_name.lower().encode()).hexdigest()[:12]
        
        if ioc_id and campaign_id in self.campaigns:
            self.iocs[ioc_id].campaigns.append(campaign_name)
            self.campaigns[campaign_id].iocs.append(ioc_id)
            self.correlator.link_to_campaign(ioc_id, campaign_id)
    
    def lookup_ioc(self, value: str) -> Optional[IOC]:
        """Look up an IOC by value."""
        # Try direct lookup
        ioc_id = self.value_to_ioc.get(value)
        if ioc_id:
            return self.iocs.get(ioc_id)
        
        # Try normalized lookup
        detected_type = self.validator.detect_type(value)
        if detected_type:
            _, normalized = self.validator.validate(detected_type, value)
            ioc_id = self.value_to_ioc.get(normalized)
            if ioc_id:
                return self.iocs.get(ioc_id)
        
        return None
    
    def search_iocs(self, 
                   ioc_type: Optional[IOCType] = None,
                   threat_level: Optional[ThreatLevel] = None,
                   tags: Optional[List[str]] = None,
                   max_age_days: Optional[int] = None,
                   limit: int = 100) -> List[IOC]:
        """Search IOCs with filters."""
        results = []
        
        for ioc in self.iocs.values():
            # Filter by type
            if ioc_type and ioc.ioc_type != ioc_type:
                continue
            
            # Filter by threat level
            if threat_level and ioc.threat_level.value < threat_level.value:
                continue
            
            # Filter by tags
            if tags and not any(t in ioc.tags for t in tags):
                continue
            
            # Filter by age
            if max_age_days and ioc.age_days() > max_age_days:
                continue
            
            # Skip expired
            if ioc.is_expired():
                continue
            
            results.append(ioc)
            
            if len(results) >= limit:
                break
        
        # Sort by threat level and confidence
        results.sort(
            key=lambda x: (x.threat_level.value, x.confidence.value),
            reverse=True
        )
        
        return results
    
    def correlate_observations(self, observed_values: List[str]) -> Dict:
        """
        Correlate observed IOC values against threat intelligence.
        
        Args:
            observed_values: List of IOC values observed in environment
            
        Returns:
            Correlation results
        """
        # Find matching IOCs
        matched_iocs = []
        unmatched = []
        
        for value in observed_values:
            ioc = self.lookup_ioc(value)
            if ioc:
                matched_iocs.append(ioc)
            else:
                unmatched.append(value)
        
        if not matched_iocs:
            return {
                'matches': 0,
                'threat_level': 'none',
                'correlation': None,
                'unmatched': unmatched
            }
        
        # Correlate
        correlation = self.correlator.correlate_incident(matched_iocs)
        
        # Determine overall threat level
        max_threat = max(ioc.threat_level.value for ioc in matched_iocs)
        threat_level = ThreatLevel(max_threat).name
        
        return {
            'matches': len(matched_iocs),
            'matched_iocs': [ioc.to_dict() for ioc in matched_iocs],
            'threat_level': threat_level,
            'correlation': correlation,
            'unmatched': unmatched,
            'kill_chain': self._map_to_kill_chain(matched_iocs)
        }
    
    def _map_to_kill_chain(self, iocs: List[IOC]) -> Dict:
        """Map IOCs to kill chain phases."""
        all_ttps = []
        for ioc in iocs:
            all_ttps.extend(ioc.ttps)
        
        return self.mitre.map_to_kill_chain(all_ttps)
    
    def generate_report(self) -> ThreatIntelReport:
        """Generate comprehensive threat intelligence report."""
        # Count by type
        type_counts = defaultdict(int)
        level_counts = defaultdict(int)
        recent = []
        expiring = []
        
        now = datetime.now()
        
        for ioc in self.iocs.values():
            type_counts[ioc.ioc_type.value] += 1
            level_counts[ioc.threat_level.name] += 1
            
            # Recent (last 7 days)
            if ioc.age_days() <= 7:
                recent.append(ioc)
            
            # Expiring soon
            if ioc.expiration and ioc.expiration <= now + timedelta(days=7):
                expiring.append(ioc)
        
        # Active campaigns
        active_campaigns = [
            c.name for c in self.campaigns.values() 
            if c.status == 'active'
        ]
        
        # Top actors (by IOC count)
        actor_ioc_counts = [
            (a.name, len(a.iocs)) for a in self.actors.values()
        ]
        actor_ioc_counts.sort(key=lambda x: -x[1])
        top_actors = [name for name, _ in actor_ioc_counts[:5]]
        
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        
        return ThreatIntelReport(
            report_id=hashlib.md5(str(now).encode()).hexdigest()[:12],
            generated_at=now,
            total_iocs=len(self.iocs),
            iocs_by_type=dict(type_counts),
            threat_level_distribution=dict(level_counts),
            active_campaigns=active_campaigns,
            top_threat_actors=top_actors,
            recent_iocs=sorted(recent, key=lambda x: x.first_seen, reverse=True)[:10],
            expiring_iocs=expiring,
            correlation_alerts=[],
            risk_score=risk_score
        )
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score based on IOCs."""
        if not self.iocs:
            return 0.0
        
        # Weight by threat level
        weights = {
            ThreatLevel.CRITICAL: 10,
            ThreatLevel.HIGH: 7,
            ThreatLevel.MEDIUM: 4,
            ThreatLevel.LOW: 2,
            ThreatLevel.INFO: 1,
            ThreatLevel.UNKNOWN: 0
        }
        
        total_weight = sum(
            weights[ioc.threat_level] for ioc in self.iocs.values()
            if not ioc.is_expired()
        )
        
        # Normalize to 0-100
        max_possible = len(self.iocs) * 10
        return min(100, (total_weight / max_possible) * 100) if max_possible > 0 else 0
    
    def _score_to_level(self, score: int) -> ConfidenceLevel:
        """Convert numeric score to confidence level."""
        if score >= 90:
            return ConfidenceLevel.CONFIRMED
        elif score >= 70:
            return ConfidenceLevel.HIGH
        elif score >= 50:
            return ConfidenceLevel.MEDIUM
        elif score >= 30:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.UNKNOWN
    
    def export_stix(self) -> Dict:
        """Export threat intel in STIX 2.1 format."""
        objects = []
        
        for ioc in self.iocs.values():
            stix_type = self._ioc_to_stix_type(ioc.ioc_type)
            
            obj = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{ioc.ioc_id}',
                'created': ioc.first_seen.isoformat() + 'Z',
                'modified': ioc.last_seen.isoformat() + 'Z',
                'name': f'{ioc.ioc_type.value}: {ioc.value[:50]}',
                'pattern': f"[{stix_type}:value = '{ioc.value}']",
                'pattern_type': 'stix',
                'valid_from': ioc.first_seen.isoformat() + 'Z',
                'labels': ioc.tags,
                'confidence': ioc.confidence.value
            }
            objects.append(obj)
        
        return {
            'type': 'bundle',
            'id': f'bundle--{hashlib.md5(str(datetime.now()).encode()).hexdigest()}',
            'objects': objects
        }
    
    def _ioc_to_stix_type(self, ioc_type: IOCType) -> str:
        """Map IOC type to STIX pattern type."""
        mapping = {
            IOCType.IP_ADDRESS: 'ipv4-addr',
            IOCType.DOMAIN: 'domain-name',
            IOCType.URL: 'url',
            IOCType.FILE_HASH_MD5: 'file:hashes.MD5',
            IOCType.FILE_HASH_SHA1: 'file:hashes.SHA-1',
            IOCType.FILE_HASH_SHA256: 'file:hashes.SHA-256',
            IOCType.EMAIL: 'email-addr'
        }
        return mapping.get(ioc_type, 'artifact')


# Testing
def main():
    """Test threat intelligence fusion."""
    print("Threat Intelligence Fusion Tests")
    print("=" * 50)
    
    fusion = ThreatIntelligenceFusion()
    
    # Add some IOCs
    print("\n1. Adding IOCs...")
    
    fusion.add_ioc(
        IOCType.IP_ADDRESS, "45.33.32.156",
        source=IntelSource.COMMERCIAL,
        source_name="ThreatIntel Pro",
        threat_level=ThreatLevel.HIGH,
        tags=["c2", "botnet", "emotet"]
    )
    
    fusion.add_ioc(
        IOCType.DOMAIN, "malware-c2.evil.com",
        source=IntelSource.OPEN_SOURCE,
        threat_level=ThreatLevel.CRITICAL,
        tags=["c2", "apt"]
    )
    
    fusion.add_ioc(
        IOCType.FILE_HASH_SHA256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source=IntelSource.INTERNAL,
        threat_level=ThreatLevel.MEDIUM,
        tags=["malware", "ransomware"]
    )
    
    fusion.add_ioc(
        IOCType.URL, "https://phishing.bad/login",
        source=IntelSource.COMMUNITY,
        threat_level=ThreatLevel.HIGH,
        tags=["phishing", "credential_theft"]
    )
    
    print(f"   Added {len(fusion.iocs)} IOCs")
    
    # Add threat actor
    print("\n2. Adding Threat Actors...")
    actor = fusion.add_threat_actor(
        name="APT29",
        aliases=["Cozy Bear", "The Dukes"],
        sophistication="advanced",
        motivation=["espionage"],
        targets=["government", "energy", "technology"]
    )
    print(f"   Added actor: {actor.name}")
    
    # Link IOC to actor
    fusion.link_ioc_to_actor("45.33.32.156", "APT29")
    
    # Add campaign
    print("\n3. Adding Campaign...")
    campaign = fusion.add_campaign(
        name="Operation ShadowStrike",
        description="Ongoing espionage campaign targeting government entities",
        threat_actors=["APT29"],
        targets=["government"]
    )
    print(f"   Added campaign: {campaign.name}")
    
    # Link IOC to campaign
    fusion.link_ioc_to_campaign("malware-c2.evil.com", "Operation ShadowStrike")
    
    # Search IOCs
    print("\n4. Searching IOCs...")
    high_threat = fusion.search_iocs(threat_level=ThreatLevel.HIGH)
    print(f"   High threat IOCs: {len(high_threat)}")
    
    c2_iocs = fusion.search_iocs(tags=["c2"])
    print(f"   C2-related IOCs: {len(c2_iocs)}")
    
    # Correlate observations
    print("\n5. Correlating Observations...")
    observations = ["45.33.32.156", "malware-c2.evil.com", "unknown.domain.com"]
    correlation = fusion.correlate_observations(observations)
    
    print(f"   Matches: {correlation['matches']}/{len(observations)}")
    print(f"   Threat Level: {correlation['threat_level']}")
    if correlation['correlation']:
        print(f"   Potential Actors: {correlation['correlation']['potential_actors']}")
        print(f"   Kill Chain Phases: {list(correlation['kill_chain'].keys())}")
    
    # Generate report
    print("\n6. Generating Report...")
    report = fusion.generate_report()
    
    print(f"   Total IOCs: {report.total_iocs}")
    print(f"   By Type: {report.iocs_by_type}")
    print(f"   Threat Levels: {report.threat_level_distribution}")
    print(f"   Risk Score: {report.risk_score:.1f}/100")
    print(f"   Active Campaigns: {report.active_campaigns}")
    print(f"   Top Actors: {report.top_threat_actors}")
    
    # Export STIX
    print("\n7. Exporting STIX...")
    stix = fusion.export_stix()
    print(f"   Exported {len(stix['objects'])} STIX objects")
    
    print("\n" + "=" * 50)
    print("All tests completed!")


if __name__ == "__main__":
    main()
