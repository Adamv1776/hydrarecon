#!/usr/bin/env python3
"""
Autonomous Red Team Engine - HydraRecon v1.2.0

AI-driven adversarial simulation for continuous security assessment.
Automates complex attack chains with intelligent adaptation.

Features:
- Automated attack chain generation
- Intelligent target selection
- Dynamic payload adaptation
- Defense evasion techniques
- Multi-stage attack orchestration
- Campaign management
- Real-time adaptation
- Comprehensive reporting

Author: HydraRecon Team
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import socket
import ssl
import struct
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import ipaddress
import base64
import urllib.request
import urllib.error

import numpy as np

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """MITRE ATT&CK aligned attack phases."""
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
    COMMAND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class TechniqueID(Enum):
    """Simulated attack technique IDs."""
    # Reconnaissance
    T1595_ACTIVE_SCANNING = "T1595"
    T1592_GATHER_VICTIM_HOST = "T1592"
    T1590_GATHER_VICTIM_NETWORK = "T1590"
    
    # Initial Access
    T1566_PHISHING = "T1566"
    T1190_EXPLOIT_PUBLIC_APP = "T1190"
    T1133_EXTERNAL_REMOTE = "T1133"
    
    # Execution
    T1059_CMD_SCRIPT = "T1059"
    T1203_EXPLOITATION = "T1203"
    
    # Persistence
    T1053_SCHEDULED_TASK = "T1053"
    T1547_BOOT_AUTOSTART = "T1547"
    
    # Privilege Escalation
    T1068_EXPLOITATION_PRIVESC = "T1068"
    T1078_VALID_ACCOUNTS = "T1078"
    
    # Defense Evasion
    T1070_INDICATOR_REMOVAL = "T1070"
    T1027_OBFUSCATION = "T1027"
    T1562_IMPAIR_DEFENSES = "T1562"
    
    # Credential Access
    T1003_CREDENTIAL_DUMP = "T1003"
    T1110_BRUTE_FORCE = "T1110"
    
    # Discovery
    T1087_ACCOUNT_DISCOVERY = "T1087"
    T1083_FILE_DISCOVERY = "T1083"
    T1046_NETWORK_SERVICE_SCAN = "T1046"
    
    # Lateral Movement
    T1021_REMOTE_SERVICES = "T1021"
    T1570_LATERAL_TOOL_TRANSFER = "T1570"
    
    # Collection
    T1005_LOCAL_DATA = "T1005"
    T1039_NETWORK_SHARE = "T1039"
    
    # C2
    T1071_APP_LAYER_PROTOCOL = "T1071"
    T1095_NON_APP_LAYER = "T1095"
    
    # Exfiltration
    T1048_EXFIL_ALT_PROTOCOL = "T1048"
    T1041_EXFIL_C2 = "T1041"


class AttackResult(Enum):
    """Result of attack technique execution."""
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    FAILED = "failed"
    DETECTED = "detected"


@dataclass
class Target:
    """Attack target information."""
    target_id: str
    ip_address: str
    hostname: str = ""
    ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    os_type: str = "unknown"
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    access_level: str = "none"  # none, user, admin, system
    last_accessed: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        return {
            'target_id': self.target_id,
            'ip': self.ip_address,
            'hostname': self.hostname,
            'ports': self.ports,
            'services': self.services,
            'os': self.os_type,
            'vulns': len(self.vulnerabilities),
            'access': self.access_level
        }


@dataclass
class AttackAction:
    """Individual attack action."""
    action_id: str
    technique: TechniqueID
    phase: AttackPhase
    target: Target
    timestamp: datetime = field(default_factory=datetime.now)
    result: AttackResult = AttackResult.FAILED
    duration_ms: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)
    blocked_by: str = ""
    detection_risk: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'action_id': self.action_id,
            'technique': self.technique.value,
            'phase': self.phase.value,
            'target': self.target.ip_address,
            'result': self.result.value,
            'duration_ms': self.duration_ms,
            'detection_risk': self.detection_risk,
            'blocked_by': self.blocked_by,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class AttackChain:
    """Multi-stage attack chain."""
    chain_id: str
    name: str
    objective: str
    phases: List[AttackPhase]
    actions: List[AttackAction] = field(default_factory=list)
    current_phase: int = 0
    status: str = "pending"  # pending, running, paused, completed, failed
    success_rate: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        return {
            'chain_id': self.chain_id,
            'name': self.name,
            'objective': self.objective,
            'phases': [p.value for p in self.phases],
            'actions': len(self.actions),
            'current_phase': self.current_phase,
            'status': self.status,
            'success_rate': self.success_rate
        }


class TechniqueSimulator(ABC):
    """Base class for attack technique simulators."""
    
    @abstractmethod
    async def execute(self, target: Target, params: Dict) -> Tuple[AttackResult, Dict]:
        """
        Execute the attack technique.
        
        Returns:
            (result, evidence_dict)
        """
        pass
    
    @property
    @abstractmethod
    def detection_risk(self) -> float:
        """Return detection risk score (0-1)."""
        pass
    
    @property
    @abstractmethod
    def technique_id(self) -> TechniqueID:
        """Return technique ID."""
        pass


class PortScanSimulator(TechniqueSimulator):
    """Simulates port scanning (T1046)."""
    
    @property
    def technique_id(self) -> TechniqueID:
        return TechniqueID.T1046_NETWORK_SERVICE_SCAN
    
    @property
    def detection_risk(self) -> float:
        return 0.3  # Low-moderate risk
    
    async def execute(self, target: Target, params: Dict) -> Tuple[AttackResult, Dict]:
        """Execute port scan."""
        ports_to_scan = params.get('ports', [22, 80, 443, 445, 3389])
        timeout = params.get('timeout', 1.0)
        
        open_ports = []
        services = {}
        
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target.ip_address, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    services[port] = self._identify_service(port)
                    
            except Exception as e:
                logger.debug(f"Port {port} scan error: {e}")
        
        # Update target
        target.ports.extend(open_ports)
        target.services.update(services)
        
        evidence = {
            'scanned_ports': ports_to_scan,
            'open_ports': open_ports,
            'services': services
        }
        
        if open_ports:
            return AttackResult.SUCCESS, evidence
        return AttackResult.FAILED, evidence
    
    def _identify_service(self, port: int) -> str:
        """Identify service by port."""
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 445: 'smb', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 6379: 'redis', 8080: 'http-proxy'
        }
        return common_services.get(port, 'unknown')


class CredentialBruteforceSimulator(TechniqueSimulator):
    """Simulates credential brute force (T1110)."""
    
    @property
    def technique_id(self) -> TechniqueID:
        return TechniqueID.T1110_BRUTE_FORCE
    
    @property
    def detection_risk(self) -> float:
        return 0.7  # High risk - often detected
    
    async def execute(self, target: Target, params: Dict) -> Tuple[AttackResult, Dict]:
        """Execute credential brute force (simulated)."""
        service = params.get('service', 'ssh')
        usernames = params.get('usernames', ['admin', 'root', 'user'])
        
        # Simulate brute force (don't actually try passwords)
        attempts = 0
        found_creds = []
        
        for username in usernames:
            attempts += 1
            # Simulate with low success rate
            await asyncio.sleep(0.01)  # Rate limiting simulation
            
            # Simulated result (5% success rate for demo)
            if random.random() < 0.05:
                found_creds.append({
                    'username': username,
                    'service': service,
                    'simulated': True
                })
        
        evidence = {
            'service': service,
            'attempts': attempts,
            'found': len(found_creds) > 0
        }
        
        if found_creds:
            target.credentials.extend(found_creds)
            return AttackResult.SUCCESS, evidence
        
        return AttackResult.FAILED, evidence


class ServiceExploitSimulator(TechniqueSimulator):
    """Simulates service exploitation (T1190)."""
    
    @property
    def technique_id(self) -> TechniqueID:
        return TechniqueID.T1190_EXPLOIT_PUBLIC_APP
    
    @property
    def detection_risk(self) -> float:
        return 0.5  # Moderate risk
    
    async def execute(self, target: Target, params: Dict) -> Tuple[AttackResult, Dict]:
        """Execute service exploit (simulated)."""
        service = params.get('service', 'http')
        exploit_type = params.get('exploit', 'generic')
        
        # Check if service is available
        service_port = None
        for port, svc in target.services.items():
            if svc == service or svc.startswith(service):
                service_port = port
                break
        
        evidence = {
            'service': service,
            'exploit_type': exploit_type,
            'port': service_port
        }
        
        if service_port is None:
            return AttackResult.FAILED, evidence
        
        # Simulate exploit attempt
        await asyncio.sleep(0.1)
        
        # Check for matching vulnerability
        has_vuln = any(
            exploit_type.lower() in v.lower() 
            for v in target.vulnerabilities
        )
        
        if has_vuln or random.random() < 0.1:  # 10% base success
            target.access_level = 'user'
            evidence['access_gained'] = 'user'
            return AttackResult.SUCCESS, evidence
        
        return AttackResult.FAILED, evidence


class DataExfiltrationSimulator(TechniqueSimulator):
    """Simulates data exfiltration (T1048)."""
    
    @property
    def technique_id(self) -> TechniqueID:
        return TechniqueID.T1048_EXFIL_ALT_PROTOCOL
    
    @property
    def detection_risk(self) -> float:
        return 0.6  # Moderate-high risk
    
    async def execute(self, target: Target, params: Dict) -> Tuple[AttackResult, Dict]:
        """Execute data exfiltration (simulated)."""
        protocol = params.get('protocol', 'dns')
        data_size = params.get('size_kb', 100)
        
        evidence = {
            'protocol': protocol,
            'data_size_kb': data_size,
            'simulated': True
        }
        
        # Require some level of access
        if target.access_level == 'none':
            evidence['reason'] = 'no_access'
            return AttackResult.FAILED, evidence
        
        # Simulate exfiltration
        await asyncio.sleep(0.05 * (data_size / 100))
        
        # Simulate detection probability
        if random.random() < self.detection_risk:
            return AttackResult.DETECTED, evidence
        
        evidence['bytes_exfiltrated'] = data_size * 1024
        return AttackResult.SUCCESS, evidence


class DefenseEvasionSimulator(TechniqueSimulator):
    """Simulates defense evasion (T1070)."""
    
    @property
    def technique_id(self) -> TechniqueID:
        return TechniqueID.T1070_INDICATOR_REMOVAL
    
    @property
    def detection_risk(self) -> float:
        return 0.2  # Low risk if done carefully
    
    async def execute(self, target: Target, params: Dict) -> Tuple[AttackResult, Dict]:
        """Execute defense evasion (simulated)."""
        technique = params.get('technique', 'log_clearing')
        
        evidence = {
            'evasion_technique': technique,
            'simulated': True
        }
        
        if target.access_level not in ['admin', 'system']:
            evidence['reason'] = 'insufficient_privileges'
            return AttackResult.FAILED, evidence
        
        # Simulate evasion
        await asyncio.sleep(0.05)
        
        evasion_success = {
            'log_clearing': 0.8,
            'timestomping': 0.9,
            'process_hiding': 0.7,
            'artifact_deletion': 0.85
        }
        
        if random.random() < evasion_success.get(technique, 0.5):
            evidence['cleared'] = True
            return AttackResult.SUCCESS, evidence
        
        return AttackResult.PARTIAL, evidence


class AttackPlanner:
    """
    AI-driven attack planning engine.
    Selects optimal techniques based on target state.
    """
    
    def __init__(self):
        # Technique selection weights by phase
        self.phase_techniques = {
            AttackPhase.RECONNAISSANCE: [
                (TechniqueID.T1046_NETWORK_SERVICE_SCAN, 1.0),
                (TechniqueID.T1595_ACTIVE_SCANNING, 0.8),
            ],
            AttackPhase.INITIAL_ACCESS: [
                (TechniqueID.T1190_EXPLOIT_PUBLIC_APP, 0.7),
                (TechniqueID.T1110_BRUTE_FORCE, 0.5),
                (TechniqueID.T1566_PHISHING, 0.6),
            ],
            AttackPhase.CREDENTIAL_ACCESS: [
                (TechniqueID.T1110_BRUTE_FORCE, 0.8),
                (TechniqueID.T1003_CREDENTIAL_DUMP, 0.6),
            ],
            AttackPhase.DEFENSE_EVASION: [
                (TechniqueID.T1070_INDICATOR_REMOVAL, 0.9),
                (TechniqueID.T1027_OBFUSCATION, 0.7),
            ],
            AttackPhase.EXFILTRATION: [
                (TechniqueID.T1048_EXFIL_ALT_PROTOCOL, 0.8),
                (TechniqueID.T1041_EXFIL_C2, 0.6),
            ],
        }
        
        # Technique prerequisites
        self.prerequisites = {
            TechniqueID.T1003_CREDENTIAL_DUMP: ['admin', 'system'],
            TechniqueID.T1070_INDICATOR_REMOVAL: ['admin', 'system'],
            TechniqueID.T1048_EXFIL_ALT_PROTOCOL: ['user', 'admin', 'system'],
        }
    
    def plan_attack_chain(self, objective: str, 
                         targets: List[Target]) -> AttackChain:
        """
        Generate an attack chain based on objective.
        
        Args:
            objective: Attack objective
            targets: Available targets
            
        Returns:
            Planned attack chain
        """
        # Map objectives to phases
        objective_phases = {
            'reconnaissance': [AttackPhase.RECONNAISSANCE],
            'data_theft': [
                AttackPhase.RECONNAISSANCE,
                AttackPhase.INITIAL_ACCESS,
                AttackPhase.CREDENTIAL_ACCESS,
                AttackPhase.COLLECTION,
                AttackPhase.EXFILTRATION
            ],
            'persistence': [
                AttackPhase.RECONNAISSANCE,
                AttackPhase.INITIAL_ACCESS,
                AttackPhase.PERSISTENCE,
                AttackPhase.DEFENSE_EVASION
            ],
            'full_compromise': [
                AttackPhase.RECONNAISSANCE,
                AttackPhase.INITIAL_ACCESS,
                AttackPhase.PRIVILEGE_ESCALATION,
                AttackPhase.CREDENTIAL_ACCESS,
                AttackPhase.DISCOVERY,
                AttackPhase.LATERAL_MOVEMENT,
                AttackPhase.COLLECTION,
                AttackPhase.EXFILTRATION,
                AttackPhase.DEFENSE_EVASION
            ]
        }
        
        phases = objective_phases.get(objective, [AttackPhase.RECONNAISSANCE])
        
        chain_id = hashlib.md5(
            f"{objective}{time.time()}".encode()
        ).hexdigest()[:12]
        
        return AttackChain(
            chain_id=chain_id,
            name=f"Auto-{objective}-{chain_id[:6]}",
            objective=objective,
            phases=phases
        )
    
    def select_technique(self, phase: AttackPhase, 
                        target: Target,
                        history: List[AttackAction]) -> Optional[TechniqueID]:
        """
        Select optimal technique for current phase.
        
        Args:
            phase: Current attack phase
            target: Target being attacked
            history: Previous attack actions
            
        Returns:
            Selected technique ID or None
        """
        available = self.phase_techniques.get(phase, [])
        if not available:
            return None
        
        # Filter by prerequisites
        valid_techniques = []
        for tech, weight in available:
            prereqs = self.prerequisites.get(tech, [])
            if not prereqs or target.access_level in prereqs:
                # Avoid repeating failed techniques
                failed_count = sum(
                    1 for a in history 
                    if a.technique == tech and a.result == AttackResult.FAILED
                )
                adjusted_weight = weight * (0.5 ** failed_count)
                valid_techniques.append((tech, adjusted_weight))
        
        if not valid_techniques:
            return None
        
        # Weighted selection
        techniques, weights = zip(*valid_techniques)
        total = sum(weights)
        probs = [w / total for w in weights]
        
        return np.random.choice(techniques, p=probs)
    
    def adapt_strategy(self, chain: AttackChain, 
                      recent_results: List[AttackResult]) -> Dict:
        """
        Adapt attack strategy based on results.
        
        Returns:
            Strategy adjustments
        """
        adjustments = {
            'slow_down': False,
            'switch_technique': False,
            'abort': False,
            'reason': ''
        }
        
        if not recent_results:
            return adjustments
        
        # Calculate failure rate
        recent = recent_results[-5:]
        failure_rate = sum(
            1 for r in recent if r in [AttackResult.FAILED, AttackResult.BLOCKED]
        ) / len(recent)
        
        detection_rate = sum(
            1 for r in recent if r == AttackResult.DETECTED
        ) / len(recent)
        
        if detection_rate > 0.3:
            adjustments['slow_down'] = True
            adjustments['reason'] = 'high_detection_rate'
        
        if failure_rate > 0.6:
            adjustments['switch_technique'] = True
            adjustments['reason'] = 'high_failure_rate'
        
        if detection_rate > 0.5 and failure_rate > 0.7:
            adjustments['abort'] = True
            adjustments['reason'] = 'operation_compromised'
        
        return adjustments


class TechniqueLibrary:
    """
    Library of attack technique simulators.
    """
    
    def __init__(self):
        self.simulators: Dict[TechniqueID, TechniqueSimulator] = {}
        self._register_simulators()
    
    def _register_simulators(self):
        """Register all technique simulators."""
        simulators = [
            PortScanSimulator(),
            CredentialBruteforceSimulator(),
            ServiceExploitSimulator(),
            DataExfiltrationSimulator(),
            DefenseEvasionSimulator(),
        ]
        
        for sim in simulators:
            self.simulators[sim.technique_id] = sim
    
    def get_simulator(self, technique: TechniqueID) -> Optional[TechniqueSimulator]:
        """Get simulator for technique."""
        return self.simulators.get(technique)
    
    def list_techniques(self) -> List[Dict]:
        """List all available techniques."""
        return [
            {
                'id': tech.value,
                'detection_risk': sim.detection_risk
            }
            for tech, sim in self.simulators.items()
        ]


class CampaignManager:
    """
    Manages red team campaigns and operations.
    """
    
    def __init__(self):
        self.campaigns: Dict[str, Dict] = {}
        self.active_chains: Dict[str, AttackChain] = {}
        self.completed_chains: List[AttackChain] = []
        self.global_stats: Dict[str, int] = defaultdict(int)
    
    def create_campaign(self, name: str, 
                       objectives: List[str],
                       scope: Dict) -> str:
        """
        Create a new red team campaign.
        
        Returns:
            Campaign ID
        """
        campaign_id = hashlib.md5(
            f"{name}{time.time()}".encode()
        ).hexdigest()[:12]
        
        self.campaigns[campaign_id] = {
            'id': campaign_id,
            'name': name,
            'objectives': objectives,
            'scope': scope,
            'created_at': datetime.now().isoformat(),
            'status': 'active',
            'chains': []
        }
        
        return campaign_id
    
    def add_chain_to_campaign(self, campaign_id: str, chain: AttackChain):
        """Add attack chain to campaign."""
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id]['chains'].append(chain.chain_id)
            self.active_chains[chain.chain_id] = chain
    
    def record_action(self, chain_id: str, action: AttackAction):
        """Record attack action."""
        if chain_id in self.active_chains:
            self.active_chains[chain_id].actions.append(action)
        
        # Update global stats
        self.global_stats['total_actions'] += 1
        self.global_stats[f'result_{action.result.value}'] += 1
    
    def complete_chain(self, chain_id: str):
        """Mark chain as completed."""
        if chain_id in self.active_chains:
            chain = self.active_chains.pop(chain_id)
            chain.status = 'completed'
            chain.completed_at = datetime.now()
            
            # Calculate success rate
            if chain.actions:
                successes = sum(
                    1 for a in chain.actions 
                    if a.result == AttackResult.SUCCESS
                )
                chain.success_rate = successes / len(chain.actions)
            
            self.completed_chains.append(chain)
    
    def get_campaign_report(self, campaign_id: str) -> Dict:
        """Generate campaign report."""
        if campaign_id not in self.campaigns:
            return {}
        
        campaign = self.campaigns[campaign_id]
        chain_ids = campaign['chains']
        
        # Aggregate chain results
        total_actions = 0
        successful = 0
        detected = 0
        techniques_used = set()
        
        for chain_id in chain_ids:
            chain = self.active_chains.get(chain_id)
            if not chain:
                chain = next(
                    (c for c in self.completed_chains if c.chain_id == chain_id),
                    None
                )
            
            if chain:
                for action in chain.actions:
                    total_actions += 1
                    if action.result == AttackResult.SUCCESS:
                        successful += 1
                    if action.result == AttackResult.DETECTED:
                        detected += 1
                    techniques_used.add(action.technique.value)
        
        return {
            'campaign_id': campaign_id,
            'name': campaign['name'],
            'objectives': campaign['objectives'],
            'total_chains': len(chain_ids),
            'total_actions': total_actions,
            'success_rate': successful / max(1, total_actions),
            'detection_rate': detected / max(1, total_actions),
            'techniques_used': list(techniques_used),
            'status': campaign['status']
        }


class AutonomousRedTeam:
    """
    Main autonomous red team engine.
    """
    
    def __init__(self):
        self.planner = AttackPlanner()
        self.library = TechniqueLibrary()
        self.campaign_mgr = CampaignManager()
        
        self.targets: Dict[str, Target] = {}
        self.is_running = False
        self.stealth_mode = True
        self.delay_between_actions = 1.0  # seconds
    
    def add_target(self, ip: str, hostname: str = "") -> Target:
        """Add target to scope."""
        target_id = hashlib.md5(ip.encode()).hexdigest()[:12]
        
        target = Target(
            target_id=target_id,
            ip_address=ip,
            hostname=hostname or ip
        )
        
        self.targets[target_id] = target
        return target
    
    def remove_target(self, target_id: str):
        """Remove target from scope."""
        self.targets.pop(target_id, None)
    
    async def run_chain(self, chain: AttackChain, 
                       target: Target) -> AttackChain:
        """
        Execute an attack chain against target.
        
        Args:
            chain: Attack chain to execute
            target: Primary target
            
        Returns:
            Completed attack chain
        """
        chain.status = 'running'
        chain.started_at = datetime.now()
        
        for phase in chain.phases:
            # Select technique for phase
            technique = self.planner.select_technique(
                phase, target, chain.actions
            )
            
            if technique is None:
                logger.warning(f"No technique available for phase {phase}")
                continue
            
            # Get simulator
            simulator = self.library.get_simulator(technique)
            if simulator is None:
                continue
            
            # Execute technique
            action = await self._execute_technique(
                simulator, target, phase, {}
            )
            
            chain.actions.append(action)
            self.campaign_mgr.record_action(chain.chain_id, action)
            
            # Adapt strategy
            recent_results = [a.result for a in chain.actions[-5:]]
            adjustments = self.planner.adapt_strategy(chain, recent_results)
            
            if adjustments['abort']:
                logger.warning(f"Aborting chain: {adjustments['reason']}")
                chain.status = 'aborted'
                break
            
            if adjustments['slow_down'] and self.stealth_mode:
                self.delay_between_actions *= 1.5
            
            # Delay between actions
            await asyncio.sleep(self.delay_between_actions)
        
        if chain.status == 'running':
            chain.status = 'completed'
        
        chain.completed_at = datetime.now()
        
        # Calculate success rate
        if chain.actions:
            successes = sum(
                1 for a in chain.actions 
                if a.result == AttackResult.SUCCESS
            )
            chain.success_rate = successes / len(chain.actions)
        
        return chain
    
    async def _execute_technique(self, simulator: TechniqueSimulator,
                                target: Target,
                                phase: AttackPhase,
                                params: Dict) -> AttackAction:
        """Execute single technique."""
        action_id = hashlib.md5(
            f"{simulator.technique_id}{time.time()}".encode()
        ).hexdigest()[:12]
        
        start_time = time.time()
        
        try:
            result, evidence = await simulator.execute(target, params)
        except Exception as e:
            logger.error(f"Technique execution failed: {e}")
            result = AttackResult.FAILED
            evidence = {'error': str(e)}
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        action = AttackAction(
            action_id=action_id,
            technique=simulator.technique_id,
            phase=phase,
            target=target,
            result=result,
            duration_ms=duration_ms,
            evidence=evidence,
            detection_risk=simulator.detection_risk
        )
        
        return action
    
    async def run_campaign(self, campaign_id: str) -> Dict:
        """
        Run full red team campaign.
        
        Returns:
            Campaign results
        """
        if campaign_id not in self.campaign_mgr.campaigns:
            return {'error': 'Campaign not found'}
        
        campaign = self.campaign_mgr.campaigns[campaign_id]
        self.is_running = True
        
        for objective in campaign['objectives']:
            # Plan attack chain
            targets = list(self.targets.values())
            if not targets:
                continue
            
            chain = self.planner.plan_attack_chain(objective, targets)
            self.campaign_mgr.add_chain_to_campaign(campaign_id, chain)
            
            # Execute against each target
            for target in targets:
                if not self.is_running:
                    break
                
                await self.run_chain(chain, target)
            
            self.campaign_mgr.complete_chain(chain.chain_id)
        
        self.is_running = False
        return self.campaign_mgr.get_campaign_report(campaign_id)
    
    def stop(self):
        """Stop running campaign."""
        self.is_running = False
    
    def get_status(self) -> Dict:
        """Get current engine status."""
        return {
            'is_running': self.is_running,
            'targets': len(self.targets),
            'active_chains': len(self.campaign_mgr.active_chains),
            'completed_chains': len(self.campaign_mgr.completed_chains),
            'stealth_mode': self.stealth_mode,
            'delay_seconds': self.delay_between_actions,
            'global_stats': dict(self.campaign_mgr.global_stats)
        }
    
    def generate_report(self) -> Dict:
        """Generate comprehensive report."""
        all_actions = []
        for chain in self.campaign_mgr.completed_chains:
            all_actions.extend(chain.actions)
        
        technique_stats = defaultdict(lambda: {'success': 0, 'total': 0})
        phase_stats = defaultdict(lambda: {'success': 0, 'total': 0})
        
        for action in all_actions:
            tech = action.technique.value
            phase = action.phase.value
            
            technique_stats[tech]['total'] += 1
            phase_stats[phase]['total'] += 1
            
            if action.result == AttackResult.SUCCESS:
                technique_stats[tech]['success'] += 1
                phase_stats[phase]['success'] += 1
        
        return {
            'total_actions': len(all_actions),
            'completed_chains': len(self.campaign_mgr.completed_chains),
            'technique_effectiveness': {
                k: v['success'] / max(1, v['total'])
                for k, v in technique_stats.items()
            },
            'phase_success_rates': {
                k: v['success'] / max(1, v['total'])
                for k, v in phase_stats.items()
            },
            'targets_compromised': sum(
                1 for t in self.targets.values()
                if t.access_level != 'none'
            ),
            'total_targets': len(self.targets)
        }


# Testing
async def main():
    """Test autonomous red team engine."""
    print("Autonomous Red Team Engine Tests")
    print("=" * 50)
    
    engine = AutonomousRedTeam()
    
    # Add targets
    print("\n1. Adding Targets...")
    target1 = engine.add_target("127.0.0.1", "localhost")
    target2 = engine.add_target("192.168.1.1", "gateway")
    print(f"   Added {len(engine.targets)} targets")
    
    # Create campaign
    print("\n2. Creating Campaign...")
    campaign_id = engine.campaign_mgr.create_campaign(
        name="Security Assessment",
        objectives=['reconnaissance', 'data_theft'],
        scope={'internal': True, 'external': False}
    )
    print(f"   Campaign ID: {campaign_id}")
    
    # Plan attack chain
    print("\n3. Planning Attack Chain...")
    chain = engine.planner.plan_attack_chain(
        'reconnaissance',
        list(engine.targets.values())
    )
    print(f"   Chain: {chain.name}")
    print(f"   Phases: {[p.value for p in chain.phases]}")
    
    # Execute chain
    print("\n4. Executing Attack Chain...")
    engine.campaign_mgr.add_chain_to_campaign(campaign_id, chain)
    
    result_chain = await engine.run_chain(chain, target1)
    
    print(f"   Status: {result_chain.status}")
    print(f"   Actions: {len(result_chain.actions)}")
    print(f"   Success Rate: {result_chain.success_rate:.0%}")
    
    # Show actions
    print("\n5. Attack Actions:")
    for action in result_chain.actions[:5]:
        print(f"   - {action.technique.value}: {action.result.value}")
        if action.evidence:
            print(f"     Evidence: {list(action.evidence.keys())}")
    
    # Get status
    print("\n6. Engine Status:")
    status = engine.get_status()
    print(f"   Active: {status['is_running']}")
    print(f"   Targets: {status['targets']}")
    print(f"   Stats: {status['global_stats']}")
    
    # Generate report
    print("\n7. Final Report:")
    engine.campaign_mgr.complete_chain(chain.chain_id)
    report = engine.generate_report()
    
    print(f"   Total Actions: {report['total_actions']}")
    print(f"   Completed Chains: {report['completed_chains']}")
    print(f"   Technique Effectiveness: {report['technique_effectiveness']}")
    
    # Campaign report
    print("\n8. Campaign Report:")
    camp_report = engine.campaign_mgr.get_campaign_report(campaign_id)
    print(f"   Success Rate: {camp_report['success_rate']:.0%}")
    print(f"   Detection Rate: {camp_report['detection_rate']:.0%}")
    print(f"   Techniques Used: {camp_report['techniques_used']}")
    
    print("\n" + "=" * 50)
    print("All tests completed!")


if __name__ == "__main__":
    asyncio.run(main())
