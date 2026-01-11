#!/usr/bin/env python3
"""
Runtime Application Self-Protection (RASP) Engine - HydraRecon v1.2.0

Real-time application protection through behavior monitoring and intervention.
Provides deep runtime visibility and automatic threat response.

Features:
- System call monitoring
- Memory protection
- Process integrity verification
- Runtime code analysis
- Anomaly-based detection
- Automatic threat response
- Event correlation
- Forensic logging

Author: HydraRecon Team
"""

import asyncio
import ctypes
import hashlib
import logging
import mmap
import os
import platform
import signal
import struct
import sys
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor
import json

import numpy as np

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of runtime threats."""
    BUFFER_OVERFLOW = auto()
    CODE_INJECTION = auto()
    MEMORY_CORRUPTION = auto()
    PRIVILEGE_ESCALATION = auto()
    SUSPICIOUS_SYSCALL = auto()
    PROCESS_HOLLOWING = auto()
    DLL_INJECTION = auto()
    HOOKING_ATTEMPT = auto()
    ANOMALOUS_BEHAVIOR = auto()
    DATA_EXFILTRATION = auto()
    CRYPTO_MINING = auto()
    RANSOMWARE_BEHAVIOR = auto()


class ResponseAction(Enum):
    """Automated response actions."""
    LOG = "log"
    ALERT = "alert"
    BLOCK = "block"
    TERMINATE = "terminate"
    QUARANTINE = "quarantine"
    ROLLBACK = "rollback"


class SeverityLevel(Enum):
    """Threat severity levels."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class SecurityEvent:
    """Runtime security event."""
    event_id: str
    timestamp: datetime
    threat_type: ThreatType
    severity: SeverityLevel
    description: str
    process_id: int
    thread_id: int
    source_module: str = ""
    stack_trace: str = ""
    memory_context: Dict[str, Any] = field(default_factory=dict)
    response_taken: ResponseAction = ResponseAction.LOG
    additional_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'threat_type': self.threat_type.name,
            'severity': self.severity.name,
            'description': self.description,
            'process_id': self.process_id,
            'thread_id': self.thread_id,
            'source_module': self.source_module,
            'response': self.response_taken.value,
            'additional_data': self.additional_data
        }


@dataclass
class ProcessProfile:
    """Profile of monitored process behavior."""
    pid: int
    name: str
    start_time: datetime
    executable_hash: str
    loaded_modules: Set[str] = field(default_factory=set)
    syscall_counts: Dict[str, int] = field(default_factory=dict)
    memory_regions: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    file_operations: List[Dict] = field(default_factory=list)
    cpu_baseline: float = 0.0
    memory_baseline: int = 0
    anomaly_score: float = 0.0


class MemoryProtector:
    """
    Memory protection and integrity monitoring.
    """
    
    def __init__(self):
        self.protected_regions: Dict[int, Dict] = {}
        self.page_guards: Set[int] = set()
        self.integrity_hashes: Dict[int, str] = {}
    
    def protect_region(self, address: int, size: int, 
                      permissions: str = "r") -> bool:
        """
        Mark a memory region as protected.
        
        Args:
            address: Start address
            size: Region size
            permissions: r=read, w=write, x=execute
            
        Returns:
            Success status
        """
        try:
            # Calculate hash of current content
            content_hash = self._hash_region(address, size)
            
            self.protected_regions[address] = {
                'size': size,
                'permissions': permissions,
                'original_hash': content_hash,
                'protected_at': datetime.now()
            }
            
            self.integrity_hashes[address] = content_hash
            
            logger.debug(f"Protected memory region at 0x{address:x}, size {size}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to protect region: {e}")
            return False
    
    def _hash_region(self, address: int, size: int) -> str:
        """Hash memory region content."""
        # In production, would read actual memory
        # Here we simulate with address-based hash
        data = struct.pack('QQ', address, size)
        return hashlib.sha256(data).hexdigest()[:32]
    
    def verify_integrity(self, address: int) -> Tuple[bool, Optional[str]]:
        """
        Verify integrity of protected region.
        
        Returns:
            (is_intact, violation_type if any)
        """
        if address not in self.protected_regions:
            return True, None
        
        region = self.protected_regions[address]
        current_hash = self._hash_region(address, region['size'])
        
        if current_hash != self.integrity_hashes[address]:
            return False, "memory_modification"
        
        return True, None
    
    def check_all_regions(self) -> List[Dict]:
        """Check integrity of all protected regions."""
        violations = []
        
        for address, region in self.protected_regions.items():
            is_intact, violation = self.verify_integrity(address)
            if not is_intact:
                violations.append({
                    'address': f"0x{address:x}",
                    'size': region['size'],
                    'violation': violation,
                    'detected_at': datetime.now().isoformat()
                })
        
        return violations
    
    def detect_nx_violation(self, address: int) -> bool:
        """Detect execution in non-executable region."""
        # Check if address is in a protected region marked non-executable
        for region_addr, region in self.protected_regions.items():
            if region_addr <= address < region_addr + region['size']:
                if 'x' not in region.get('permissions', ''):
                    return True
        return False


class SyscallMonitor:
    """
    System call monitoring and analysis.
    """
    
    # High-risk syscalls to monitor
    SENSITIVE_SYSCALLS = {
        'ptrace': {'risk': 5, 'reason': 'process manipulation'},
        'mprotect': {'risk': 4, 'reason': 'memory permission change'},
        'mmap': {'risk': 3, 'reason': 'memory mapping'},
        'execve': {'risk': 5, 'reason': 'process execution'},
        'fork': {'risk': 3, 'reason': 'process creation'},
        'clone': {'risk': 3, 'reason': 'thread/process creation'},
        'open': {'risk': 2, 'reason': 'file access'},
        'write': {'risk': 2, 'reason': 'data write'},
        'socket': {'risk': 3, 'reason': 'network operation'},
        'connect': {'risk': 3, 'reason': 'network connection'},
        'sendto': {'risk': 3, 'reason': 'network send'},
        'recvfrom': {'risk': 2, 'reason': 'network receive'},
        'kill': {'risk': 4, 'reason': 'signal sending'},
        'setuid': {'risk': 5, 'reason': 'privilege change'},
        'setgid': {'risk': 5, 'reason': 'privilege change'},
    }
    
    # Suspicious syscall patterns
    ATTACK_PATTERNS = [
        {
            'name': 'shellcode_execution',
            'sequence': ['mmap', 'mprotect', 'write'],
            'window': 100  # ms
        },
        {
            'name': 'process_injection',
            'sequence': ['ptrace', 'write', 'ptrace'],
            'window': 500
        },
        {
            'name': 'credential_dump',
            'sequence': ['open', 'read', 'socket', 'sendto'],
            'window': 1000
        }
    ]
    
    def __init__(self, max_history: int = 1000):
        self.syscall_history: deque = deque(maxlen=max_history)
        self.syscall_counts: Dict[str, int] = {}
        self.baseline_established = False
        self.baseline_rates: Dict[str, float] = {}
        self.anomaly_threshold = 3.0  # Standard deviations
    
    def record_syscall(self, syscall_name: str, 
                      args: Dict[str, Any] = None,
                      pid: int = 0,
                      tid: int = 0) -> Optional[Dict]:
        """
        Record a system call and check for threats.
        
        Returns:
            Alert dict if threat detected, None otherwise
        """
        timestamp = time.time() * 1000  # ms
        
        entry = {
            'syscall': syscall_name,
            'timestamp': timestamp,
            'args': args or {},
            'pid': pid,
            'tid': tid
        }
        
        self.syscall_history.append(entry)
        self.syscall_counts[syscall_name] = self.syscall_counts.get(syscall_name, 0) + 1
        
        alerts = []
        
        # Check if sensitive syscall
        if syscall_name in self.SENSITIVE_SYSCALLS:
            info = self.SENSITIVE_SYSCALLS[syscall_name]
            if info['risk'] >= 4:
                alerts.append({
                    'type': 'high_risk_syscall',
                    'syscall': syscall_name,
                    'reason': info['reason'],
                    'risk_level': info['risk']
                })
        
        # Check for attack patterns
        pattern_match = self._check_patterns()
        if pattern_match:
            alerts.append(pattern_match)
        
        # Check for anomaly
        if self.baseline_established:
            anomaly = self._check_anomaly(syscall_name)
            if anomaly:
                alerts.append(anomaly)
        
        return alerts[0] if alerts else None
    
    def _check_patterns(self) -> Optional[Dict]:
        """Check syscall history for attack patterns."""
        if len(self.syscall_history) < 3:
            return None
        
        recent = list(self.syscall_history)[-20:]  # Last 20 syscalls
        
        for pattern in self.ATTACK_PATTERNS:
            if self._matches_pattern(recent, pattern):
                return {
                    'type': 'attack_pattern',
                    'pattern_name': pattern['name'],
                    'severity': 'high'
                }
        
        return None
    
    def _matches_pattern(self, history: List[Dict], pattern: Dict) -> bool:
        """Check if recent history matches attack pattern."""
        sequence = pattern['sequence']
        window_ms = pattern['window']
        
        # Extract just syscall names
        syscalls = [h['syscall'] for h in history]
        
        # Look for sequence
        for i in range(len(syscalls) - len(sequence) + 1):
            if syscalls[i:i+len(sequence)] == sequence:
                # Check timing window
                start_time = history[i]['timestamp']
                end_time = history[i + len(sequence) - 1]['timestamp']
                
                if end_time - start_time <= window_ms:
                    return True
        
        return False
    
    def establish_baseline(self, duration_seconds: int = 60):
        """
        Establish baseline syscall rates.
        
        In production, this would run for the specified duration.
        Here we simulate with current counts.
        """
        if self.syscall_counts:
            total = sum(self.syscall_counts.values())
            for syscall, count in self.syscall_counts.items():
                self.baseline_rates[syscall] = count / max(1, total)
        
        self.baseline_established = True
        logger.info("Syscall baseline established")
    
    def _check_anomaly(self, syscall_name: str) -> Optional[Dict]:
        """Check if syscall rate is anomalous."""
        if syscall_name not in self.baseline_rates:
            # New syscall not seen during baseline
            return {
                'type': 'new_syscall',
                'syscall': syscall_name,
                'severity': 'medium'
            }
        
        # Compare current rate to baseline
        baseline_rate = self.baseline_rates[syscall_name]
        total = sum(self.syscall_counts.values())
        current_rate = self.syscall_counts[syscall_name] / max(1, total)
        
        # Simple threshold check
        if current_rate > baseline_rate * self.anomaly_threshold:
            return {
                'type': 'rate_anomaly',
                'syscall': syscall_name,
                'baseline_rate': baseline_rate,
                'current_rate': current_rate,
                'severity': 'medium'
            }
        
        return None


class BehaviorAnalyzer:
    """
    Behavioral analysis for runtime anomaly detection.
    """
    
    def __init__(self):
        self.process_profiles: Dict[int, ProcessProfile] = {}
        self.behavior_models: Dict[str, Dict] = {}
        self.event_window: deque = deque(maxlen=10000)
    
    def profile_process(self, pid: int) -> ProcessProfile:
        """Create or get process profile."""
        if pid in self.process_profiles:
            return self.process_profiles[pid]
        
        # Create new profile
        profile = ProcessProfile(
            pid=pid,
            name=self._get_process_name(pid),
            start_time=datetime.now(),
            executable_hash=self._get_exe_hash(pid)
        )
        
        self.process_profiles[pid] = profile
        return profile
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name by PID."""
        try:
            if platform.system() == 'Linux':
                with open(f'/proc/{pid}/comm', 'r') as f:
                    return f.read().strip()
        except:
            pass
        return f"process_{pid}"
    
    def _get_exe_hash(self, pid: int) -> str:
        """Get hash of process executable."""
        try:
            if platform.system() == 'Linux':
                exe_path = os.readlink(f'/proc/{pid}/exe')
                with open(exe_path, 'rb') as f:
                    return hashlib.sha256(f.read(4096)).hexdigest()[:16]
        except:
            pass
        return hashlib.md5(str(pid).encode()).hexdigest()[:16]
    
    def record_event(self, pid: int, event_type: str, 
                    details: Dict[str, Any]) -> float:
        """
        Record behavioral event and return anomaly score.
        
        Returns:
            Anomaly score (0.0 = normal, 1.0+ = anomalous)
        """
        profile = self.profile_process(pid)
        
        event = {
            'timestamp': time.time(),
            'pid': pid,
            'type': event_type,
            'details': details
        }
        
        self.event_window.append(event)
        
        # Update profile
        if event_type == 'syscall':
            syscall = details.get('name', 'unknown')
            profile.syscall_counts[syscall] = \
                profile.syscall_counts.get(syscall, 0) + 1
        
        elif event_type == 'file_op':
            profile.file_operations.append({
                'path': details.get('path'),
                'operation': details.get('operation'),
                'timestamp': datetime.now().isoformat()
            })
        
        elif event_type == 'network':
            profile.network_connections.append({
                'remote': details.get('remote'),
                'port': details.get('port'),
                'timestamp': datetime.now().isoformat()
            })
        
        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly_score(profile, event)
        profile.anomaly_score = anomaly_score
        
        return anomaly_score
    
    def _calculate_anomaly_score(self, profile: ProcessProfile, 
                                 event: Dict) -> float:
        """Calculate behavioral anomaly score."""
        scores = []
        
        # Check for rapid syscall changes
        if profile.syscall_counts:
            syscall_entropy = self._calculate_entropy(
                list(profile.syscall_counts.values())
            )
            # Low entropy (concentrated syscalls) can be suspicious
            if syscall_entropy < 1.0:
                scores.append(0.5)
        
        # Check for unusual file patterns
        if len(profile.file_operations) > 10:
            recent_ops = profile.file_operations[-10:]
            # Rapid file operations
            time_span = 1.0  # Simulated
            ops_per_sec = len(recent_ops) / max(0.1, time_span)
            if ops_per_sec > 100:  # High file I/O
                scores.append(0.7)
        
        # Check for network patterns
        if len(profile.network_connections) > 5:
            # Multiple unique destinations
            unique_hosts = len(set(
                c.get('remote') for c in profile.network_connections
            ))
            if unique_hosts > 10:
                scores.append(0.3)
        
        # Event-specific scoring
        event_type = event.get('type')
        details = event.get('details', {})
        
        if event_type == 'syscall':
            if details.get('name') in ['ptrace', 'execve', 'setuid']:
                scores.append(0.6)
        
        return max(scores) if scores else 0.0
    
    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy."""
        total = sum(values)
        if total == 0:
            return 0.0
        
        probs = [v / total for v in values if v > 0]
        return -sum(p * np.log2(p) for p in probs)
    
    def detect_ransomware_behavior(self, pid: int) -> Tuple[bool, float]:
        """
        Detect ransomware-like behavior patterns.
        
        Returns:
            (is_detected, confidence)
        """
        if pid not in self.process_profiles:
            return False, 0.0
        
        profile = self.process_profiles[pid]
        indicators = 0
        
        # Check for mass file operations
        if len(profile.file_operations) > 100:
            indicators += 1
        
        # Check for file extension patterns (rename/encrypt)
        extensions_seen = set()
        for op in profile.file_operations:
            path = op.get('path', '')
            if '.' in path:
                ext = path.rsplit('.', 1)[-1]
                extensions_seen.add(ext)
        
        # Unusual extension diversity
        if len(extensions_seen) < 3 and len(profile.file_operations) > 50:
            indicators += 1
        
        # Check for crypto syscalls
        crypto_syscalls = {'getrandom', 'crypto'}
        if any(s in profile.syscall_counts for s in crypto_syscalls):
            indicators += 1
        
        # Check for rapid file system traversal
        if profile.syscall_counts.get('getdents', 0) > 100:
            indicators += 1
        
        confidence = min(1.0, indicators * 0.25)
        is_detected = indicators >= 3
        
        return is_detected, confidence


class ResponseEngine:
    """
    Automated threat response engine.
    """
    
    def __init__(self):
        self.response_rules: List[Dict] = []
        self.action_log: List[Dict] = []
        self.blocked_pids: Set[int] = set()
        self.quarantine_path = "/tmp/rasp_quarantine"
    
    def add_rule(self, threat_type: ThreatType, 
                min_severity: SeverityLevel,
                action: ResponseAction):
        """Add response rule."""
        self.response_rules.append({
            'threat_type': threat_type,
            'min_severity': min_severity,
            'action': action
        })
    
    def determine_response(self, event: SecurityEvent) -> ResponseAction:
        """Determine appropriate response for event."""
        matched_action = ResponseAction.LOG
        
        for rule in self.response_rules:
            if rule['threat_type'] == event.threat_type:
                if event.severity.value >= rule['min_severity'].value:
                    if rule['action'].value > matched_action.value:
                        matched_action = rule['action']
        
        return matched_action
    
    def execute_response(self, event: SecurityEvent, 
                        action: ResponseAction) -> bool:
        """
        Execute response action.
        
        Returns:
            Success status
        """
        self.action_log.append({
            'event_id': event.event_id,
            'action': action.value,
            'timestamp': datetime.now().isoformat(),
            'pid': event.process_id
        })
        
        success = True
        
        if action == ResponseAction.LOG:
            logger.warning(f"Security event: {event.description}")
        
        elif action == ResponseAction.ALERT:
            logger.critical(f"ALERT: {event.threat_type.name} - {event.description}")
            # In production: send to SIEM, notify security team
        
        elif action == ResponseAction.BLOCK:
            success = self._block_process(event.process_id)
        
        elif action == ResponseAction.TERMINATE:
            success = self._terminate_process(event.process_id)
        
        elif action == ResponseAction.QUARANTINE:
            success = self._quarantine_artifacts(event)
        
        return success
    
    def _block_process(self, pid: int) -> bool:
        """Block process from further execution."""
        try:
            self.blocked_pids.add(pid)
            # In production: use seccomp/LSM to block
            logger.info(f"Blocked process {pid}")
            return True
        except Exception as e:
            logger.error(f"Failed to block {pid}: {e}")
            return False
    
    def _terminate_process(self, pid: int) -> bool:
        """Terminate malicious process."""
        try:
            os.kill(pid, signal.SIGKILL)
            logger.info(f"Terminated process {pid}")
            return True
        except ProcessLookupError:
            return True  # Already dead
        except Exception as e:
            logger.error(f"Failed to terminate {pid}: {e}")
            return False
    
    def _quarantine_artifacts(self, event: SecurityEvent) -> bool:
        """Move malicious artifacts to quarantine."""
        try:
            os.makedirs(self.quarantine_path, exist_ok=True)
            
            # Log quarantine action
            quarantine_record = {
                'event_id': event.event_id,
                'timestamp': datetime.now().isoformat(),
                'threat_type': event.threat_type.name,
                'data': event.additional_data
            }
            
            record_path = os.path.join(
                self.quarantine_path,
                f"{event.event_id}.json"
            )
            
            with open(record_path, 'w') as f:
                json.dump(quarantine_record, f, indent=2)
            
            logger.info(f"Quarantined artifacts for event {event.event_id}")
            return True
            
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")
            return False


class RASPEngine:
    """
    Main Runtime Application Self-Protection engine.
    """
    
    def __init__(self):
        self.memory_protector = MemoryProtector()
        self.syscall_monitor = SyscallMonitor()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.response_engine = ResponseEngine()
        
        self.events: List[SecurityEvent] = []
        self.is_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Set up default response rules."""
        # Critical threats - terminate
        self.response_engine.add_rule(
            ThreatType.CODE_INJECTION,
            SeverityLevel.HIGH,
            ResponseAction.TERMINATE
        )
        
        self.response_engine.add_rule(
            ThreatType.RANSOMWARE_BEHAVIOR,
            SeverityLevel.HIGH,
            ResponseAction.TERMINATE
        )
        
        # High threats - block
        self.response_engine.add_rule(
            ThreatType.PRIVILEGE_ESCALATION,
            SeverityLevel.HIGH,
            ResponseAction.BLOCK
        )
        
        # Medium threats - alert
        self.response_engine.add_rule(
            ThreatType.SUSPICIOUS_SYSCALL,
            SeverityLevel.MEDIUM,
            ResponseAction.ALERT
        )
    
    def start(self, monitor_self: bool = True):
        """Start RASP protection."""
        self.is_active = True
        
        # Establish baselines
        self.syscall_monitor.establish_baseline()
        
        if monitor_self:
            pid = os.getpid()
            self.behavior_analyzer.profile_process(pid)
        
        logger.info("RASP Engine started")
    
    def stop(self):
        """Stop RASP protection."""
        self.is_active = False
        logger.info("RASP Engine stopped")
    
    def protect_code_region(self, address: int, size: int):
        """Protect a code region from modification."""
        self.memory_protector.protect_region(address, size, "rx")
    
    def protect_data_region(self, address: int, size: int):
        """Protect a data region."""
        self.memory_protector.protect_region(address, size, "r")
    
    def record_syscall(self, syscall_name: str, 
                      args: Dict = None) -> Optional[SecurityEvent]:
        """
        Record and analyze a system call.
        
        Returns:
            SecurityEvent if threat detected
        """
        pid = os.getpid()
        tid = threading.get_ident()
        
        # Record syscall
        alert = self.syscall_monitor.record_syscall(
            syscall_name, args, pid, tid
        )
        
        # Record behavior
        anomaly_score = self.behavior_analyzer.record_event(
            pid, 'syscall', {'name': syscall_name, 'args': args}
        )
        
        # Generate event if threat detected
        if alert or anomaly_score > 0.7:
            event = self._create_event(
                ThreatType.SUSPICIOUS_SYSCALL,
                SeverityLevel.MEDIUM if alert else SeverityLevel.LOW,
                f"Suspicious syscall: {syscall_name}",
                pid, tid
            )
            
            if alert:
                event.additional_data['alert'] = alert
            event.additional_data['anomaly_score'] = anomaly_score
            
            self._handle_event(event)
            return event
        
        return None
    
    def check_memory_integrity(self) -> List[SecurityEvent]:
        """Check all protected memory regions."""
        events = []
        violations = self.memory_protector.check_all_regions()
        
        for violation in violations:
            event = self._create_event(
                ThreatType.MEMORY_CORRUPTION,
                SeverityLevel.CRITICAL,
                f"Memory integrity violation at {violation['address']}",
                os.getpid(),
                threading.get_ident()
            )
            event.additional_data['violation'] = violation
            
            self._handle_event(event)
            events.append(event)
        
        return events
    
    def check_ransomware(self, pid: int = None) -> Optional[SecurityEvent]:
        """Check for ransomware behavior."""
        pid = pid or os.getpid()
        
        is_detected, confidence = \
            self.behavior_analyzer.detect_ransomware_behavior(pid)
        
        if is_detected:
            event = self._create_event(
                ThreatType.RANSOMWARE_BEHAVIOR,
                SeverityLevel.CRITICAL,
                f"Ransomware behavior detected (confidence: {confidence:.0%})",
                pid,
                threading.get_ident()
            )
            event.additional_data['confidence'] = confidence
            
            self._handle_event(event)
            return event
        
        return None
    
    def _create_event(self, threat_type: ThreatType,
                     severity: SeverityLevel,
                     description: str,
                     pid: int,
                     tid: int) -> SecurityEvent:
        """Create security event."""
        event_id = hashlib.md5(
            f"{time.time()}{threat_type}{pid}".encode()
        ).hexdigest()[:16]
        
        return SecurityEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            threat_type=threat_type,
            severity=severity,
            description=description,
            process_id=pid,
            thread_id=tid,
            stack_trace=self._get_stack_trace()
        )
    
    def _get_stack_trace(self) -> str:
        """Get current stack trace."""
        return ''.join(traceback.format_stack()[:-2])
    
    def _handle_event(self, event: SecurityEvent):
        """Handle security event."""
        self.events.append(event)
        
        # Determine and execute response
        action = self.response_engine.determine_response(event)
        event.response_taken = action
        
        self.response_engine.execute_response(event, action)
        
        logger.info(
            f"RASP Event: {event.threat_type.name} "
            f"(severity={event.severity.name}, action={action.value})"
        )
    
    def get_statistics(self) -> Dict:
        """Get RASP statistics."""
        severity_counts = {}
        threat_counts = {}
        
        for event in self.events:
            sev = event.severity.name
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            threat = event.threat_type.name
            threat_counts[threat] = threat_counts.get(threat, 0) + 1
        
        return {
            'is_active': self.is_active,
            'total_events': len(self.events),
            'by_severity': severity_counts,
            'by_threat_type': threat_counts,
            'protected_regions': len(self.memory_protector.protected_regions),
            'monitored_processes': len(self.behavior_analyzer.process_profiles),
            'blocked_pids': list(self.response_engine.blocked_pids),
            'syscall_counts': dict(self.syscall_monitor.syscall_counts)
        }
    
    def export_events(self) -> List[Dict]:
        """Export all security events."""
        return [event.to_dict() for event in self.events]


# Testing
def main():
    """Test RASP engine."""
    print("Runtime Application Self-Protection Tests")
    print("=" * 50)
    
    rasp = RASPEngine()
    
    # Start protection
    print("\n1. Starting RASP Engine...")
    rasp.start(monitor_self=True)
    print(f"   Active: {rasp.is_active}")
    
    # Protect memory regions
    print("\n2. Protecting Memory Regions...")
    rasp.protect_code_region(0x400000, 4096)
    rasp.protect_data_region(0x600000, 2048)
    print(f"   Protected regions: {len(rasp.memory_protector.protected_regions)}")
    
    # Simulate syscalls
    print("\n3. Recording Syscalls...")
    
    test_syscalls = [
        ('open', {'path': '/etc/passwd'}),
        ('read', {'fd': 3, 'size': 1024}),
        ('mmap', {'addr': 0, 'len': 4096}),
        ('write', {'fd': 1, 'data': 'test'}),
        ('socket', {'family': 2, 'type': 1}),
        ('connect', {'addr': '192.168.1.1', 'port': 443}),
    ]
    
    for syscall, args in test_syscalls:
        event = rasp.record_syscall(syscall, args)
        if event:
            print(f"   ALERT: {syscall} -> {event.threat_type.name}")
        else:
            print(f"   OK: {syscall}")
    
    # Simulate suspicious sequence
    print("\n4. Simulating Suspicious Pattern...")
    suspicious = ['mmap', 'mprotect', 'write', 'ptrace']
    for syscall in suspicious:
        event = rasp.record_syscall(syscall, {})
        if event:
            print(f"   DETECTED: {event.description}")
    
    # Check memory integrity
    print("\n5. Checking Memory Integrity...")
    violations = rasp.check_memory_integrity()
    print(f"   Violations found: {len(violations)}")
    
    # Simulate file operations for ransomware detection
    print("\n6. Testing Ransomware Detection...")
    pid = os.getpid()
    
    # Simulate file operation pattern
    for i in range(50):
        rasp.behavior_analyzer.record_event(
            pid, 'file_op', 
            {'path': f'/data/file{i}.encrypted', 'operation': 'write'}
        )
    
    ransomware_event = rasp.check_ransomware(pid)
    if ransomware_event:
        print(f"   Ransomware detected! Confidence: "
              f"{ransomware_event.additional_data.get('confidence', 0):.0%}")
    else:
        print("   No ransomware behavior detected")
    
    # Get statistics
    print("\n7. RASP Statistics...")
    stats = rasp.get_statistics()
    print(f"   Total events: {stats['total_events']}")
    print(f"   By severity: {stats['by_severity']}")
    print(f"   By threat type: {stats['by_threat_type']}")
    print(f"   Syscall counts: {stats['syscall_counts']}")
    
    # Export events
    print("\n8. Exporting Events...")
    exported = rasp.export_events()
    print(f"   Exported {len(exported)} events")
    
    if exported:
        print(f"   Sample event: {exported[0]['threat_type']} - "
              f"{exported[0]['description'][:40]}...")
    
    # Stop
    rasp.stop()
    
    print("\n" + "=" * 50)
    print("All tests completed!")


if __name__ == "__main__":
    main()
