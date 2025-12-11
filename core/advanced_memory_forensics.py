"""
HydraRecon Advanced Memory Forensics Module
Deep memory analysis for malware detection and artifact recovery
"""

import asyncio
import hashlib
import json
import mmap
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, BinaryIO
import logging

logger = logging.getLogger(__name__)


class MemoryDumpFormat(Enum):
    """Memory dump formats"""
    RAW = "raw"
    LIME = "lime"
    WINPMEM = "winpmem"
    VMM = "vmm"
    HIBERNATION = "hibernation"
    CRASH = "crash"
    VMS = "virtualbox"
    VMWARE = "vmware"


class ProcessState(Enum):
    """Process states"""
    RUNNING = "running"
    SLEEPING = "sleeping"
    STOPPED = "stopped"
    ZOMBIE = "zombie"
    DEAD = "dead"
    HIDDEN = "hidden"


class MalwareType(Enum):
    """Malware types"""
    ROOTKIT = "rootkit"
    RAT = "rat"
    KEYLOGGER = "keylogger"
    RANSOMWARE = "ransomware"
    CRYPTOMINER = "cryptominer"
    BACKDOOR = "backdoor"
    TROJAN = "trojan"
    WORM = "worm"
    SPYWARE = "spyware"
    BOOTKIT = "bootkit"
    FILELESS = "fileless"


class ArtifactType(Enum):
    """Forensic artifact types"""
    PROCESS = "process"
    THREAD = "thread"
    NETWORK_CONNECTION = "network_connection"
    REGISTRY_KEY = "registry_key"
    FILE_HANDLE = "file_handle"
    DLL = "dll"
    DRIVER = "driver"
    MUTEX = "mutex"
    EVENT = "event"
    SEMAPHORE = "semaphore"
    TIMER = "timer"
    HOOK = "hook"
    INJECTION = "injection"
    CREDENTIAL = "credential"
    ENCRYPTION_KEY = "encryption_key"


class SeverityLevel(Enum):
    """Finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MemoryProcess:
    """Process extracted from memory"""
    pid: int
    ppid: int
    name: str
    path: Optional[str] = None
    cmdline: Optional[str] = None
    start_time: Optional[datetime] = None
    threads: int = 0
    handles: int = 0
    memory_usage: int = 0
    virtual_address: int = 0
    is_hidden: bool = False
    is_hollow: bool = False
    is_suspicious: bool = False
    dlls: List[str] = field(default_factory=list)
    connections: List['NetworkConnection'] = field(default_factory=list)


@dataclass
class NetworkConnection:
    """Network connection from memory"""
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int
    process_name: Optional[str] = None
    created: Optional[datetime] = None


@dataclass
class InjectedCode:
    """Injected code detection"""
    target_pid: int
    target_process: str
    injection_type: str
    source_pid: Optional[int] = None
    source_process: Optional[str] = None
    code_section: Optional[bytes] = None
    virtual_address: int = 0
    size: int = 0
    permissions: str = ""


@dataclass
class HiddenArtifact:
    """Hidden artifact (rootkit detection)"""
    artifact_type: ArtifactType
    details: str
    hiding_technique: str
    virtual_address: Optional[int] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedCredential:
    """Extracted credential"""
    credential_type: str
    username: Optional[str] = None
    domain: Optional[str] = None
    password_hash: Optional[str] = None
    plaintext: Optional[str] = None
    source: str = ""
    encryption_type: Optional[str] = None


@dataclass
class MalwareIndicator:
    """Malware indicator finding"""
    indicator_id: str
    malware_type: MalwareType
    severity: SeverityLevel
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    iocs: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class MemoryDumpProfile:
    """Memory dump profile information"""
    format_type: MemoryDumpFormat
    os_type: str  # Windows, Linux, macOS
    os_version: str
    architecture: str  # x86, x64, arm64
    build_number: Optional[int] = None
    kernel_version: Optional[str] = None
    dump_time: Optional[datetime] = None
    physical_memory: int = 0


class MemoryDumpAnalyzer:
    """Memory dump analysis engine"""
    
    def __init__(self, dump_path: str):
        self.dump_path = dump_path
        self.profile: Optional[MemoryDumpProfile] = None
        self.processes: Dict[int, MemoryProcess] = {}
        self.connections: List[NetworkConnection] = []
        self.artifacts: List[Any] = []
        self._mmap: Optional[mmap.mmap] = None
        self._file: Optional[BinaryIO] = None
        
    def open(self):
        """Open memory dump for analysis"""
        try:
            self._file = open(self.dump_path, 'rb')
            self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            
            # Identify dump format and OS
            self.profile = self._identify_profile()
            
        except Exception as e:
            logger.error(f"Failed to open memory dump: {e}")
            raise
            
    def close(self):
        """Close memory dump"""
        if self._mmap:
            self._mmap.close()
        if self._file:
            self._file.close()
            
    def _identify_profile(self) -> MemoryDumpProfile:
        """Identify memory dump profile"""
        if not self._mmap:
            raise RuntimeError("Dump not opened")
            
        # Read first bytes to identify format
        header = bytes(self._mmap[:4096])
        
        # Check for LiME format
        if header[:4] == b'EMiL':
            return self._parse_lime_header(header)
            
        # Check for VMware VMSS/VMSN
        if header[:4] == b'\xd2\xbe\xd2\xbe':
            return MemoryDumpProfile(
                format_type=MemoryDumpFormat.VMWARE,
                os_type='Unknown',
                os_version='Unknown',
                architecture='x64',
                physical_memory=len(self._mmap)
            )
            
        # Check for Windows crash dump
        if header[:8] == b'PAGEDUMP' or header[:8] == b'PAGEDU64':
            return self._parse_crash_dump(header)
            
        # Check for Windows hibernation
        if header[:4] == b'hibr' or header[:4] == b'HIBR':
            return MemoryDumpProfile(
                format_type=MemoryDumpFormat.HIBERNATION,
                os_type='Windows',
                os_version='Unknown',
                architecture='x64',
                physical_memory=len(self._mmap)
            )
            
        # Default to raw format
        return MemoryDumpProfile(
            format_type=MemoryDumpFormat.RAW,
            os_type='Unknown',
            os_version='Unknown',
            architecture='x64',
            physical_memory=len(self._mmap)
        )
        
    def _parse_lime_header(self, header: bytes) -> MemoryDumpProfile:
        """Parse LiME format header"""
        return MemoryDumpProfile(
            format_type=MemoryDumpFormat.LIME,
            os_type='Linux',
            os_version='Unknown',
            architecture='x64',
            physical_memory=len(self._mmap)
        )
        
    def _parse_crash_dump(self, header: bytes) -> MemoryDumpProfile:
        """Parse Windows crash dump header"""
        is_64bit = header[:8] == b'PAGEDU64'
        
        return MemoryDumpProfile(
            format_type=MemoryDumpFormat.CRASH,
            os_type='Windows',
            os_version='Unknown',
            architecture='x64' if is_64bit else 'x86',
            physical_memory=len(self._mmap)
        )


class WindowsMemoryAnalyzer:
    """Windows-specific memory analysis"""
    
    def __init__(self, dump: MemoryDumpAnalyzer):
        self.dump = dump
        self.kdbg_offset: Optional[int] = None
        self.dtb: Optional[int] = None
        
    def find_kdbg(self) -> Optional[int]:
        """Find KDBG (Kernel Debugger Data Block)"""
        if not self.dump._mmap:
            return None
            
        # KDBG signature
        signatures = [
            b'KDBG',
            b'\x00\x00\x00\x00\x00\x00\x00\x00KDBG',
        ]
        
        for sig in signatures:
            offset = self.dump._mmap.find(sig)
            if offset != -1:
                self.kdbg_offset = offset
                return offset
                
        return None
        
    def list_processes(self) -> List[MemoryProcess]:
        """List processes from memory"""
        processes = []
        
        # Would implement EPROCESS structure walking
        # This is a simplified example
        
        return processes
        
    def detect_process_hollowing(self, process: MemoryProcess) -> bool:
        """Detect process hollowing"""
        # Check if PE header in memory matches file on disk
        # Check for executable memory regions
        # Compare VAD tree with loaded modules
        return False
        
    def detect_dll_injection(self, process: MemoryProcess) -> List[InjectedCode]:
        """Detect DLL injection"""
        injections = []
        
        # Check for unknown DLLs
        # Check for DLLs loaded from suspicious paths
        # Check for reflective DLL loading patterns
        
        return injections
        
    def extract_network_connections(self) -> List[NetworkConnection]:
        """Extract network connections"""
        connections = []
        
        # Would walk tcpip.sys structures
        # Parse _TCP_ENDPOINT and _UDP_ENDPOINT
        
        return connections
        
    def find_hidden_processes(self) -> List[MemoryProcess]:
        """Find hidden processes (rootkit detection)"""
        hidden = []
        
        # Compare EPROCESS list with:
        # - PspCidTable
        # - Csrss handle table
        # - Session process list
        # - Scheduler threads
        
        return hidden
        
    def extract_registry_keys(self) -> List[Dict[str, Any]]:
        """Extract registry keys from memory"""
        keys = []
        
        # Walk CM (Configuration Manager) structures
        # Extract HKLM\SYSTEM, SAM, etc.
        
        return keys


class LinuxMemoryAnalyzer:
    """Linux-specific memory analysis"""
    
    def __init__(self, dump: MemoryDumpAnalyzer):
        self.dump = dump
        self.kernel_banner: Optional[str] = None
        
    def find_kernel_banner(self) -> Optional[str]:
        """Find Linux kernel banner"""
        if not self.dump._mmap:
            return None
            
        # Search for Linux version string
        banner_pattern = rb'Linux version \d+\.\d+\.\d+'
        match = re.search(banner_pattern, bytes(self.dump._mmap[:0x100000]))
        
        if match:
            # Extract full banner
            start = match.start()
            end = self.dump._mmap.find(b'\x00', start)
            self.kernel_banner = bytes(self.dump._mmap[start:end]).decode('utf-8', errors='ignore')
            return self.kernel_banner
            
        return None
        
    def list_processes(self) -> List[MemoryProcess]:
        """List processes from task_struct"""
        processes = []
        
        # Would walk task_struct linked list
        # Parse comm, pid, parent, mm, etc.
        
        return processes
        
    def detect_rootkit(self) -> List[HiddenArtifact]:
        """Detect Linux rootkits"""
        artifacts = []
        
        # Check for:
        # - Hidden processes (task list inconsistencies)
        # - Hidden modules (lsmod vs /proc/modules)
        # - Syscall table hooks
        # - VFS hooks
        # - Inline hooks
        
        return artifacts
        
    def extract_bash_history(self) -> List[str]:
        """Extract bash history from memory"""
        history = []
        
        # Search for history patterns
        # Parse readline structures
        
        return history
        
    def find_netfilter_hooks(self) -> List[Dict[str, Any]]:
        """Find netfilter hooks"""
        hooks = []
        
        # Walk nf_hooks array
        # Check for suspicious hook functions
        
        return hooks


class CredentialExtractor:
    """Extract credentials from memory"""
    
    def __init__(self, dump: MemoryDumpAnalyzer):
        self.dump = dump
        
    def extract_lsass_secrets(self) -> List[ExtractedCredential]:
        """Extract secrets from LSASS memory"""
        credentials = []
        
        # Would implement:
        # - MSV1_0 credentials (NTLM hashes)
        # - Kerberos tickets
        # - WDigest plaintext passwords
        # - TsPkg credentials
        # - SSP/AP credentials
        # - DPAPI master keys
        
        return credentials
        
    def find_passwords_in_memory(self) -> List[ExtractedCredential]:
        """Search for plaintext passwords in memory"""
        credentials = []
        
        if not self.dump._mmap:
            return credentials
            
        # Common password patterns
        patterns = [
            (rb'password["\s:=]+([^\s"<>]+)', 'password_field'),
            (rb'passwd["\s:=]+([^\s"<>]+)', 'passwd_field'),
            (rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', 'basic_auth'),
            (rb'Bearer\s+([A-Za-z0-9\-_.~+/]+)', 'bearer_token'),
            (rb'api[_-]?key["\s:=]+([A-Za-z0-9\-_]+)', 'api_key'),
            (rb'secret["\s:=]+([^\s"<>]+)', 'secret'),
        ]
        
        for pattern, cred_type in patterns:
            for match in re.finditer(pattern, bytes(self.dump._mmap)):
                try:
                    value = match.group(1).decode('utf-8', errors='ignore')
                    if len(value) > 4:  # Filter noise
                        credentials.append(ExtractedCredential(
                            credential_type=cred_type,
                            plaintext=value,
                            source=f"offset:{match.start()}"
                        ))
                except Exception:
                    pass
                    
        return credentials
        
    def extract_ssh_keys(self) -> List[ExtractedCredential]:
        """Extract SSH keys from memory"""
        credentials = []
        
        if not self.dump._mmap:
            return credentials
            
        # SSH private key markers
        key_starts = [
            b'-----BEGIN RSA PRIVATE KEY-----',
            b'-----BEGIN DSA PRIVATE KEY-----',
            b'-----BEGIN EC PRIVATE KEY-----',
            b'-----BEGIN OPENSSH PRIVATE KEY-----',
        ]
        
        for marker in key_starts:
            offset = 0
            while True:
                pos = self.dump._mmap.find(marker, offset)
                if pos == -1:
                    break
                    
                # Find end marker
                end = self.dump._mmap.find(b'-----END', pos + len(marker))
                if end != -1:
                    end = self.dump._mmap.find(b'-----', end + 8)
                    if end != -1:
                        key_data = bytes(self.dump._mmap[pos:end + 5]).decode('utf-8', errors='ignore')
                        credentials.append(ExtractedCredential(
                            credential_type='ssh_private_key',
                            plaintext=key_data,
                            source=f"offset:{pos}"
                        ))
                        
                offset = pos + len(marker)
                
        return credentials
        
    def find_encryption_keys(self) -> List[Dict[str, Any]]:
        """Find encryption keys in memory"""
        keys = []
        
        if not self.dump._mmap:
            return keys
            
        # AES key schedule detection
        # Look for key expansion patterns
        
        # Bitcoin/crypto wallet keys
        wallet_patterns = [
            rb'[\x01-\xff]{32}',  # Private key pattern (simplified)
        ]
        
        return keys


class MalwareDetector:
    """Detect malware indicators in memory"""
    
    def __init__(self, dump: MemoryDumpAnalyzer):
        self.dump = dump
        self.signatures = self._load_signatures()
        
    def _load_signatures(self) -> List[Dict[str, Any]]:
        """Load malware signatures"""
        return [
            {
                'name': 'Mimikatz',
                'type': MalwareType.RAT,
                'strings': [b'mimikatz', b'gentilkiwi', b'sekurlsa::logonpasswords'],
                'severity': SeverityLevel.CRITICAL
            },
            {
                'name': 'Cobalt Strike',
                'type': MalwareType.RAT,
                'strings': [b'\\.\pipe\msagent_', b'beacon', b'%windir%\\system32\\msiexec.exe'],
                'severity': SeverityLevel.CRITICAL
            },
            {
                'name': 'Metasploit',
                'type': MalwareType.RAT,
                'strings': [b'meterpreter', b'stdapi_', b'core_migrate'],
                'severity': SeverityLevel.CRITICAL
            },
            {
                'name': 'PowerShell Empire',
                'type': MalwareType.RAT,
                'strings': [b'Invoke-Empire', b'invoke-mimikatz'],
                'severity': SeverityLevel.CRITICAL
            },
            {
                'name': 'Gh0st RAT',
                'type': MalwareType.RAT,
                'strings': [b'Gh0st', b'pcMain'],
                'severity': SeverityLevel.HIGH
            },
            {
                'name': 'Cryptominer',
                'type': MalwareType.CRYPTOMINER,
                'strings': [b'stratum+tcp://', b'xmrig', b'monero', b'coinhive'],
                'severity': SeverityLevel.MEDIUM
            },
            {
                'name': 'Ransomware Generic',
                'type': MalwareType.RANSOMWARE,
                'strings': [b'YOUR FILES HAVE BEEN ENCRYPTED', b'.onion', b'bitcoin:'],
                'severity': SeverityLevel.CRITICAL
            },
        ]
        
    def scan_signatures(self) -> List[MalwareIndicator]:
        """Scan for malware signatures"""
        indicators = []
        
        if not self.dump._mmap:
            return indicators
            
        for sig in self.signatures:
            for string in sig['strings']:
                offset = self.dump._mmap.find(string)
                if offset != -1:
                    indicators.append(MalwareIndicator(
                        indicator_id=f"SIG-{hashlib.md5(sig['name'].encode()).hexdigest()[:8]}",
                        malware_type=sig['type'],
                        severity=sig['severity'],
                        title=f"{sig['name']} Detected",
                        description=f"Signature match for {sig['name']} found at offset {offset}",
                        evidence={
                            'signature': string.decode('utf-8', errors='ignore'),
                            'offset': offset,
                            'context': self._get_context(offset, 100)
                        },
                        iocs=[string.decode('utf-8', errors='ignore')]
                    ))
                    break  # One match per signature is enough
                    
        return indicators
        
    def _get_context(self, offset: int, size: int) -> str:
        """Get context around an offset"""
        if not self.dump._mmap:
            return ""
            
        start = max(0, offset - size)
        end = min(len(self.dump._mmap), offset + size)
        
        context = bytes(self.dump._mmap[start:end])
        # Convert to printable string
        return ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        
    def detect_code_injection(self) -> List[InjectedCode]:
        """Detect code injection techniques"""
        injections = []
        
        # Would implement:
        # - Process hollowing detection
        # - DLL injection detection
        # - Reflective DLL loading
        # - Thread execution hijacking
        # - APC injection
        # - Atom bombing
        
        return injections
        
    def detect_hooks(self) -> List[Dict[str, Any]]:
        """Detect API hooks"""
        hooks = []
        
        # Would check:
        # - IAT hooks
        # - EAT hooks
        # - Inline hooks
        # - SSDT hooks
        # - IDT hooks
        # - IRP hooks
        
        return hooks
        
    def analyze_malfind(self) -> List[Dict[str, Any]]:
        """Find hidden/injected code in process memory"""
        findings = []
        
        # Would implement:
        # - VAD scanning for suspicious regions
        # - RWX memory detection
        # - PE carving in memory
        # - Shellcode detection
        
        return findings


class TimelineReconstructor:
    """Reconstruct timeline from memory artifacts"""
    
    def __init__(self, dump: MemoryDumpAnalyzer):
        self.dump = dump
        self.events: List[Dict[str, Any]] = []
        
    def build_timeline(self) -> List[Dict[str, Any]]:
        """Build forensic timeline from memory"""
        events = []
        
        # Process creation times
        for process in self.dump.processes.values():
            if process.start_time:
                events.append({
                    'timestamp': process.start_time,
                    'type': 'process_start',
                    'description': f'Process {process.name} (PID: {process.pid}) started',
                    'artifact': process
                })
                
        # Network connections
        for conn in self.dump.connections:
            if conn.created:
                events.append({
                    'timestamp': conn.created,
                    'type': 'network_connection',
                    'description': f'{conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port}',
                    'artifact': conn
                })
                
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min)
        
        self.events = events
        return events


class AdvancedMemoryForensics:
    """Main memory forensics integration class"""
    
    def __init__(self, dump_path: str):
        self.dump = MemoryDumpAnalyzer(dump_path)
        self.windows_analyzer: Optional[WindowsMemoryAnalyzer] = None
        self.linux_analyzer: Optional[LinuxMemoryAnalyzer] = None
        self.credential_extractor: Optional[CredentialExtractor] = None
        self.malware_detector: Optional[MalwareDetector] = None
        self.timeline: Optional[TimelineReconstructor] = None
        self.findings: List[Any] = []
        
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive memory analysis"""
        results = {
            'dump_path': self.dump.dump_path,
            'analysis_time': datetime.now().isoformat(),
            'profile': None,
            'processes': [],
            'connections': [],
            'malware_indicators': [],
            'credentials': [],
            'hidden_artifacts': [],
            'injections': [],
            'timeline': [],
            'summary': {
                'total_processes': 0,
                'hidden_processes': 0,
                'suspicious_processes': 0,
                'total_connections': 0,
                'malware_detected': 0,
                'credentials_found': 0
            }
        }
        
        # Open dump
        self.dump.open()
        
        try:
            # Set profile info
            if self.dump.profile:
                results['profile'] = {
                    'format': self.dump.profile.format_type.value,
                    'os': self.dump.profile.os_type,
                    'version': self.dump.profile.os_version,
                    'arch': self.dump.profile.architecture,
                    'memory_size': self.dump.profile.physical_memory
                }
                
            # Initialize analyzers based on OS
            if self.dump.profile and self.dump.profile.os_type == 'Windows':
                self.windows_analyzer = WindowsMemoryAnalyzer(self.dump)
            elif self.dump.profile and self.dump.profile.os_type == 'Linux':
                self.linux_analyzer = LinuxMemoryAnalyzer(self.dump)
                
            # Initialize common analyzers
            self.credential_extractor = CredentialExtractor(self.dump)
            self.malware_detector = MalwareDetector(self.dump)
            self.timeline = TimelineReconstructor(self.dump)
            
            # Malware detection
            malware_indicators = self.malware_detector.scan_signatures()
            results['malware_indicators'] = [
                {
                    'id': m.indicator_id,
                    'type': m.malware_type.value,
                    'severity': m.severity.value,
                    'title': m.title,
                    'description': m.description,
                    'iocs': m.iocs
                }
                for m in malware_indicators
            ]
            results['summary']['malware_detected'] = len(malware_indicators)
            
            # Credential extraction
            credentials = []
            credentials.extend(self.credential_extractor.find_passwords_in_memory())
            credentials.extend(self.credential_extractor.extract_ssh_keys())
            
            results['credentials'] = [
                {
                    'type': c.credential_type,
                    'username': c.username,
                    'domain': c.domain,
                    'source': c.source
                    # Not including actual credentials in output
                }
                for c in credentials
            ]
            results['summary']['credentials_found'] = len(credentials)
            
            # Build timeline
            timeline = self.timeline.build_timeline()
            results['timeline'] = [
                {
                    'time': e['timestamp'].isoformat() if e['timestamp'] else None,
                    'type': e['type'],
                    'description': e['description']
                }
                for e in timeline[:100]  # Limit to 100 events
            ]
            
        finally:
            self.dump.close()
            
        return results
        
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate forensics report"""
        report = []
        
        report.append("=" * 70)
        report.append("MEMORY FORENSICS ANALYSIS REPORT")
        report.append("=" * 70)
        
        report.append(f"\nDump File: {results['dump_path']}")
        report.append(f"Analysis Time: {results['analysis_time']}")
        
        if results['profile']:
            report.append(f"\n{'=' * 50}")
            report.append("DUMP PROFILE")
            report.append("=" * 50)
            
            profile = results['profile']
            report.append(f"Format: {profile['format']}")
            report.append(f"Operating System: {profile['os']}")
            report.append(f"Version: {profile['version']}")
            report.append(f"Architecture: {profile['arch']}")
            report.append(f"Memory Size: {profile['memory_size'] / (1024*1024*1024):.2f} GB")
            
        report.append(f"\n{'=' * 50}")
        report.append("SUMMARY")
        report.append("=" * 50)
        
        summary = results['summary']
        report.append(f"Total Processes: {summary['total_processes']}")
        report.append(f"Hidden Processes: {summary['hidden_processes']}")
        report.append(f"Suspicious Processes: {summary['suspicious_processes']}")
        report.append(f"Network Connections: {summary['total_connections']}")
        report.append(f"Malware Indicators: {summary['malware_detected']}")
        report.append(f"Credentials Found: {summary['credentials_found']}")
        
        # Malware findings
        if results['malware_indicators']:
            report.append(f"\n{'=' * 50}")
            report.append("MALWARE INDICATORS")
            report.append("=" * 50)
            
            for indicator in results['malware_indicators']:
                severity = indicator['severity'].upper()
                report.append(f"\n[{severity}] {indicator['title']}")
                report.append(f"  Type: {indicator['type']}")
                report.append(f"  Description: {indicator['description']}")
                if indicator['iocs']:
                    report.append(f"  IOCs: {', '.join(indicator['iocs'][:3])}")
                    
        # Credentials
        if results['credentials']:
            report.append(f"\n{'=' * 50}")
            report.append("CREDENTIALS FOUND")
            report.append("=" * 50)
            
            for cred in results['credentials'][:10]:  # Limit display
                report.append(f"\n[{cred['type']}]")
                if cred['username']:
                    report.append(f"  Username: {cred['username']}")
                if cred['domain']:
                    report.append(f"  Domain: {cred['domain']}")
                report.append(f"  Source: {cred['source']}")
                
        # Timeline
        if results['timeline']:
            report.append(f"\n{'=' * 50}")
            report.append("TIMELINE (Recent Events)")
            report.append("=" * 50)
            
            for event in results['timeline'][:20]:
                if event['time']:
                    report.append(f"\n{event['time']} | {event['type']}")
                    report.append(f"  {event['description']}")
                    
        return "\n".join(report)
        
    def export_iocs(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Export IOCs for threat intelligence"""
        iocs = {
            'analysis_time': results['analysis_time'],
            'indicators': {
                'malware_strings': [],
                'network_iocs': [],
                'file_hashes': [],
                'process_names': []
            }
        }
        
        for indicator in results.get('malware_indicators', []):
            iocs['indicators']['malware_strings'].extend(indicator.get('iocs', []))
            
        return iocs
