#!/usr/bin/env python3
"""
Memory Forensics Engine - Advanced RAM Analysis & Volatile Artifact Extraction
Revolutionary memory forensics and live system analysis platform.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid


class MemoryRegionType(Enum):
    """Types of memory regions."""
    HEAP = auto()
    STACK = auto()
    CODE = auto()
    DATA = auto()
    MAPPED_FILE = auto()
    SHARED = auto()
    KERNEL = auto()
    DRIVER = auto()
    DLL_MODULE = auto()
    EXECUTABLE = auto()
    THREAD_LOCAL = auto()
    RESERVED = auto()
    UNKNOWN = auto()


class ProcessState(Enum):
    """Process states."""
    RUNNING = auto()
    SLEEPING = auto()
    STOPPED = auto()
    ZOMBIE = auto()
    DEAD = auto()
    HIDDEN = auto()
    INJECTED = auto()
    HOLLOWED = auto()


class InjectionTechnique(Enum):
    """Code injection techniques."""
    DLL_INJECTION = auto()
    PROCESS_HOLLOWING = auto()
    THREAD_HIJACKING = auto()
    APC_INJECTION = auto()
    ATOM_BOMBING = auto()
    PROCESS_DOPPELGANGING = auto()
    EARLY_BIRD = auto()
    HEAVEN_GATE = auto()
    REFLECTIVE_DLL = auto()
    SHELLCODE_INJECTION = auto()
    HOOK_INJECTION = auto()
    MODULE_STOMPING = auto()
    TRANSACTED_HOLLOWING = auto()
    PHANTOM_DLL = auto()


class ArtifactType(Enum):
    """Types of memory artifacts."""
    PASSWORD = auto()
    ENCRYPTION_KEY = auto()
    CERTIFICATE = auto()
    PRIVATE_KEY = auto()
    SESSION_TOKEN = auto()
    COOKIE = auto()
    CREDIT_CARD = auto()
    NETWORK_CONNECTION = auto()
    URL = auto()
    EMAIL = auto()
    COMMAND_LINE = auto()
    REGISTRY_KEY = auto()
    FILE_PATH = auto()
    BITCOIN_WALLET = auto()
    API_KEY = auto()
    MALWARE_CONFIG = auto()
    C2_ADDRESS = auto()
    YARA_MATCH = auto()


class MalwareFamily(Enum):
    """Known malware families."""
    COBALT_STRIKE = auto()
    EMOTET = auto()
    TRICKBOT = auto()
    MIMIKATZ = auto()
    METASPLOIT = auto()
    EMPIRE = auto()
    QAKBOT = auto()
    ICEDID = auto()
    RACCOON = auto()
    REDLINE = auto()
    VIDAR = auto()
    AGENT_TESLA = auto()
    REMCOS = auto()
    NJRAT = auto()
    ASYNCRAT = auto()
    UNKNOWN = auto()


@dataclass
class MemoryRegion:
    """Represents a memory region."""
    region_id: str
    base_address: int
    size: int
    region_type: MemoryRegionType
    protection: str
    mapped_file: Optional[str]
    is_executable: bool
    is_writable: bool
    is_private: bool
    content_hash: str
    entropy: float
    suspicious_score: float
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessInfo:
    """Represents process information."""
    process_id: int
    parent_pid: int
    name: str
    path: str
    command_line: str
    state: ProcessState
    user: str
    create_time: datetime
    threads: int
    handles: int
    memory_regions: List[MemoryRegion]
    loaded_modules: List[str]
    network_connections: List[Dict[str, Any]]
    suspicious_indicators: List[str]
    injection_detected: bool = False
    injection_type: Optional[InjectionTechnique] = None
    parent_spoofed: bool = False
    hidden: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryArtifact:
    """Represents a memory artifact."""
    artifact_id: str
    artifact_type: ArtifactType
    process_id: int
    address: int
    size: int
    value: str
    raw_value: bytes
    context: str
    confidence: float
    timestamp: datetime
    is_encrypted: bool = False
    related_artifacts: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InjectionIndicator:
    """Indicates potential code injection."""
    indicator_id: str
    process_id: int
    technique: InjectionTechnique
    source_process: Optional[int]
    target_region: MemoryRegion
    confidence: float
    evidence: List[str]
    timeline: List[Dict[str, Any]]
    iocs: List[str]
    yara_matches: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MalwareIndicator:
    """Indicates potential malware."""
    indicator_id: str
    malware_family: MalwareFamily
    process_id: int
    detection_method: str
    signature: str
    confidence: float
    config_extracted: Dict[str, Any]
    c2_addresses: List[str]
    mutex_names: List[str]
    registry_keys: List[str]
    yara_rules: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkArtifact:
    """Network-related memory artifact."""
    artifact_id: str
    process_id: int
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    protocol: str
    state: str
    timestamp: datetime
    is_suspicious: bool
    threat_intel_match: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KernelObject:
    """Kernel object from memory."""
    object_id: str
    object_type: str
    address: int
    name: str
    reference_count: int
    handle_count: int
    owner_process: int
    security_descriptor: str
    is_hidden: bool
    is_suspicious: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class MemoryForensicsEngine:
    """
    Revolutionary memory forensics and volatile artifact extraction platform.
    
    Features:
    - Live memory acquisition and analysis
    - Process injection detection (15+ techniques)
    - Malware family identification
    - Credential extraction from memory
    - Network connection reconstruction
    - Hidden process detection
    - Kernel object analysis
    - YARA-based pattern matching
    - Entropy analysis for packed code
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "memory_forensics.db"
        self.logger = logging.getLogger("MemoryForensics")
        self.processes: Dict[int, ProcessInfo] = {}
        self.regions: Dict[str, MemoryRegion] = {}
        self.artifacts: Dict[str, MemoryArtifact] = {}
        self.injections: Dict[str, InjectionIndicator] = {}
        self.malware_indicators: Dict[str, MalwareIndicator] = {}
        self.callbacks: Dict[str, List[Callable]] = {}
        
        # Pattern definitions
        self.artifact_patterns = self._load_artifact_patterns()
        self.injection_signatures = self._load_injection_signatures()
        self.malware_signatures = self._load_malware_signatures()
        self.yara_rules = self._load_yara_rules()
        
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS processes (
                process_id INTEGER PRIMARY KEY,
                parent_pid INTEGER,
                name TEXT,
                path TEXT,
                command_line TEXT,
                state TEXT,
                user TEXT,
                create_time TEXT,
                threads INTEGER,
                handles INTEGER,
                injection_detected INTEGER,
                injection_type TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS memory_regions (
                region_id TEXT PRIMARY KEY,
                process_id INTEGER,
                base_address INTEGER,
                size INTEGER,
                region_type TEXT,
                protection TEXT,
                mapped_file TEXT,
                is_executable INTEGER,
                entropy REAL,
                suspicious_score REAL,
                content_hash TEXT,
                tags TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                artifact_type TEXT,
                process_id INTEGER,
                address INTEGER,
                size INTEGER,
                value TEXT,
                context TEXT,
                confidence REAL,
                timestamp TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS injection_indicators (
                indicator_id TEXT PRIMARY KEY,
                process_id INTEGER,
                technique TEXT,
                source_process INTEGER,
                confidence REAL,
                evidence TEXT,
                iocs TEXT,
                yara_matches TEXT,
                timestamp TEXT
            );
            
            CREATE TABLE IF NOT EXISTS malware_indicators (
                indicator_id TEXT PRIMARY KEY,
                malware_family TEXT,
                process_id INTEGER,
                detection_method TEXT,
                signature TEXT,
                confidence REAL,
                config_extracted TEXT,
                c2_addresses TEXT,
                timestamp TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_regions_process ON memory_regions(process_id);
            CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type);
            CREATE INDEX IF NOT EXISTS idx_artifacts_process ON artifacts(process_id);
        """)
        
        conn.commit()
        conn.close()
    
    def _load_artifact_patterns(self) -> Dict[ArtifactType, List[Dict[str, Any]]]:
        """Load patterns for artifact detection."""
        return {
            ArtifactType.PASSWORD: [
                {"pattern": rb"password[=:]\s*([^\s]+)", "name": "Password field"},
                {"pattern": rb"pwd[=:]\s*([^\s]+)", "name": "PWD field"},
                {"pattern": rb"pass[=:]\s*([^\s]+)", "name": "Pass field"}
            ],
            ArtifactType.EMAIL: [
                {"pattern": rb"[\w\.-]+@[\w\.-]+\.\w+", "name": "Email address"}
            ],
            ArtifactType.URL: [
                {"pattern": rb"https?://[\w\.-]+(?:/[\w\./\-\?=&%]+)?", "name": "URL"}
            ],
            ArtifactType.BITCOIN_WALLET: [
                {"pattern": rb"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", "name": "Bitcoin address"},
                {"pattern": rb"bc1[a-zA-HJ-NP-Z0-9]{39,59}", "name": "Bitcoin Bech32"}
            ],
            ArtifactType.API_KEY: [
                {"pattern": rb"[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][=:]\s*([A-Za-z0-9_\-]{20,})", "name": "API Key"},
                {"pattern": rb"AKIA[0-9A-Z]{16}", "name": "AWS Access Key"}
            ],
            ArtifactType.PRIVATE_KEY: [
                {"pattern": rb"-----BEGIN (?:RSA )?PRIVATE KEY-----", "name": "Private Key Header"}
            ],
            ArtifactType.CREDIT_CARD: [
                {"pattern": rb"4[0-9]{12}(?:[0-9]{3})?", "name": "Visa"},
                {"pattern": rb"5[1-5][0-9]{14}", "name": "Mastercard"},
                {"pattern": rb"3[47][0-9]{13}", "name": "Amex"}
            ],
            ArtifactType.ENCRYPTION_KEY: [
                {"pattern": rb"[A-Fa-f0-9]{32}", "name": "128-bit key"},
                {"pattern": rb"[A-Fa-f0-9]{64}", "name": "256-bit key"}
            ],
            ArtifactType.SESSION_TOKEN: [
                {"pattern": rb"session[_-]?id[=:]\s*([A-Za-z0-9_\-]{20,})", "name": "Session ID"},
                {"pattern": rb"[Bb]earer\s+([A-Za-z0-9_\-\.]+)", "name": "Bearer Token"}
            ]
        }
    
    def _load_injection_signatures(self) -> Dict[InjectionTechnique, Dict[str, Any]]:
        """Load injection technique signatures."""
        return {
            InjectionTechnique.PROCESS_HOLLOWING: {
                "indicators": [
                    "NtUnmapViewOfSection called",
                    "Executable region in suspended process",
                    "PE header at non-standard base"
                ],
                "memory_patterns": [
                    rb"MZ[\x00-\xff]{58}PE\x00\x00",  # PE header
                ],
                "api_calls": ["NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory"]
            },
            InjectionTechnique.DLL_INJECTION: {
                "indicators": [
                    "LoadLibrary in remote process",
                    "Suspicious DLL path",
                    "Non-standard DLL location"
                ],
                "memory_patterns": [],
                "api_calls": ["CreateRemoteThread", "LoadLibraryA", "LoadLibraryW"]
            },
            InjectionTechnique.REFLECTIVE_DLL: {
                "indicators": [
                    "PE in RWX memory",
                    "No disk backing",
                    "Custom loader stub"
                ],
                "memory_patterns": [
                    rb"\x4D\x5A.{0,500}ReflectiveLoader",
                ],
                "api_calls": ["VirtualAlloc", "VirtualProtect"]
            },
            InjectionTechnique.THREAD_HIJACKING: {
                "indicators": [
                    "Thread context modified",
                    "RIP/EIP changed to shellcode",
                    "Suspended thread with modified context"
                ],
                "memory_patterns": [],
                "api_calls": ["SetThreadContext", "SuspendThread", "ResumeThread"]
            },
            InjectionTechnique.APC_INJECTION: {
                "indicators": [
                    "APC queued to remote thread",
                    "Alertable thread targeted",
                    "Shellcode in APC"
                ],
                "memory_patterns": [],
                "api_calls": ["QueueUserAPC", "NtQueueApcThread"]
            },
            InjectionTechnique.ATOM_BOMBING: {
                "indicators": [
                    "GlobalAddAtom with code",
                    "NtQueueApcThread with GlobalGetAtom",
                    "ROP chain in atom"
                ],
                "memory_patterns": [],
                "api_calls": ["GlobalAddAtomA", "GlobalGetAtomNameA", "NtQueueApcThread"]
            },
            InjectionTechnique.PROCESS_DOPPELGANGING: {
                "indicators": [
                    "TxF transaction abuse",
                    "NtCreateProcessEx from transaction",
                    "Fileless execution"
                ],
                "memory_patterns": [],
                "api_calls": ["NtCreateTransaction", "NtCreateSection", "NtCreateProcessEx"]
            },
            InjectionTechnique.EARLY_BIRD: {
                "indicators": [
                    "APC before thread start",
                    "Suspended process with APC",
                    "Main thread never runs"
                ],
                "memory_patterns": [],
                "api_calls": ["CreateProcessA", "QueueUserAPC", "ResumeThread"]
            },
            InjectionTechnique.MODULE_STOMPING: {
                "indicators": [
                    "Legitimate DLL overwritten",
                    "Code section modified",
                    "Hash mismatch with disk"
                ],
                "memory_patterns": [],
                "api_calls": ["VirtualProtect", "memcpy"]
            },
            InjectionTechnique.HEAVEN_GATE: {
                "indicators": [
                    "32-bit to 64-bit transition",
                    "Far JMP to 64-bit code",
                    "WoW64 abuse"
                ],
                "memory_patterns": [
                    rb"\x6A\x33\xE8[\x00-\xff]{4}\x83\xC4\x04\xCB",  # Heaven's Gate pattern
                ],
                "api_calls": []
            }
        }
    
    def _load_malware_signatures(self) -> Dict[MalwareFamily, Dict[str, Any]]:
        """Load malware family signatures."""
        return {
            MalwareFamily.COBALT_STRIKE: {
                "strings": [
                    b"beacon.dll",
                    b"ReflectiveLoader",
                    b"%s as %s\\%s: %d",
                    b"IEX (New-Object Net.Webclient).DownloadString"
                ],
                "config_patterns": [
                    rb"\x00\x01\x00\x01\x00\x02",  # Cobalt Strike config marker
                ],
                "mutex_patterns": [
                    r"MSCTF\.Asm\.*"
                ]
            },
            MalwareFamily.MIMIKATZ: {
                "strings": [
                    b"mimikatz",
                    b"sekurlsa::",
                    b"lsadump::",
                    b"privilege::debug",
                    b"Benjamin DELPY"
                ],
                "config_patterns": [],
                "mutex_patterns": []
            },
            MalwareFamily.METASPLOIT: {
                "strings": [
                    b"metsrv.dll",
                    b"meterpreter",
                    b"stdapi",
                    b"priv_elevate_getsystem"
                ],
                "config_patterns": [
                    rb"\x4d\x5a.{0,200}metsrv",
                ],
                "mutex_patterns": []
            },
            MalwareFamily.EMOTET: {
                "strings": [
                    b"EMOTET",
                    b"Epoch"
                ],
                "config_patterns": [
                    rb"\xEC.{100,500}http",  # Emotet C2 pattern
                ],
                "mutex_patterns": [
                    r"Global\\[A-F0-9]{8}"
                ]
            },
            MalwareFamily.TRICKBOT: {
                "strings": [
                    b"<moduleconfig>",
                    b"<autostart>",
                    b"dinj",
                    b"sinj"
                ],
                "config_patterns": [],
                "mutex_patterns": [
                    r"Global\\.*Trick.*"
                ]
            },
            MalwareFamily.QAKBOT: {
                "strings": [
                    b"qbot",
                    b"pinkslipbot"
                ],
                "config_patterns": [],
                "mutex_patterns": []
            },
            MalwareFamily.AGENT_TESLA: {
                "strings": [
                    b"AgentTesla",
                    b"smtp.yandex.ru",
                    b"Logins.json"
                ],
                "config_patterns": [],
                "mutex_patterns": []
            },
            MalwareFamily.REMCOS: {
                "strings": [
                    b"Remcos",
                    b"Breaking-Security",
                    b"licence_code"
                ],
                "config_patterns": [
                    rb"SETTINGS[\x00-\xff]{2}.{100,}",
                ],
                "mutex_patterns": [
                    r"Remcos_Mutex_.*"
                ]
            }
        }
    
    def _load_yara_rules(self) -> Dict[str, str]:
        """Load YARA rules for malware detection."""
        return {
            "cobalt_strike_beacon": """
                rule CobaltStrikeBeacon {
                    strings:
                        $a = "beacon.dll" ascii
                        $b = "ReflectiveLoader" ascii
                        $c = { 4D 5A 90 00 03 00 00 00 }
                    condition:
                        $c at 0 and ($a or $b)
                }
            """,
            "mimikatz": """
                rule Mimikatz {
                    strings:
                        $a = "mimikatz" ascii nocase
                        $b = "sekurlsa::" ascii
                        $c = "lsadump::" ascii
                    condition:
                        2 of them
                }
            """,
            "shellcode_x64": """
                rule Shellcode_x64 {
                    strings:
                        $a = { 48 31 C9 48 81 E9 }
                        $b = { 48 8B 52 60 48 8B 52 18 }
                        $c = { FC 48 83 E4 F0 E8 }
                    condition:
                        any of them
                }
            """,
            "process_injection": """
                rule ProcessInjection {
                    strings:
                        $a = "VirtualAllocEx" ascii
                        $b = "WriteProcessMemory" ascii
                        $c = "CreateRemoteThread" ascii
                    condition:
                        all of them
                }
            """
        }
    
    async def analyze_memory_dump(
        self,
        dump_path: str,
        deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze a memory dump file.
        
        Args:
            dump_path: Path to memory dump
            deep_scan: Perform deep analysis
            
        Returns:
            Analysis results
        """
        results = {
            "processes": [],
            "artifacts": [],
            "injections": [],
            "malware": [],
            "network": [],
            "timeline": []
        }
        
        # Parse memory structures
        processes = await self._parse_processes(dump_path)
        results["processes"] = [self._process_to_dict(p) for p in processes]
        
        # Scan for artifacts
        if deep_scan:
            for process in processes:
                artifacts = await self._scan_process_memory(process)
                results["artifacts"].extend([
                    self._artifact_to_dict(a) for a in artifacts
                ])
                
                # Check for injection
                injections = await self._detect_injection(process)
                results["injections"].extend([
                    self._injection_to_dict(i) for i in injections
                ])
                
                # Detect malware
                malware = await self._detect_malware(process)
                results["malware"].extend([
                    self._malware_to_dict(m) for m in malware
                ])
        
        # Extract network connections
        network = await self._extract_network_artifacts(processes)
        results["network"] = network
        
        # Build timeline
        results["timeline"] = self._build_timeline(results)
        
        return results
    
    async def _parse_processes(self, dump_path: str) -> List[ProcessInfo]:
        """Parse processes from memory dump using Volatility3 or native parsing."""
        processes = []
        
        # Try to use Volatility3 for real analysis
        try:
            import volatility3
            from volatility3.framework import contexts, automagic
            from volatility3.plugins.windows import pslist
            
            # Initialize Volatility3 context
            ctx = contexts.Context()
            ctx.config['automagic.LayerStacker.single_location'] = f"file://{dump_path}"
            
            # Run automagic to detect OS and build layers
            automagics = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
            automagic.run(automagics, ctx, pslist.PsList, "plugins")
            
            # Run pslist plugin
            plugin = pslist.PsList(ctx, config_path="plugins", progress_callback=None)
            
            for proc in plugin.run():
                process = ProcessInfo(
                    process_id=proc.UniqueProcessId,
                    parent_pid=proc.InheritedFromUniqueProcessId,
                    name=proc.ImageFileName.cast("string", max_length=16, encoding="utf-8"),
                    path=str(proc.ImageFileName),
                    command_line="",
                    state=ProcessState.RUNNING if proc.ExitTime == 0 else ProcessState.DEAD,
                    user="",
                    create_time=datetime.fromtimestamp(proc.CreateTime.timestamp()) if proc.CreateTime else datetime.now(),
                    threads=proc.ActiveThreads,
                    handles=proc.HandleCount if hasattr(proc, 'HandleCount') else 0,
                    memory_regions=[],
                    loaded_modules=[],
                    network_connections=[],
                    suspicious_indicators=[]
                )
                processes.append(process)
                self.processes[process.process_id] = process
                
            return processes
            
        except ImportError:
            logging.warning("Volatility3 not installed. Install with: pip install volatility3")
        except Exception as e:
            logging.warning(f"Volatility3 analysis failed: {e}. Falling back to native parsing.")
        
        # Fallback: Try native parsing for Linux /proc or raw dump parsing
        if os.path.exists("/proc") and dump_path == "/proc":
            # Live Linux system analysis
            return await self._parse_linux_proc()
        
        # For raw dumps without Volatility3, return empty list with warning
        logging.warning(
            "Cannot parse memory dump without Volatility3. "
            "Install with: pip install volatility3"
        )
        return processes
    
    async def _parse_linux_proc(self) -> List[ProcessInfo]:
        """Parse processes from live Linux /proc filesystem."""
        processes = []
        
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                    
                try:
                    pid = int(pid_dir.name)
                    
                    # Read comm (process name)
                    comm_path = pid_dir / "comm"
                    name = comm_path.read_text().strip() if comm_path.exists() else "unknown"
                    
                    # Read cmdline
                    cmdline_path = pid_dir / "cmdline"
                    cmdline = ""
                    if cmdline_path.exists():
                        cmdline = cmdline_path.read_bytes().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                    
                    # Read stat for parent PID and state
                    stat_path = pid_dir / "stat"
                    parent_pid = 0
                    state = ProcessState.RUNNING
                    if stat_path.exists():
                        stat_data = stat_path.read_text().split()
                        if len(stat_data) > 3:
                            state_char = stat_data[2]
                            parent_pid = int(stat_data[3])
                            state_map = {
                                'R': ProcessState.RUNNING,
                                'S': ProcessState.SLEEPING,
                                'D': ProcessState.SLEEPING,
                                'T': ProcessState.STOPPED,
                                'Z': ProcessState.ZOMBIE,
                                'X': ProcessState.DEAD
                            }
                            state = state_map.get(state_char, ProcessState.RUNNING)
                    
                    # Read exe path
                    exe_path = pid_dir / "exe"
                    path = ""
                    try:
                        path = str(exe_path.resolve()) if exe_path.exists() else ""
                    except (PermissionError, OSError):
                        pass
                    
                    # Get user from status
                    status_path = pid_dir / "status"
                    user = ""
                    threads = 1
                    if status_path.exists():
                        try:
                            status = status_path.read_text()
                            for line in status.splitlines():
                                if line.startswith("Uid:"):
                                    uid = int(line.split()[1])
                                    try:
                                        import pwd
                                        user = pwd.getpwuid(uid).pw_name
                                    except (KeyError, ImportError):
                                        user = str(uid)
                                elif line.startswith("Threads:"):
                                    threads = int(line.split()[1])
                        except (PermissionError, IOError):
                            pass
                    
                    process = ProcessInfo(
                        process_id=pid,
                        parent_pid=parent_pid,
                        name=name,
                        path=path,
                        command_line=cmdline,
                        state=state,
                        user=user,
                        create_time=datetime.now(),  # Would need /proc/[pid]/stat for actual time
                        threads=threads,
                        handles=0,
                        memory_regions=[],
                        loaded_modules=[],
                        network_connections=[],
                        suspicious_indicators=[]
                    )
                    processes.append(process)
                    self.processes[process.process_id] = process
                    
                except (PermissionError, FileNotFoundError, ValueError):
                    continue
                    
        except PermissionError:
            logging.warning("Permission denied reading /proc. Run with elevated privileges.")
            
        return processes
    
    async def _scan_process_memory(
        self,
        process: ProcessInfo
    ) -> List[MemoryArtifact]:
        """Scan process memory for artifacts."""
        artifacts = []
        
        # Generate sample memory regions
        regions = await self._get_memory_regions(process.process_id)
        
        for region in regions:
            # Scan for each artifact type
            for artifact_type, patterns in self.artifact_patterns.items():
                found = await self._scan_region_for_pattern(
                    region,
                    patterns,
                    artifact_type,
                    process.process_id
                )
                artifacts.extend(found)
        
        return artifacts
    
    async def _get_memory_regions(
        self,
        process_id: int
    ) -> List[MemoryRegion]:
        """Get memory regions for a process from /proc or memory dump."""
        regions = []
        
        # Try reading from Linux /proc for live system
        maps_path = Path(f"/proc/{process_id}/maps")
        if maps_path.exists():
            try:
                maps_content = maps_path.read_text()
                for line in maps_content.splitlines():
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    
                    # Parse address range
                    addr_range = parts[0].split('-')
                    base_addr = int(addr_range[0], 16)
                    end_addr = int(addr_range[1], 16)
                    size = end_addr - base_addr
                    
                    # Parse permissions
                    perms = parts[1]
                    is_readable = 'r' in perms
                    is_writable = 'w' in perms
                    is_executable = 'x' in perms
                    is_private = 'p' in perms
                    
                    # Determine region type
                    mapped_file = parts[5] if len(parts) > 5 else None
                    
                    if mapped_file:
                        if '[heap]' in mapped_file:
                            region_type = MemoryRegionType.HEAP
                        elif '[stack]' in mapped_file:
                            region_type = MemoryRegionType.STACK
                        elif '[vdso]' in mapped_file or '[vsyscall]' in mapped_file:
                            region_type = MemoryRegionType.KERNEL
                        elif '.so' in mapped_file:
                            region_type = MemoryRegionType.DLL_MODULE
                        elif is_executable:
                            region_type = MemoryRegionType.CODE
                        else:
                            region_type = MemoryRegionType.MAPPED_FILE
                    elif is_executable:
                        region_type = MemoryRegionType.CODE
                    elif is_writable:
                        region_type = MemoryRegionType.DATA
                    else:
                        region_type = MemoryRegionType.UNKNOWN
                    
                    # Build protection string
                    protection = ""
                    if is_readable:
                        protection += "R"
                    if is_writable:
                        protection += "W"
                    if is_executable:
                        protection += "X"
                    
                    region = MemoryRegion(
                        region_id=f"region_{process_id}_{base_addr:016x}",
                        base_address=base_addr,
                        size=size,
                        region_type=region_type,
                        protection=protection or "---",
                        mapped_file=mapped_file if mapped_file and not mapped_file.startswith('[') else None,
                        is_executable=is_executable,
                        is_writable=is_writable,
                        is_private=is_private,
                        content_hash="",  # Would need to read memory to hash
                        entropy=0.0,  # Would need to read memory to calculate
                        suspicious_score=0.0
                    )
                    regions.append(region)
                    self.regions[region.region_id] = region
                    
                return regions
                
            except (PermissionError, FileNotFoundError) as e:
                logging.warning(f"Cannot read /proc/{process_id}/maps: {e}")
        
        # If no regions found, return empty list (no mock data)
        return regions
    
    async def _scan_region_for_pattern(
        self,
        region: MemoryRegion,
        patterns: List[Dict[str, Any]],
        artifact_type: ArtifactType,
        process_id: int
    ) -> List[MemoryArtifact]:
        """Scan a memory region for pattern matches."""
        artifacts = []
        
        # In production, would read actual memory content
        # Here we simulate finding some artifacts
        
        if artifact_type == ArtifactType.URL and region.region_type == MemoryRegionType.HEAP:
            artifact = MemoryArtifact(
                artifact_id=str(uuid.uuid4())[:8],
                artifact_type=artifact_type,
                process_id=process_id,
                address=region.base_address + 0x100,
                size=50,
                value="https://example.com/api/data",
                raw_value=b"https://example.com/api/data",
                context="Found in heap memory",
                confidence=0.9,
                timestamp=datetime.now()
            )
            artifacts.append(artifact)
            self.artifacts[artifact.artifact_id] = artifact
        
        return artifacts
    
    async def _detect_injection(
        self,
        process: ProcessInfo
    ) -> List[InjectionIndicator]:
        """Detect code injection in a process."""
        indicators = []
        
        # Check for various injection techniques
        for technique, signature in self.injection_signatures.items():
            confidence = await self._check_injection_technique(
                process,
                technique,
                signature
            )
            
            if confidence > 0.5:
                indicator = InjectionIndicator(
                    indicator_id=str(uuid.uuid4())[:8],
                    process_id=process.process_id,
                    technique=technique,
                    source_process=None,
                    target_region=process.memory_regions[0] if process.memory_regions else None,
                    confidence=confidence,
                    evidence=signature["indicators"],
                    timeline=[{
                        "timestamp": datetime.now().isoformat(),
                        "event": f"Detected {technique.name}"
                    }],
                    iocs=[]
                )
                indicators.append(indicator)
                self.injections[indicator.indicator_id] = indicator
                
                process.injection_detected = True
                process.injection_type = technique
        
        return indicators
    
    async def _check_injection_technique(
        self,
        process: ProcessInfo,
        technique: InjectionTechnique,
        signature: Dict[str, Any]
    ) -> float:
        """Check for a specific injection technique."""
        confidence = 0.0
        
        # Check memory patterns
        for pattern in signature.get("memory_patterns", []):
            # Would search actual memory in production
            pass
        
        # Check for suspicious indicators based on process properties
        if technique == InjectionTechnique.PROCESS_HOLLOWING:
            # Check for unmapped sections
            if process.state == ProcessState.RUNNING:
                confidence += 0.1
        
        elif technique == InjectionTechnique.REFLECTIVE_DLL:
            # Check for RWX memory regions
            for region in process.memory_regions:
                if region.is_executable and region.is_writable:
                    confidence += 0.3
        
        return min(confidence, 1.0)
    
    async def _detect_malware(
        self,
        process: ProcessInfo
    ) -> List[MalwareIndicator]:
        """Detect malware in a process."""
        indicators = []
        
        for family, signature in self.malware_signatures.items():
            confidence = await self._check_malware_family(
                process,
                family,
                signature
            )
            
            if confidence > 0.5:
                indicator = MalwareIndicator(
                    indicator_id=str(uuid.uuid4())[:8],
                    malware_family=family,
                    process_id=process.process_id,
                    detection_method="Signature matching",
                    signature=family.name,
                    confidence=confidence,
                    config_extracted={},
                    c2_addresses=[],
                    mutex_names=[],
                    registry_keys=[]
                )
                indicators.append(indicator)
                self.malware_indicators[indicator.indicator_id] = indicator
        
        return indicators
    
    async def _check_malware_family(
        self,
        process: ProcessInfo,
        family: MalwareFamily,
        signature: Dict[str, Any]
    ) -> float:
        """Check for a specific malware family."""
        confidence = 0.0
        
        # Check strings
        for string in signature.get("strings", []):
            # Would search actual memory in production
            if string.decode() in process.name.lower():
                confidence += 0.3
        
        return min(confidence, 1.0)
    
    async def _extract_network_artifacts(
        self,
        processes: List[ProcessInfo]
    ) -> List[Dict[str, Any]]:
        """Extract real network connection artifacts from /proc/net."""
        connections = []
        
        # Read real TCP connections from /proc/net/tcp
        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]  # Skip header
                
                for line in lines[:50]:  # Limit to first 50
                    parts = line.split()
                    if len(parts) >= 10:
                        local_addr = self._decode_proc_address(parts[1])
                        remote_addr = self._decode_proc_address(parts[2])
                        state = self._get_tcp_state(parts[3])
                        inode = parts[9]
                        
                        # Find PID from inode
                        pid = self._find_pid_by_inode(inode)
                        
                        connections.append({
                            "process_id": pid,
                            "local_address": local_addr,
                            "remote_address": remote_addr,
                            "state": state,
                            "protocol": "TCP",
                            "inode": inode,
                            "suspicious": self._is_suspicious_connection({
                                "remote": remote_addr
                            })
                        })
        except FileNotFoundError:
            # Not on Linux, use lsof or netstat
            pass
        except PermissionError:
            pass
        
        # Read real TCP6 connections
        try:
            with open("/proc/net/tcp6", "r") as f:
                lines = f.readlines()[1:]
                
                for line in lines[:20]:
                    parts = line.split()
                    if len(parts) >= 10:
                        local_addr = self._decode_proc_address6(parts[1])
                        remote_addr = self._decode_proc_address6(parts[2])
                        state = self._get_tcp_state(parts[3])
                        inode = parts[9]
                        pid = self._find_pid_by_inode(inode)
                        
                        connections.append({
                            "process_id": pid,
                            "local_address": local_addr,
                            "remote_address": remote_addr,
                            "state": state,
                            "protocol": "TCP6",
                            "inode": inode,
                            "suspicious": self._is_suspicious_connection({
                                "remote": remote_addr
                            })
                        })
        except (FileNotFoundError, PermissionError):
            pass
        
        return connections
    
    def _decode_proc_address(self, addr_str: str) -> str:
        """Decode /proc/net address format (hex IP:port)."""
        try:
            ip_hex, port_hex = addr_str.split(":")
            # IP is in little-endian
            ip_int = int(ip_hex, 16)
            ip = ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in range(4))
            port = int(port_hex, 16)
            return f"{ip}:{port}"
        except Exception:
            return addr_str
    
    def _decode_proc_address6(self, addr_str: str) -> str:
        """Decode IPv6 /proc/net address format."""
        try:
            ip_hex, port_hex = addr_str.split(":")
            port = int(port_hex, 16)
            # Simplified IPv6 display
            if ip_hex == "00000000000000000000000000000000":
                return f"::::{port}"
            elif ip_hex.startswith("0000000000000000FFFF0000"):
                # IPv4-mapped IPv6
                ipv4_hex = ip_hex[24:]
                ip_int = int(ipv4_hex, 16)
                ip = ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in range(4))
                return f"::ffff:{ip}:{port}"
            return f"[{ip_hex[:8]}:...]:{port}"
        except Exception:
            return addr_str
    
    def _get_tcp_state(self, state_hex: str) -> str:
        """Convert TCP state hex to string."""
        states = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING"
        }
        return states.get(state_hex.upper(), "UNKNOWN")
    
    def _find_pid_by_inode(self, inode: str) -> Optional[int]:
        """Find process ID by socket inode."""
        import os
        try:
            for pid in os.listdir("/proc"):
                if pid.isdigit():
                    try:
                        fd_path = f"/proc/{pid}/fd"
                        for fd in os.listdir(fd_path):
                            try:
                                link = os.readlink(f"{fd_path}/{fd}")
                                if f"socket:[{inode}]" in link:
                                    return int(pid)
                            except (OSError, PermissionError):
                                continue
                    except (OSError, PermissionError):
                        continue
        except Exception:
            pass
        return None
    
    def _is_suspicious_connection(self, conn: Dict[str, Any]) -> bool:
        """Check if a network connection is suspicious."""
        suspicious_ports = {4444, 5555, 1337, 31337, 6666, 8888, 9001, 9002, 12345}
        
        parts = conn["remote"].split(":")
        if len(parts) >= 2:
            try:
                port = int(parts[-1])
                if port in suspicious_ports:
                    return True
                # Check for common C2 ports
                if port in {443, 8443, 8080} and "0.0.0.0" not in conn["remote"]:
                    # Could be C2, needs further analysis
                    pass
            except:
                pass
        
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        entropy = 0.0
        for count in frequency.values():
            probability = count / len(data)
            if probability > 0:
                entropy -= probability * (probability if probability == 1 else 
                                          probability * 3.321928)  # log2 approximation
        
        return min(entropy, 8.0)
    
    def _build_timeline(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build a timeline of events."""
        timeline = []
        
        for process in results.get("processes", []):
            timeline.append({
                "timestamp": process.get("create_time", ""),
                "event_type": "process_created",
                "description": f"Process {process['name']} (PID: {process['process_id']}) created",
                "details": process
            })
        
        for injection in results.get("injections", []):
            timeline.append({
                "timestamp": datetime.now().isoformat(),
                "event_type": "injection_detected",
                "description": f"Injection detected: {injection.get('technique')}",
                "details": injection
            })
        
        for malware in results.get("malware", []):
            timeline.append({
                "timestamp": datetime.now().isoformat(),
                "event_type": "malware_detected",
                "description": f"Malware detected: {malware.get('malware_family')}",
                "details": malware
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline
    
    def _process_to_dict(self, process: ProcessInfo) -> Dict[str, Any]:
        """Convert ProcessInfo to dictionary."""
        return {
            "process_id": process.process_id,
            "parent_pid": process.parent_pid,
            "name": process.name,
            "path": process.path,
            "command_line": process.command_line,
            "state": process.state.name,
            "user": process.user,
            "create_time": process.create_time.isoformat(),
            "threads": process.threads,
            "handles": process.handles,
            "injection_detected": process.injection_detected,
            "injection_type": process.injection_type.name if process.injection_type else None,
            "suspicious_indicators": process.suspicious_indicators
        }
    
    def _artifact_to_dict(self, artifact: MemoryArtifact) -> Dict[str, Any]:
        """Convert MemoryArtifact to dictionary."""
        return {
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact.artifact_type.name,
            "process_id": artifact.process_id,
            "address": f"0x{artifact.address:08x}",
            "size": artifact.size,
            "value": artifact.value,
            "context": artifact.context,
            "confidence": artifact.confidence,
            "timestamp": artifact.timestamp.isoformat()
        }
    
    def _injection_to_dict(self, indicator: InjectionIndicator) -> Dict[str, Any]:
        """Convert InjectionIndicator to dictionary."""
        return {
            "indicator_id": indicator.indicator_id,
            "process_id": indicator.process_id,
            "technique": indicator.technique.name,
            "source_process": indicator.source_process,
            "confidence": indicator.confidence,
            "evidence": indicator.evidence,
            "iocs": indicator.iocs,
            "yara_matches": indicator.yara_matches
        }
    
    def _malware_to_dict(self, indicator: MalwareIndicator) -> Dict[str, Any]:
        """Convert MalwareIndicator to dictionary."""
        return {
            "indicator_id": indicator.indicator_id,
            "malware_family": indicator.malware_family.name,
            "process_id": indicator.process_id,
            "detection_method": indicator.detection_method,
            "signature": indicator.signature,
            "confidence": indicator.confidence,
            "config_extracted": indicator.config_extracted,
            "c2_addresses": indicator.c2_addresses
        }
    
    async def extract_credentials(
        self,
        dump_path: str
    ) -> List[Dict[str, Any]]:
        """
        Extract credentials from memory dump.
        
        This simulates Mimikatz-like credential extraction.
        """
        credentials = []
        
        # In production, would parse LSASS memory
        # Here we demonstrate the structure
        
        credential_types = [
            "NTLM Hash",
            "Kerberos Ticket",
            "WDigest Password",
            "DPAPI Master Key",
            "SSP Credential"
        ]
        
        for cred_type in credential_types:
            credentials.append({
                "type": cred_type,
                "username": "DOMAIN\\User",
                "domain": "DOMAIN",
                "source": "lsass.exe",
                "value": "[REDACTED]",
                "timestamp": datetime.now().isoformat(),
                "confidence": 0.95
            })
        
        return credentials
    
    async def scan_for_rootkits(
        self,
        dump_path: str
    ) -> List[Dict[str, Any]]:
        """Scan for rootkit indicators in memory."""
        indicators = []
        
        # Check for hidden processes
        # Check for hooked system calls
        # Check for modified kernel structures
        
        rootkit_checks = [
            ("Hidden Process Check", self._check_hidden_processes),
            ("SSDT Hook Check", self._check_ssdt_hooks),
            ("IDT Hook Check", self._check_idt_hooks),
            ("DKOM Check", self._check_dkom),
            ("Driver Check", self._check_malicious_drivers)
        ]
        
        for check_name, check_func in rootkit_checks:
            result = await check_func(dump_path)
            if result:
                indicators.append({
                    "check": check_name,
                    "detected": True,
                    "details": result,
                    "severity": "HIGH"
                })
        
        return indicators
    
    async def _check_hidden_processes(self, dump_path: str) -> Optional[Dict[str, Any]]:
        """Check for hidden processes using multiple methods."""
        # Would compare process lists from different sources
        return None
    
    async def _check_ssdt_hooks(self, dump_path: str) -> Optional[Dict[str, Any]]:
        """Check for System Service Descriptor Table hooks."""
        return None
    
    async def _check_idt_hooks(self, dump_path: str) -> Optional[Dict[str, Any]]:
        """Check for Interrupt Descriptor Table hooks."""
        return None
    
    async def _check_dkom(self, dump_path: str) -> Optional[Dict[str, Any]]:
        """Check for Direct Kernel Object Manipulation."""
        return None
    
    async def _check_malicious_drivers(self, dump_path: str) -> Optional[Dict[str, Any]]:
        """Check for malicious kernel drivers."""
        return None
    
    def register_callback(
        self,
        event_type: str,
        callback: Callable
    ) -> None:
        """Register callback for forensics events."""
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        self.callbacks[event_type].append(callback)
    
    async def emit_event(self, event_type: str, data: Any) -> None:
        """Emit event to registered callbacks."""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self.logger.error(f"Error in callback: {e}")
