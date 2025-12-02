"""
Digital Forensics Module
Memory analysis, disk forensics, artifact collection
"""

import asyncio
import os
import re
import json
import hashlib
import struct
import mmap
import binascii
from typing import Dict, List, Optional, Any, Tuple, Generator
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
import subprocess
import tempfile


class ArtifactType(Enum):
    """Types of forensic artifacts"""
    BROWSER_HISTORY = "browser_history"
    BROWSER_COOKIES = "browser_cookies"
    BROWSER_PASSWORDS = "browser_passwords"
    BROWSER_DOWNLOADS = "browser_downloads"
    REGISTRY_KEY = "registry_key"
    EVENT_LOG = "event_log"
    PREFETCH = "prefetch"
    SHELLBAG = "shellbag"
    JUMP_LIST = "jump_list"
    RECENT_DOCS = "recent_docs"
    USB_HISTORY = "usb_history"
    NETWORK_HISTORY = "network_history"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    STARTUP = "startup"
    USER_ACCOUNT = "user_account"
    DELETED_FILE = "deleted_file"
    MEMORY_STRING = "memory_string"
    PROCESS = "process"
    NETWORK_CONNECTION = "network_connection"
    CREDENTIAL = "credential"
    SSH_KEY = "ssh_key"
    ENCRYPTION_KEY = "encryption_key"


class EvidenceStatus(Enum):
    """Status of collected evidence"""
    COLLECTED = "collected"
    ANALYZED = "analyzed"
    EXPORTED = "exported"
    CORRUPTED = "corrupted"
    ENCRYPTED = "encrypted"


@dataclass
class ForensicArtifact:
    """Represents a forensic artifact"""
    artifact_id: str
    artifact_type: ArtifactType
    source: str
    data: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    hash_md5: str = ""
    hash_sha256: str = ""
    collected_at: str = field(default_factory=lambda: datetime.now().isoformat())
    analyzed: bool = False
    notes: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class MemoryRegion:
    """Represents a memory region"""
    address: int
    size: int
    protection: str
    state: str
    type: str
    mapped_file: str = ""
    content: bytes = b""


@dataclass
class ProcessInfo:
    """Process information from memory"""
    pid: int
    ppid: int
    name: str
    path: str
    cmdline: str
    create_time: str
    user: str
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    handles: List[Dict[str, Any]] = field(default_factory=list)
    threads: List[Dict[str, Any]] = field(default_factory=list)
    dlls: List[str] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)


class MemoryAnalyzer:
    """
    Memory analysis engine
    Analyzes memory dumps and live memory
    """
    
    # Common patterns to search for
    PATTERNS = {
        "email": rb'[\w\.-]+@[\w\.-]+\.\w+',
        "url": rb'https?://[\w\.-]+(?:/[\w\./\-\?=&%]*)?',
        "ip_address": rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        "credit_card": rb'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
        "ssn": rb'\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b',
        "phone": rb'\b\d{3}[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b',
        "bitcoin": rb'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "private_key": rb'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
        "password_hash": rb'\$[126aby]\$[^\$]+\$[^\$]+',
        "windows_path": rb'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        "unix_path": rb'/(?:[^/\0\n]+/)*[^/\0\n]+',
        "base64_blob": rb'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        "uuid": rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    }
    
    # Magic bytes for file type identification
    MAGIC_BYTES = {
        b'\x4D\x5A': "PE Executable",
        b'\x7F\x45\x4C\x46': "ELF Executable",
        b'\xCA\xFE\xBA\xBE': "Mach-O Executable",
        b'\x50\x4B\x03\x04': "ZIP Archive",
        b'\x52\x61\x72\x21': "RAR Archive",
        b'\x1F\x8B': "GZIP Archive",
        b'\x25\x50\x44\x46': "PDF Document",
        b'\xD0\xCF\x11\xE0': "MS Office (OLE)",
        b'\x50\x4B\x03\x04': "Office Open XML",
        b'\x89\x50\x4E\x47': "PNG Image",
        b'\xFF\xD8\xFF': "JPEG Image",
        b'\x47\x49\x46\x38': "GIF Image",
        b'SQLite format 3': "SQLite Database",
    }
    
    def __init__(self, chunk_size: int = 1024 * 1024):
        self.chunk_size = chunk_size
        self.artifacts: List[ForensicArtifact] = []
        
    def analyze_dump(self, 
                     dump_path: str,
                     patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze a memory dump file
        """
        results = {
            "file": dump_path,
            "size": 0,
            "analysis_time": datetime.now().isoformat(),
            "strings": [],
            "patterns_found": {},
            "embedded_files": [],
            "processes": [],
        }
        
        if not os.path.exists(dump_path):
            results["error"] = "File not found"
            return results
            
        results["size"] = os.path.getsize(dump_path)
        
        # Select patterns to search
        if patterns:
            search_patterns = {k: v for k, v in self.PATTERNS.items() if k in patterns}
        else:
            search_patterns = self.PATTERNS
            
        # Memory-map the file for efficient searching
        with open(dump_path, 'rb') as f:
            try:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                
                # Search for patterns
                for pattern_name, pattern in search_patterns.items():
                    matches = set()
                    for match in re.finditer(pattern, mm):
                        try:
                            decoded = match.group().decode('utf-8', errors='ignore')
                            matches.add(decoded)
                        except Exception:
                            matches.add(match.group().hex())
                            
                    if matches:
                        results["patterns_found"][pattern_name] = list(matches)[:100]  # Limit results
                        
                # Search for embedded files
                results["embedded_files"] = self._find_embedded_files(mm)
                
                # Extract readable strings
                results["strings"] = self._extract_strings(mm, min_length=8)[:1000]
                
                mm.close()
                
            except Exception as e:
                results["error"] = str(e)
                
        return results
        
    def _find_embedded_files(self, data: mmap.mmap) -> List[Dict[str, Any]]:
        """Find embedded files in memory by magic bytes"""
        embedded = []
        
        for magic, file_type in self.MAGIC_BYTES.items():
            offset = 0
            while True:
                pos = data.find(magic, offset)
                if pos == -1:
                    break
                    
                embedded.append({
                    "type": file_type,
                    "offset": hex(pos),
                    "magic": magic.hex(),
                })
                
                offset = pos + 1
                
                # Limit search
                if len(embedded) > 100:
                    break
                    
        return embedded
        
    def _extract_strings(self, 
                         data: mmap.mmap, 
                         min_length: int = 4,
                         encoding: str = "utf-8") -> List[str]:
        """Extract readable strings from memory"""
        strings = []
        current_string = []
        
        printable = set(range(32, 127)) | {9, 10, 13}  # ASCII printable + whitespace
        
        for i in range(len(data)):
            byte = data[i]
            if byte in printable:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
                
            # Stop if we have enough strings
            if len(strings) >= 10000:
                break
                
        return strings
        
    def analyze_process_memory(self, pid: int) -> ProcessInfo:
        """Analyze a running process's memory (Linux)"""
        proc_info = ProcessInfo(
            pid=pid,
            ppid=0,
            name="",
            path="",
            cmdline="",
            create_time="",
            user="",
        )
        
        try:
            # Read process info from /proc
            proc_path = Path(f"/proc/{pid}")
            
            if not proc_path.exists():
                return proc_info
                
            # Get command line
            cmdline_path = proc_path / "cmdline"
            if cmdline_path.exists():
                proc_info.cmdline = cmdline_path.read_text().replace('\x00', ' ').strip()
                
            # Get executable path
            exe_path = proc_path / "exe"
            if exe_path.exists():
                try:
                    proc_info.path = os.readlink(str(exe_path))
                    proc_info.name = os.path.basename(proc_info.path)
                except Exception:
                    pass
                    
            # Get memory maps
            maps_path = proc_path / "maps"
            if maps_path.exists():
                for line in maps_path.read_text().split('\n'):
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 5:
                        addr_range = parts[0].split('-')
                        region = MemoryRegion(
                            address=int(addr_range[0], 16),
                            size=int(addr_range[1], 16) - int(addr_range[0], 16),
                            protection=parts[1],
                            state="committed",
                            type=parts[4] if len(parts) > 4 else "private",
                            mapped_file=parts[5] if len(parts) > 5 else "",
                        )
                        proc_info.memory_regions.append(region)
                        
            # Get open file descriptors
            fd_path = proc_path / "fd"
            if fd_path.exists():
                for fd in fd_path.iterdir():
                    try:
                        target = os.readlink(str(fd))
                        proc_info.handles.append({
                            "fd": fd.name,
                            "target": target,
                        })
                    except Exception:
                        pass
                        
            # Get network connections
            proc_info.network_connections = self._get_process_connections(pid)
            
        except Exception as e:
            proc_info.cmdline = f"Error: {e}"
            
        return proc_info
        
    def _get_process_connections(self, pid: int) -> List[Dict[str, Any]]:
        """Get network connections for a process"""
        connections = []
        
        try:
            # Parse /proc/net/tcp and /proc/net/tcp6
            for proto in ["tcp", "tcp6", "udp", "udp6"]:
                net_path = Path(f"/proc/{pid}/net/{proto}")
                if not net_path.exists():
                    net_path = Path(f"/proc/net/{proto}")
                    
                if net_path.exists():
                    lines = net_path.read_text().split('\n')[1:]  # Skip header
                    for line in lines:
                        if not line.strip():
                            continue
                        parts = line.split()
                        if len(parts) < 10:
                            continue
                            
                        # Parse addresses
                        local = self._parse_net_addr(parts[1])
                        remote = self._parse_net_addr(parts[2])
                        state = int(parts[3], 16)
                        inode = parts[9]
                        
                        connections.append({
                            "protocol": proto,
                            "local_addr": local[0],
                            "local_port": local[1],
                            "remote_addr": remote[0],
                            "remote_port": remote[1],
                            "state": self._tcp_state(state),
                        })
                        
        except Exception:
            pass
            
        return connections
        
    def _parse_net_addr(self, addr_str: str) -> Tuple[str, int]:
        """Parse network address from /proc/net format"""
        try:
            addr, port = addr_str.split(':')
            port = int(port, 16)
            
            # Convert hex address to IP
            if len(addr) == 8:  # IPv4
                bytes_addr = bytes.fromhex(addr)
                ip = '.'.join(str(b) for b in reversed(bytes_addr))
            else:  # IPv6
                ip = addr  # Simplified
                
            return (ip, port)
        except Exception:
            return ("0.0.0.0", 0)
            
    def _tcp_state(self, state: int) -> str:
        """Convert TCP state number to string"""
        states = {
            1: "ESTABLISHED",
            2: "SYN_SENT",
            3: "SYN_RECV",
            4: "FIN_WAIT1",
            5: "FIN_WAIT2",
            6: "TIME_WAIT",
            7: "CLOSE",
            8: "CLOSE_WAIT",
            9: "LAST_ACK",
            10: "LISTEN",
            11: "CLOSING",
        }
        return states.get(state, f"UNKNOWN({state})")


class DiskForensics:
    """
    Disk forensics engine
    Analyze disk images and file systems
    """
    
    def __init__(self):
        self.artifacts: List[ForensicArtifact] = []
        
    def analyze_disk_image(self, 
                           image_path: str,
                           mount_point: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a disk image
        """
        results = {
            "image_path": image_path,
            "analysis_time": datetime.now().isoformat(),
            "partitions": [],
            "file_systems": [],
            "deleted_files": [],
            "artifacts": [],
        }
        
        # Get image info using file command
        try:
            output = subprocess.check_output(["file", image_path]).decode()
            results["image_type"] = output.strip()
        except Exception:
            results["image_type"] = "Unknown"
            
        # Try to mount and analyze
        if mount_point:
            results["artifacts"] = self._analyze_mounted_fs(mount_point)
            
        return results
        
    def _analyze_mounted_fs(self, mount_point: str) -> List[Dict[str, Any]]:
        """Analyze a mounted filesystem"""
        artifacts = []
        
        # Collect browser artifacts
        browser_artifacts = self._collect_browser_artifacts(mount_point)
        artifacts.extend(browser_artifacts)
        
        # Collect system artifacts
        system_artifacts = self._collect_system_artifacts(mount_point)
        artifacts.extend(system_artifacts)
        
        # Find interesting files
        interesting_files = self._find_interesting_files(mount_point)
        artifacts.extend(interesting_files)
        
        return artifacts
        
    def _collect_browser_artifacts(self, base_path: str) -> List[Dict[str, Any]]:
        """Collect browser forensic artifacts"""
        artifacts = []
        
        # Chrome paths (Linux)
        chrome_paths = [
            "home/*/.config/google-chrome/Default",
            "home/*/.config/chromium/Default",
        ]
        
        # Firefox paths
        firefox_paths = [
            "home/*/.mozilla/firefox/*.default*",
        ]
        
        for pattern in chrome_paths:
            full_pattern = os.path.join(base_path, pattern)
            import glob
            for path in glob.glob(full_pattern):
                # History
                history_db = os.path.join(path, "History")
                if os.path.exists(history_db):
                    artifacts.append({
                        "type": ArtifactType.BROWSER_HISTORY.value,
                        "source": "Chrome",
                        "path": history_db,
                    })
                    
                # Cookies
                cookies_db = os.path.join(path, "Cookies")
                if os.path.exists(cookies_db):
                    artifacts.append({
                        "type": ArtifactType.BROWSER_COOKIES.value,
                        "source": "Chrome",
                        "path": cookies_db,
                    })
                    
                # Login Data (passwords)
                login_db = os.path.join(path, "Login Data")
                if os.path.exists(login_db):
                    artifacts.append({
                        "type": ArtifactType.BROWSER_PASSWORDS.value,
                        "source": "Chrome",
                        "path": login_db,
                        "note": "Encrypted with DPAPI/keyring",
                    })
                    
        return artifacts
        
    def _collect_system_artifacts(self, base_path: str) -> List[Dict[str, Any]]:
        """Collect system forensic artifacts"""
        artifacts = []
        
        # Linux artifacts
        linux_artifacts = {
            "etc/passwd": "user_accounts",
            "etc/shadow": "password_hashes",
            "etc/group": "groups",
            "var/log/auth.log": "auth_log",
            "var/log/syslog": "syslog",
            "var/log/secure": "secure_log",
            "home/*/.bash_history": "bash_history",
            "home/*/.ssh/known_hosts": "ssh_known_hosts",
            "home/*/.ssh/authorized_keys": "ssh_authorized_keys",
            "home/*/.ssh/id_rsa": "ssh_private_key",
            "root/.bash_history": "root_bash_history",
            "etc/crontab": "scheduled_tasks",
            "var/spool/cron/*": "user_crontabs",
        }
        
        import glob
        for pattern, artifact_type in linux_artifacts.items():
            full_pattern = os.path.join(base_path, pattern)
            for path in glob.glob(full_pattern):
                if os.path.isfile(path):
                    artifacts.append({
                        "type": artifact_type,
                        "path": path,
                    })
                    
        return artifacts
        
    def _find_interesting_files(self, base_path: str) -> List[Dict[str, Any]]:
        """Find interesting files for analysis"""
        interesting = []
        
        # File patterns to look for
        patterns = [
            ("*.kdb*", "KeePass database"),
            ("*.key", "Key file"),
            ("*.pem", "PEM certificate/key"),
            ("*.pfx", "PKCS12 certificate"),
            ("*.wallet", "Wallet file"),
            ("*.sql", "SQL file"),
            ("*.bak", "Backup file"),
            ("*password*", "Password file"),
            ("*secret*", "Secret file"),
            ("*credential*", "Credential file"),
            ("*.config", "Config file"),
            ("*.conf", "Config file"),
        ]
        
        import glob
        for pattern, description in patterns:
            for root, dirs, files in os.walk(base_path):
                # Skip deep paths
                if root.count(os.sep) - base_path.count(os.sep) > 5:
                    continue
                    
                import fnmatch
                for filename in fnmatch.filter(files, pattern):
                    filepath = os.path.join(root, filename)
                    interesting.append({
                        "type": description,
                        "path": filepath,
                        "size": os.path.getsize(filepath),
                    })
                    
                # Limit results
                if len(interesting) > 500:
                    return interesting
                    
        return interesting
        
    def carve_files(self, 
                    image_path: str,
                    output_dir: str,
                    file_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Carve files from disk image
        """
        carved = []
        
        # Default file types
        if file_types is None:
            file_types = ["jpeg", "png", "pdf", "doc", "zip"]
            
        # Try using photorec/foremost if available
        try:
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Use foremost
            cmd = ["foremost", "-t", ",".join(file_types), "-o", output_dir, image_path]
            subprocess.run(cmd, capture_output=True, timeout=3600)
            
            # List carved files
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    carved.append({
                        "path": filepath,
                        "type": os.path.splitext(f)[1],
                        "size": os.path.getsize(filepath),
                    })
                    
        except FileNotFoundError:
            # Manual carving if foremost not available
            carved = self._manual_carve(image_path, output_dir, file_types)
        except Exception as e:
            carved.append({"error": str(e)})
            
        return carved
        
    def _manual_carve(self, 
                      image_path: str,
                      output_dir: str,
                      file_types: List[str]) -> List[Dict[str, Any]]:
        """Simple file carving implementation"""
        carved = []
        
        # File signatures for carving
        signatures = {
            "jpeg": {
                "header": b'\xFF\xD8\xFF',
                "footer": b'\xFF\xD9',
            },
            "png": {
                "header": b'\x89PNG\r\n\x1A\n',
                "footer": b'IEND\xAE\x42\x60\x82',
            },
            "pdf": {
                "header": b'%PDF',
                "footer": b'%%EOF',
            },
            "zip": {
                "header": b'PK\x03\x04',
                "footer": None,  # Variable length
            },
        }
        
        os.makedirs(output_dir, exist_ok=True)
        
        with open(image_path, 'rb') as f:
            data = f.read()
            
        for file_type in file_types:
            if file_type not in signatures:
                continue
                
            sig = signatures[file_type]
            header = sig["header"]
            footer = sig["footer"]
            
            offset = 0
            file_count = 0
            
            while True:
                # Find header
                start = data.find(header, offset)
                if start == -1:
                    break
                    
                # Find footer
                if footer:
                    end = data.find(footer, start + len(header))
                    if end == -1:
                        offset = start + 1
                        continue
                    end += len(footer)
                else:
                    # For files without clear footer, take a chunk
                    end = min(start + 1024*1024, len(data))  # 1MB max
                    
                # Extract and save
                file_data = data[start:end]
                output_file = os.path.join(output_dir, f"carved_{file_type}_{file_count:04d}.{file_type}")
                
                with open(output_file, 'wb') as out:
                    out.write(file_data)
                    
                carved.append({
                    "path": output_file,
                    "type": file_type,
                    "offset": hex(start),
                    "size": end - start,
                })
                
                file_count += 1
                offset = end
                
                # Limit carving
                if file_count >= 100:
                    break
                    
        return carved


class ArtifactCollector:
    """
    Collect and analyze forensic artifacts from live system
    """
    
    def __init__(self):
        self.artifacts: List[ForensicArtifact] = []
        
    def collect_all(self) -> Dict[str, Any]:
        """Collect all available artifacts from the system"""
        results = {
            "collection_time": datetime.now().isoformat(),
            "hostname": os.uname().nodename,
            "artifacts": [],
        }
        
        # Collect different artifact types
        collectors = [
            self._collect_user_artifacts,
            self._collect_network_artifacts,
            self._collect_process_artifacts,
            self._collect_persistence_artifacts,
            self._collect_credential_artifacts,
        ]
        
        for collector in collectors:
            try:
                artifacts = collector()
                results["artifacts"].extend(artifacts)
            except Exception as e:
                results["artifacts"].append({
                    "type": "error",
                    "collector": collector.__name__,
                    "error": str(e),
                })
                
        return results
        
    def _collect_user_artifacts(self) -> List[Dict[str, Any]]:
        """Collect user-related artifacts"""
        artifacts = []
        
        # Get user info
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        artifacts.append({
                            "type": ArtifactType.USER_ACCOUNT.value,
                            "username": parts[0],
                            "uid": parts[2],
                            "gid": parts[3],
                            "home": parts[5],
                            "shell": parts[6],
                        })
        except Exception:
            pass
            
        # Get logged in users
        try:
            output = subprocess.check_output(["who"]).decode()
            for line in output.strip().split('\n'):
                if line:
                    artifacts.append({
                        "type": "logged_in_user",
                        "data": line,
                    })
        except Exception:
            pass
            
        # Get bash history
        home = os.path.expanduser("~")
        history_file = os.path.join(home, ".bash_history")
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    commands = f.readlines()[-100:]  # Last 100 commands
                    artifacts.append({
                        "type": "bash_history",
                        "user": os.getenv("USER"),
                        "commands": [c.strip() for c in commands],
                    })
            except Exception:
                pass
                
        return artifacts
        
    def _collect_network_artifacts(self) -> List[Dict[str, Any]]:
        """Collect network-related artifacts"""
        artifacts = []
        
        # Get network connections
        try:
            output = subprocess.check_output(["ss", "-tunapl"]).decode()
            for line in output.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    artifacts.append({
                        "type": ArtifactType.NETWORK_CONNECTION.value,
                        "protocol": parts[0],
                        "state": parts[1] if len(parts) > 5 else "N/A",
                        "local": parts[4] if len(parts) > 4 else "N/A",
                        "remote": parts[5] if len(parts) > 5 else "N/A",
                        "process": parts[-1] if len(parts) > 6 else "N/A",
                    })
        except Exception:
            pass
            
        # Get ARP cache
        try:
            output = subprocess.check_output(["arp", "-a"]).decode()
            for line in output.strip().split('\n'):
                if line:
                    artifacts.append({
                        "type": "arp_entry",
                        "data": line,
                    })
        except Exception:
            pass
            
        # Get DNS cache (if available)
        try:
            output = subprocess.check_output(["systemd-resolve", "--statistics"]).decode()
            artifacts.append({
                "type": "dns_cache_stats",
                "data": output,
            })
        except Exception:
            pass
            
        return artifacts
        
    def _collect_process_artifacts(self) -> List[Dict[str, Any]]:
        """Collect process-related artifacts"""
        artifacts = []
        
        # Get process list
        try:
            output = subprocess.check_output(["ps", "auxww"]).decode()
            for line in output.strip().split('\n')[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    artifacts.append({
                        "type": ArtifactType.PROCESS.value,
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": parts[2],
                        "mem": parts[3],
                        "start": parts[8],
                        "command": parts[10],
                    })
        except Exception:
            pass
            
        return artifacts
        
    def _collect_persistence_artifacts(self) -> List[Dict[str, Any]]:
        """Collect persistence mechanism artifacts"""
        artifacts = []
        
        # Cron jobs
        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/var/spool/cron/crontabs",
        ]
        
        for path in cron_paths:
            if os.path.isfile(path):
                try:
                    with open(path, 'r') as f:
                        artifacts.append({
                            "type": ArtifactType.SCHEDULED_TASK.value,
                            "source": path,
                            "content": f.read(),
                        })
                except Exception:
                    pass
            elif os.path.isdir(path):
                try:
                    for f in os.listdir(path):
                        filepath = os.path.join(path, f)
                        if os.path.isfile(filepath):
                            with open(filepath, 'r') as file:
                                artifacts.append({
                                    "type": ArtifactType.SCHEDULED_TASK.value,
                                    "source": filepath,
                                    "content": file.read(),
                                })
                except Exception:
                    pass
                    
        # Systemd services
        try:
            output = subprocess.check_output(["systemctl", "list-unit-files", "--type=service"]).decode()
            for line in output.strip().split('\n')[1:-2]:
                parts = line.split()
                if len(parts) >= 2:
                    artifacts.append({
                        "type": ArtifactType.SERVICE.value,
                        "name": parts[0],
                        "state": parts[1],
                    })
        except Exception:
            pass
            
        # Startup scripts
        startup_dirs = [
            "/etc/init.d",
            "/etc/rc.local",
            os.path.expanduser("~/.config/autostart"),
        ]
        
        for path in startup_dirs:
            if os.path.isdir(path):
                try:
                    for f in os.listdir(path):
                        artifacts.append({
                            "type": ArtifactType.STARTUP.value,
                            "path": os.path.join(path, f),
                        })
                except Exception:
                    pass
                    
        return artifacts
        
    def _collect_credential_artifacts(self) -> List[Dict[str, Any]]:
        """Collect credential-related artifacts"""
        artifacts = []
        
        # SSH keys
        ssh_dir = os.path.expanduser("~/.ssh")
        if os.path.isdir(ssh_dir):
            for f in os.listdir(ssh_dir):
                filepath = os.path.join(ssh_dir, f)
                if os.path.isfile(filepath):
                    artifacts.append({
                        "type": ArtifactType.SSH_KEY.value if "id_" in f else "ssh_config",
                        "path": filepath,
                        "is_private": "id_" in f and not f.endswith(".pub"),
                    })
                    
        # AWS credentials
        aws_creds = os.path.expanduser("~/.aws/credentials")
        if os.path.exists(aws_creds):
            artifacts.append({
                "type": ArtifactType.CREDENTIAL.value,
                "source": "AWS",
                "path": aws_creds,
            })
            
        # GCP credentials
        gcp_creds = os.path.expanduser("~/.config/gcloud/credentials.db")
        if os.path.exists(gcp_creds):
            artifacts.append({
                "type": ArtifactType.CREDENTIAL.value,
                "source": "GCP",
                "path": gcp_creds,
            })
            
        return artifacts


class ForensicsManager:
    """
    Main forensics management interface
    """
    
    def __init__(self, output_dir: str = "forensics_output"):
        self.output_dir = output_dir
        self.memory_analyzer = MemoryAnalyzer()
        self.disk_forensics = DiskForensics()
        self.artifact_collector = ArtifactCollector()
        
        os.makedirs(output_dir, exist_ok=True)
        
    def analyze_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """Analyze a memory dump"""
        results = self.memory_analyzer.analyze_dump(dump_path)
        
        # Save results
        output_file = os.path.join(
            self.output_dir,
            f"memory_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        results["report_path"] = output_file
        return results
        
    def collect_live_artifacts(self) -> Dict[str, Any]:
        """Collect artifacts from live system"""
        results = self.artifact_collector.collect_all()
        
        # Save results
        output_file = os.path.join(
            self.output_dir,
            f"artifact_collection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        results["report_path"] = output_file
        return results
        
    def carve_files(self, 
                    image_path: str,
                    file_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Carve files from disk image"""
        carve_dir = os.path.join(
            self.output_dir,
            f"carved_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        carved = self.disk_forensics.carve_files(image_path, carve_dir, file_types)
        
        return {
            "output_dir": carve_dir,
            "files_carved": len(carved),
            "files": carved,
        }
        
    def generate_report(self, 
                        analysis_results: Dict[str, Any],
                        format: str = "html") -> str:
        """Generate forensics report"""
        report_file = os.path.join(
            self.output_dir,
            f"forensics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        )
        
        if format == "html":
            html = self._generate_html_report(analysis_results)
            with open(report_file, 'w') as f:
                f.write(html)
        else:
            with open(report_file, 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
                
        return report_file
        
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML forensics report"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Forensics Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        .header { background: linear-gradient(135deg, #16213e, #0f3460); padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .section { background: #16213e; border-radius: 10px; padding: 15px; margin-bottom: 15px; }
        .section h2 { color: #00ff88; border-bottom: 1px solid #00ff88; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f3460; color: #00ff88; }
        .highlight { color: #ff6b6b; font-weight: bold; }
        .success { color: #00ff88; }
        pre { background: #0f0f1a; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Digital Forensics Analysis Report</h1>
        <p>Generated: """ + datetime.now().isoformat() + """</p>
    </div>
"""
        
        # Add sections based on results
        if "patterns_found" in results:
            html += """
    <div class="section">
        <h2>Pattern Matches</h2>
        <table>
            <tr><th>Pattern</th><th>Count</th><th>Samples</th></tr>
"""
            for pattern, matches in results.get("patterns_found", {}).items():
                samples = ", ".join(str(m)[:50] for m in matches[:3])
                html += f"""
            <tr>
                <td>{pattern}</td>
                <td>{len(matches)}</td>
                <td><pre>{samples}...</pre></td>
            </tr>
"""
            html += """
        </table>
    </div>
"""
            
        if "artifacts" in results:
            html += """
    <div class="section">
        <h2>Collected Artifacts</h2>
        <table>
            <tr><th>Type</th><th>Source</th><th>Details</th></tr>
"""
            for artifact in results.get("artifacts", [])[:50]:
                html += f"""
            <tr>
                <td>{artifact.get('type', 'unknown')}</td>
                <td>{artifact.get('source', artifact.get('path', 'N/A'))}</td>
                <td>{str(artifact)[:100]}...</td>
            </tr>
"""
            html += """
        </table>
    </div>
"""
            
        html += """
</body>
</html>
"""
        return html


if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("Digital Forensics Module")
    print("="*60)
    
    manager = ForensicsManager()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "collect":
            print("\n[*] Collecting live system artifacts...")
            results = manager.collect_live_artifacts()
            print(f"[+] Collected {len(results['artifacts'])} artifacts")
            print(f"[+] Report saved to: {results['report_path']}")
            
        elif sys.argv[1] == "memory" and len(sys.argv) > 2:
            dump_path = sys.argv[2]
            print(f"\n[*] Analyzing memory dump: {dump_path}")
            results = manager.analyze_memory_dump(dump_path)
            print(f"[+] Found {len(results.get('patterns_found', {}))} pattern types")
            print(f"[+] Report saved to: {results['report_path']}")
            
    else:
        print("\nUsage:")
        print("  python forensics.py collect           - Collect live system artifacts")
        print("  python forensics.py memory <dump>     - Analyze memory dump")
