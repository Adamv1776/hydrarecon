"""
HydraRecon Advanced Firmware Analysis Module
Deep firmware extraction, analysis, and vulnerability detection
"""

import asyncio
import binascii
import hashlib
import json
import logging
import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class FirmwareType(Enum):
    """Firmware types"""
    EMBEDDED_LINUX = "embedded_linux"
    RTOS = "rtos"
    BARE_METAL = "bare_metal"
    ANDROID = "android"
    VXWORKS = "vxworks"
    QNX = "qnx"
    THREADX = "threadx"
    FREERTOS = "freertos"
    UNKNOWN = "unknown"


class Architecture(Enum):
    """CPU architectures"""
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPSEL = "mipsel"
    X86 = "x86"
    X86_64 = "x86_64"
    PPC = "powerpc"
    XTENSA = "xtensa"
    AVR = "avr"
    UNKNOWN = "unknown"


class FileSystemType(Enum):
    """Filesystem types"""
    SQUASHFS = "squashfs"
    CRAMFS = "cramfs"
    JFFS2 = "jffs2"
    YAFFS = "yaffs"
    UBIFS = "ubifs"
    EXT2 = "ext2"
    EXT3 = "ext3"
    EXT4 = "ext4"
    FAT = "fat"
    ROMFS = "romfs"
    UNKNOWN = "unknown"


class CompressionType(Enum):
    """Compression algorithms"""
    GZIP = "gzip"
    LZMA = "lzma"
    XZ = "xz"
    LZO = "lzo"
    ZSTD = "zstd"
    BZIP2 = "bzip2"
    NONE = "none"


class SeverityLevel(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FirmwareInfo:
    """Firmware metadata"""
    firmware_id: str
    filename: str
    file_size: int
    file_hash_md5: str
    file_hash_sha256: str
    firmware_type: FirmwareType = FirmwareType.UNKNOWN
    architecture: Architecture = Architecture.UNKNOWN
    endianness: str = "little"
    base_address: int = 0
    entry_point: int = 0
    vendor: str = ""
    product: str = ""
    version: str = ""
    build_date: Optional[datetime] = None
    compression: CompressionType = CompressionType.NONE
    filesystem: FileSystemType = FileSystemType.UNKNOWN


@dataclass
class ExtractedFile:
    """Extracted file from firmware"""
    path: str
    size: int
    file_type: str
    permissions: str = ""
    owner: str = ""
    hash_sha256: str = ""
    is_executable: bool = False
    is_script: bool = False
    is_config: bool = False
    interesting: bool = False


@dataclass
class FirmwareFinding:
    """Security finding in firmware"""
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel
    category: str
    file_path: str = ""
    line_number: int = 0
    evidence: str = ""
    cwe_id: Optional[str] = None
    remediation: str = ""


@dataclass
class HardcodedCredential:
    """Hardcoded credential"""
    credential_type: str
    username: str = ""
    password: str = ""
    hash_value: str = ""
    file_path: str = ""
    line_number: int = 0


@dataclass
class CryptoKey:
    """Cryptographic key material"""
    key_type: str
    algorithm: str = ""
    key_size: int = 0
    file_path: str = ""
    is_private: bool = False
    is_weak: bool = False


class FirmwareHeader:
    """Firmware header parser"""
    
    # Common firmware signatures
    SIGNATURES = {
        b'\x27\x05\x19\x56': ('uImage', 'U-Boot Image'),
        b'hsqs': ('squashfs', 'SquashFS Little Endian'),
        b'sqsh': ('squashfs', 'SquashFS Big Endian'),
        b'\x1f\x8b\x08': ('gzip', 'Gzip Compressed'),
        b'\xfd\x37\x7a\x58\x5a\x00': ('xz', 'XZ Compressed'),
        b'\x5d\x00\x00': ('lzma', 'LZMA Compressed'),
        b'BZh': ('bzip2', 'Bzip2 Compressed'),
        b'\x85\x19\x01\x28': ('cramfs_le', 'CramFS Little Endian'),
        b'\x28\x01\x19\x85': ('cramfs_be', 'CramFS Big Endian'),
        b'\x85\x19': ('jffs2', 'JFFS2'),
        b'-rom1fs-': ('romfs', 'RomFS'),
        b'UBI#': ('ubi', 'UBI Image'),
        b'\x31\x18\x10\x06': ('ubifs', 'UBIFS'),
        b'\x7fELF': ('elf', 'ELF Executable'),
        b'ANDROID!': ('android', 'Android Boot Image'),
        b'\x88\x16\x88\x58': ('vxworks', 'VxWorks'),
    }
    
    def detect_type(self, data: bytes) -> Tuple[str, str]:
        """Detect firmware/file type from header"""
        for sig, (type_id, type_name) in self.SIGNATURES.items():
            if data.startswith(sig):
                return (type_id, type_name)
                
        # Extended checks
        if b'Linux' in data[:1024]:
            return ('linux', 'Linux Kernel')
            
        return ('unknown', 'Unknown')
        
    def parse_uboot_header(self, data: bytes) -> Optional[Dict]:
        """Parse U-Boot image header"""
        if not data.startswith(b'\x27\x05\x19\x56'):
            return None
            
        try:
            header = struct.unpack('>IIIIIIIBBBB32s', data[:64])
            
            return {
                'magic': hex(header[0]),
                'header_crc': header[1],
                'timestamp': datetime.fromtimestamp(header[2]),
                'data_size': header[3],
                'load_addr': hex(header[4]),
                'entry_point': hex(header[5]),
                'data_crc': header[6],
                'os': header[7],
                'arch': header[8],
                'image_type': header[9],
                'compression': header[10],
                'name': header[11].split(b'\x00')[0].decode('utf-8', errors='ignore')
            }
            
        except Exception as e:
            logger.error(f"Failed to parse U-Boot header: {e}")
            return None


class BinaryAnalyzer:
    """Binary code analyzer"""
    
    def __init__(self):
        self.dangerous_functions = {
            'strcpy': 'CWE-120: Buffer Copy without Checking Size',
            'strcat': 'CWE-120: Buffer Copy without Checking Size',
            'sprintf': 'CWE-120: Buffer Copy without Checking Size',
            'gets': 'CWE-120: Extremely Dangerous - gets()',
            'scanf': 'CWE-120: Format String Vulnerability Risk',
            'vsprintf': 'CWE-120: Buffer Copy without Checking Size',
            'system': 'CWE-78: OS Command Injection Risk',
            'popen': 'CWE-78: OS Command Injection Risk',
            'execve': 'CWE-78: OS Command Injection Risk',
            'execl': 'CWE-78: OS Command Injection Risk',
            'execlp': 'CWE-78: OS Command Injection Risk',
            'execle': 'CWE-78: OS Command Injection Risk',
            'execv': 'CWE-78: OS Command Injection Risk',
            'execvp': 'CWE-78: OS Command Injection Risk',
            'mktemp': 'CWE-377: Insecure Temporary File',
            'rand': 'CWE-330: Weak PRNG',
            'srand': 'CWE-330: Weak PRNG',
        }
        
    def detect_architecture(self, data: bytes) -> Architecture:
        """Detect architecture from ELF header"""
        if not data.startswith(b'\x7fELF'):
            return Architecture.UNKNOWN
            
        # ELF machine type at offset 18
        try:
            e_machine = struct.unpack('<H', data[18:20])[0]
            
            machine_map = {
                0x03: Architecture.X86,
                0x3E: Architecture.X86_64,
                0x28: Architecture.ARM,
                0xB7: Architecture.ARM64,
                0x08: Architecture.MIPS,
                0x14: Architecture.PPC,
            }
            
            return machine_map.get(e_machine, Architecture.UNKNOWN)
            
        except:
            return Architecture.UNKNOWN
            
    def detect_endianness(self, data: bytes) -> str:
        """Detect endianness from ELF"""
        if data.startswith(b'\x7fELF') and len(data) > 5:
            if data[5] == 1:
                return 'little'
            elif data[5] == 2:
                return 'big'
        return 'unknown'
        
    def find_strings(self, data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
        """Extract printable strings from binary"""
        strings = []
        current = []
        start_offset = 0
        
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                if not current:
                    start_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append((start_offset, ''.join(current)))
                current = []
                
        if len(current) >= min_length:
            strings.append((start_offset, ''.join(current)))
            
        return strings
        
    def find_function_references(self, data: bytes, strings: List[Tuple[int, str]]) -> List[Dict]:
        """Find references to dangerous functions"""
        findings = []
        
        for offset, s in strings:
            for func, cwe in self.dangerous_functions.items():
                if func in s or s == func:
                    findings.append({
                        'function': func,
                        'offset': hex(offset),
                        'context': s[:100],
                        'cwe': cwe
                    })
                    
        return findings


class FilesystemExtractor:
    """Filesystem extraction engine"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.extracted_files: List[ExtractedFile] = []
        
    async def extract(self, firmware_path: str, fs_type: FileSystemType) -> List[ExtractedFile]:
        """Extract filesystem contents"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        if fs_type == FileSystemType.SQUASHFS:
            return await self._extract_squashfs(firmware_path)
        elif fs_type == FileSystemType.CRAMFS:
            return await self._extract_cramfs(firmware_path)
        elif fs_type == FileSystemType.JFFS2:
            return await self._extract_jffs2(firmware_path)
        else:
            # Try binwalk-style extraction
            return await self._generic_extract(firmware_path)
            
    async def _extract_squashfs(self, path: str) -> List[ExtractedFile]:
        """Extract SquashFS filesystem"""
        try:
            # Try using unsquashfs
            result = await asyncio.create_subprocess_exec(
                'unsquashfs', '-d', os.path.join(self.output_dir, 'squashfs-root'),
                '-f', path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await result.wait()
            
            if result.returncode == 0:
                return self._enumerate_extracted(os.path.join(self.output_dir, 'squashfs-root'))
                
        except FileNotFoundError:
            logger.warning("unsquashfs not available")
            
        return []
        
    async def _extract_cramfs(self, path: str) -> List[ExtractedFile]:
        """Extract CramFS filesystem"""
        try:
            result = await asyncio.create_subprocess_exec(
                'cramfsck', '-x', os.path.join(self.output_dir, 'cramfs-root'),
                path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await result.wait()
            
            if result.returncode == 0:
                return self._enumerate_extracted(os.path.join(self.output_dir, 'cramfs-root'))
                
        except FileNotFoundError:
            logger.warning("cramfsck not available")
            
        return []
        
    async def _extract_jffs2(self, path: str) -> List[ExtractedFile]:
        """Extract JFFS2 filesystem"""
        try:
            result = await asyncio.create_subprocess_exec(
                'jefferson', '-d', os.path.join(self.output_dir, 'jffs2-root'),
                path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await result.wait()
            
            if result.returncode == 0:
                return self._enumerate_extracted(os.path.join(self.output_dir, 'jffs2-root'))
                
        except FileNotFoundError:
            logger.warning("jefferson not available")
            
        return []
        
    async def _generic_extract(self, path: str) -> List[ExtractedFile]:
        """Generic extraction using binwalk signatures"""
        # Manual signature-based extraction
        with open(path, 'rb') as f:
            data = f.read()
            
        # Find embedded filesystems
        fs_offsets = []
        
        # SquashFS
        for match in re.finditer(b'hsqs|sqsh', data):
            fs_offsets.append((match.start(), 'squashfs'))
            
        # Gzip
        for match in re.finditer(b'\x1f\x8b\x08', data):
            fs_offsets.append((match.start(), 'gzip'))
            
        # Extract each found filesystem
        for offset, fs_type in fs_offsets:
            output_path = os.path.join(self.output_dir, f'{fs_type}_{offset}')
            
            with open(output_path, 'wb') as f:
                f.write(data[offset:])
                
        return self._enumerate_extracted(self.output_dir)
        
    def _enumerate_extracted(self, root_dir: str) -> List[ExtractedFile]:
        """Enumerate extracted files"""
        files = []
        
        for dirpath, dirnames, filenames in os.walk(root_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(file_path, root_dir)
                
                try:
                    stat_info = os.stat(file_path)
                    
                    # Determine file type
                    with open(file_path, 'rb') as f:
                        header = f.read(256)
                        
                    file_type = self._detect_file_type(header, filename)
                    
                    # Calculate hash
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                        
                    extracted = ExtractedFile(
                        path=rel_path,
                        size=stat_info.st_size,
                        file_type=file_type,
                        permissions=oct(stat_info.st_mode)[-3:],
                        hash_sha256=file_hash,
                        is_executable=self._is_executable(header, filename),
                        is_script=self._is_script(filename),
                        is_config=self._is_config(filename),
                        interesting=self._is_interesting(rel_path, filename)
                    )
                    
                    files.append(extracted)
                    
                except Exception as e:
                    logger.debug(f"Error processing {file_path}: {e}")
                    
        self.extracted_files = files
        return files
        
    def _detect_file_type(self, header: bytes, filename: str) -> str:
        """Detect file type"""
        if header.startswith(b'\x7fELF'):
            return 'elf'
        elif header.startswith(b'#!'):
            return 'script'
        elif header.startswith(b'PK'):
            return 'zip'
        elif filename.endswith(('.so', '.so.0', '.so.1')):
            return 'shared_library'
        elif filename.endswith('.ko'):
            return 'kernel_module'
        elif filename.endswith('.conf'):
            return 'config'
        else:
            return 'data'
            
    def _is_executable(self, header: bytes, filename: str) -> bool:
        """Check if file is executable"""
        return header.startswith(b'\x7fELF') or header.startswith(b'#!')
        
    def _is_script(self, filename: str) -> bool:
        """Check if file is a script"""
        return filename.endswith(('.sh', '.py', '.pl', '.rb', '.lua', '.php'))
        
    def _is_config(self, filename: str) -> bool:
        """Check if file is a config file"""
        return filename.endswith(('.conf', '.cfg', '.ini', '.xml', '.json', '.yaml', '.yml'))
        
    def _is_interesting(self, path: str, filename: str) -> bool:
        """Check if file is security-relevant"""
        interesting_names = {
            'passwd', 'shadow', 'group', 'sudoers',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            '.pem', '.key', '.crt', '.cer', '.p12',
            'httpd.conf', 'nginx.conf', 'sshd_config',
            'hosts', 'resolv.conf', 'interfaces',
            'wpa_supplicant.conf', 'hostapd.conf',
            'rc.local', 'init.d', 'inittab',
            'dropbear', 'telnetd', 'ftpd'
        }
        
        return any(name in path.lower() for name in interesting_names)


class CredentialScanner:
    """Scan for hardcoded credentials"""
    
    def __init__(self):
        self.patterns = {
            'password': [
                r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']+)',
                r'PASSWORD\s*[=:]\s*["\']?([^\s"\']+)',
            ],
            'api_key': [
                r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{16,})',
                r'(?:secret|token)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{16,})',
            ],
            'username': [
                r'(?:username|user)\s*[=:]\s*["\']?([^\s"\']+)',
            ],
            'private_key': [
                r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            ]
        }
        
        # Common default credentials
        self.default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('root', 'toor'),
            ('admin', '1234'),
            ('user', 'user'),
            ('admin', ''),
            ('root', ''),
        ]
        
    def scan_file(self, file_path: str) -> List[HardcodedCredential]:
        """Scan file for credentials"""
        credentials = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                for cred_type, patterns in self.patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            value = match.group(1) if match.groups() else match.group(0)
                            
                            credentials.append(HardcodedCredential(
                                credential_type=cred_type,
                                password=value if cred_type == 'password' else '',
                                file_path=file_path,
                                line_number=line_num
                            ))
                            
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
            
        return credentials
        
    def scan_shadow_file(self, file_path: str) -> List[HardcodedCredential]:
        """Parse shadow file for password hashes"""
        credentials = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    
                    if len(parts) >= 2 and parts[1] not in ['*', '!', '!!', 'x']:
                        credentials.append(HardcodedCredential(
                            credential_type='shadow_hash',
                            username=parts[0],
                            hash_value=parts[1],
                            file_path=file_path
                        ))
                        
        except Exception as e:
            logger.debug(f"Error parsing shadow file: {e}")
            
        return credentials
        
    def detect_weak_passwords(self, hash_value: str) -> bool:
        """Check if hash is for a weak password"""
        # Check hash type
        if hash_value.startswith('$1$'):
            # MD5 - weak algorithm
            return True
        elif hash_value.startswith('$5$'):
            # SHA256
            return False
        elif hash_value.startswith('$6$'):
            # SHA512 - strong
            return False
            
        return False


class CryptoAnalyzer:
    """Analyze cryptographic usage"""
    
    def __init__(self):
        self.key_patterns = {
            'rsa_private': b'-----BEGIN RSA PRIVATE KEY-----',
            'ec_private': b'-----BEGIN EC PRIVATE KEY-----',
            'dsa_private': b'-----BEGIN DSA PRIVATE KEY-----',
            'private_key': b'-----BEGIN PRIVATE KEY-----',
            'encrypted_private': b'-----BEGIN ENCRYPTED PRIVATE KEY-----',
            'certificate': b'-----BEGIN CERTIFICATE-----',
            'public_key': b'-----BEGIN PUBLIC KEY-----',
        }
        
        self.weak_algorithms = {
            'DES', 'RC4', 'MD5', 'SHA1', 'RC2', 'BLOWFISH'
        }
        
    def scan_for_keys(self, data: bytes, file_path: str = "") -> List[CryptoKey]:
        """Scan for cryptographic keys"""
        keys = []
        
        for key_type, pattern in self.key_patterns.items():
            if pattern in data:
                keys.append(CryptoKey(
                    key_type=key_type,
                    file_path=file_path,
                    is_private='private' in key_type.lower()
                ))
                
        return keys
        
    def find_weak_crypto(self, data: bytes) -> List[Dict]:
        """Find weak cryptographic algorithm usage"""
        findings = []
        
        # Convert to string for searching
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = str(data)
            
        for algo in self.weak_algorithms:
            pattern = rf'\b{algo}\b'
            matches = re.finditer(pattern, text, re.IGNORECASE)
            
            for match in matches:
                context_start = max(0, match.start() - 50)
                context_end = min(len(text), match.end() + 50)
                
                findings.append({
                    'algorithm': algo,
                    'offset': match.start(),
                    'context': text[context_start:context_end]
                })
                
        return findings


class VulnerabilityScanner:
    """Scan for known vulnerabilities"""
    
    def __init__(self):
        self.known_vulns = self._load_vuln_patterns()
        
    def _load_vuln_patterns(self) -> Dict[str, Dict]:
        """Load vulnerability patterns"""
        return {
            'busybox_old': {
                'pattern': r'BusyBox v1\.[012][0-9]\.',
                'severity': 'high',
                'description': 'Outdated BusyBox version with known vulnerabilities',
                'cwe': 'CWE-1104'
            },
            'openssl_old': {
                'pattern': r'OpenSSL 0\.\d+|OpenSSL 1\.0\.[01]',
                'severity': 'critical',
                'description': 'Outdated OpenSSL version vulnerable to Heartbleed/POODLE',
                'cwe': 'CWE-327'
            },
            'dropbear_old': {
                'pattern': r'Dropbear sshd v0\.|Dropbear sshd v201[0-5]',
                'severity': 'high',
                'description': 'Outdated Dropbear SSH with known vulnerabilities',
                'cwe': 'CWE-1104'
            },
            'telnet_enabled': {
                'pattern': r'telnetd|/usr/sbin/telnetd',
                'severity': 'high',
                'description': 'Telnet service enabled (insecure protocol)',
                'cwe': 'CWE-319'
            },
            'ftp_enabled': {
                'pattern': r'ftpd|vsftpd|proftpd',
                'severity': 'medium',
                'description': 'FTP service present (insecure protocol)',
                'cwe': 'CWE-319'
            },
            'debug_symbols': {
                'pattern': r'__assert_fail|__stack_chk_fail',
                'severity': 'info',
                'description': 'Debug symbols present in binary',
                'cwe': 'CWE-489'
            }
        }
        
    def scan_file(self, file_path: str) -> List[FirmwareFinding]:
        """Scan file for vulnerability patterns"""
        findings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            text = data.decode('utf-8', errors='ignore')
            
            for vuln_id, vuln_info in self.known_vulns.items():
                if re.search(vuln_info['pattern'], text, re.IGNORECASE):
                    findings.append(FirmwareFinding(
                        finding_id=vuln_id,
                        title=vuln_id.replace('_', ' ').title(),
                        description=vuln_info['description'],
                        severity=SeverityLevel[vuln_info['severity'].upper()],
                        category='vulnerability',
                        file_path=file_path,
                        cwe_id=vuln_info.get('cwe')
                    ))
                    
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
            
        return findings


class FirmwareAnalysisEngine:
    """Main firmware analysis engine"""
    
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or tempfile.mkdtemp(prefix='firmware_')
        self.header_parser = FirmwareHeader()
        self.binary_analyzer = BinaryAnalyzer()
        self.cred_scanner = CredentialScanner()
        self.crypto_analyzer = CryptoAnalyzer()
        self.vuln_scanner = VulnerabilityScanner()
        self.extractor: Optional[FilesystemExtractor] = None
        
    async def analyze(self, firmware_path: str) -> Dict[str, Any]:
        """Perform comprehensive firmware analysis"""
        results = {
            'analysis_id': hashlib.md5(f"{firmware_path}{datetime.now()}".encode()).hexdigest()[:12],
            'timestamp': datetime.now().isoformat(),
            'firmware_path': firmware_path,
            'firmware_info': None,
            'extracted_files': [],
            'findings': [],
            'credentials': [],
            'crypto_keys': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Read firmware
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
            
        # Basic info
        firmware_info = FirmwareInfo(
            firmware_id=results['analysis_id'],
            filename=os.path.basename(firmware_path),
            file_size=len(firmware_data),
            file_hash_md5=hashlib.md5(firmware_data).hexdigest(),
            file_hash_sha256=hashlib.sha256(firmware_data).hexdigest(),
        )
        
        # Detect type and architecture
        type_id, type_name = self.header_parser.detect_type(firmware_data)
        firmware_info.architecture = self.binary_analyzer.detect_architecture(firmware_data)
        firmware_info.endianness = self.binary_analyzer.detect_endianness(firmware_data)
        
        # Parse headers
        if type_id == 'uImage':
            uboot_info = self.header_parser.parse_uboot_header(firmware_data)
            if uboot_info:
                firmware_info.build_date = uboot_info.get('timestamp')
                
        results['firmware_info'] = {
            'filename': firmware_info.filename,
            'size': firmware_info.file_size,
            'md5': firmware_info.file_hash_md5,
            'sha256': firmware_info.file_hash_sha256,
            'type': type_name,
            'architecture': firmware_info.architecture.value,
            'endianness': firmware_info.endianness
        }
        
        # Extract filesystem
        self.extractor = FilesystemExtractor(self.output_dir)
        
        # Detect filesystem type
        fs_type = self._detect_filesystem(firmware_data)
        extracted = await self.extractor.extract(firmware_path, fs_type)
        
        results['extracted_files'] = [
            {
                'path': f.path,
                'size': f.size,
                'type': f.file_type,
                'executable': f.is_executable,
                'interesting': f.interesting
            }
            for f in extracted
        ]
        
        # Scan extracted files
        for file_info in extracted:
            file_path = os.path.join(self.output_dir, file_info.path)
            
            if not os.path.exists(file_path):
                continue
                
            # Vulnerability scan
            vulns = self.vuln_scanner.scan_file(file_path)
            for vuln in vulns:
                results['findings'].append({
                    'id': vuln.finding_id,
                    'title': vuln.title,
                    'description': vuln.description,
                    'severity': vuln.severity.value,
                    'category': vuln.category,
                    'file': file_info.path,
                    'cwe': vuln.cwe_id
                })
                
            # Credential scan
            if file_info.is_config or file_info.is_script or 'shadow' in file_info.path.lower():
                if 'shadow' in file_info.path.lower():
                    creds = self.cred_scanner.scan_shadow_file(file_path)
                else:
                    creds = self.cred_scanner.scan_file(file_path)
                    
                for cred in creds:
                    results['credentials'].append({
                        'type': cred.credential_type,
                        'username': cred.username,
                        'file': cred.file_path,
                        'line': cred.line_number
                    })
                    
            # Crypto scan
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    
                keys = self.crypto_analyzer.scan_for_keys(file_data, file_info.path)
                for key in keys:
                    results['crypto_keys'].append({
                        'type': key.key_type,
                        'file': key.file_path,
                        'is_private': key.is_private
                    })
                    
            except:
                pass
                
        # Binary analysis for dangerous functions
        bin_findings = self.binary_analyzer.find_function_references(
            firmware_data,
            self.binary_analyzer.find_strings(firmware_data)
        )
        
        for finding in bin_findings:
            results['findings'].append({
                'id': f"FUNC_{finding['function']}",
                'title': f"Dangerous Function: {finding['function']}",
                'description': finding['cwe'],
                'severity': 'medium',
                'category': 'code_quality',
                'offset': finding['offset']
            })
            
        # Calculate summary
        for finding in results['findings']:
            severity = finding.get('severity', 'info').lower()
            if severity in results['summary']:
                results['summary'][severity] += 1
                
        return results
        
    def _detect_filesystem(self, data: bytes) -> FileSystemType:
        """Detect embedded filesystem type"""
        if b'hsqs' in data or b'sqsh' in data:
            return FileSystemType.SQUASHFS
        elif b'\x85\x19\x01\x28' in data or b'\x28\x01\x19\x85' in data:
            return FileSystemType.CRAMFS
        elif b'\x85\x19' in data:
            return FileSystemType.JFFS2
        elif b'UBI#' in data:
            return FileSystemType.UBIFS
        elif b'-rom1fs-' in data:
            return FileSystemType.ROMFS
            
        return FileSystemType.UNKNOWN
        
    def generate_report(self, results: Dict) -> str:
        """Generate analysis report"""
        report = []
        
        report.append("=" * 70)
        report.append("FIRMWARE SECURITY ANALYSIS REPORT")
        report.append("=" * 70)
        
        report.append(f"\nAnalysis ID: {results['analysis_id']}")
        report.append(f"Timestamp: {results['timestamp']}")
        
        fw_info = results.get('firmware_info', {})
        report.append(f"\n{'=' * 50}")
        report.append("FIRMWARE INFORMATION")
        report.append("=" * 50)
        report.append(f"Filename: {fw_info.get('filename', 'N/A')}")
        report.append(f"Size: {fw_info.get('size', 0)} bytes")
        report.append(f"MD5: {fw_info.get('md5', 'N/A')}")
        report.append(f"SHA256: {fw_info.get('sha256', 'N/A')}")
        report.append(f"Type: {fw_info.get('type', 'Unknown')}")
        report.append(f"Architecture: {fw_info.get('architecture', 'Unknown')}")
        report.append(f"Endianness: {fw_info.get('endianness', 'Unknown')}")
        
        report.append(f"\n{'=' * 50}")
        report.append("SUMMARY")
        report.append("=" * 50)
        summary = results.get('summary', {})
        report.append(f"Critical: {summary.get('critical', 0)}")
        report.append(f"High: {summary.get('high', 0)}")
        report.append(f"Medium: {summary.get('medium', 0)}")
        report.append(f"Low: {summary.get('low', 0)}")
        report.append(f"Info: {summary.get('info', 0)}")
        
        report.append(f"\n{'=' * 50}")
        report.append("SECURITY FINDINGS")
        report.append("=" * 50)
        
        for finding in results.get('findings', [])[:20]:
            report.append(f"\n[{finding['severity'].upper()}] {finding['title']}")
            report.append(f"  Description: {finding['description']}")
            if finding.get('file'):
                report.append(f"  File: {finding['file']}")
            if finding.get('cwe'):
                report.append(f"  CWE: {finding['cwe']}")
                
        # Credentials
        creds = results.get('credentials', [])
        if creds:
            report.append(f"\n{'=' * 50}")
            report.append("HARDCODED CREDENTIALS")
            report.append("=" * 50)
            
            for cred in creds[:10]:
                report.append(f"\n[{cred['type'].upper()}]")
                if cred.get('username'):
                    report.append(f"  Username: {cred['username']}")
                report.append(f"  File: {cred['file']}")
                
        # Crypto keys
        keys = results.get('crypto_keys', [])
        if keys:
            report.append(f"\n{'=' * 50}")
            report.append("CRYPTOGRAPHIC KEYS")
            report.append("=" * 50)
            
            for key in keys:
                status = "PRIVATE KEY" if key['is_private'] else "Certificate/Public"
                report.append(f"\n[{status}] {key['type']}")
                report.append(f"  File: {key['file']}")
                
        report.append(f"\n{'=' * 50}")
        report.append("RECOMMENDATIONS")
        report.append("=" * 50)
        
        recommendations = [
            "Update outdated software components",
            "Remove hardcoded credentials and use secure key management",
            "Disable insecure services (telnet, FTP)",
            "Strip debug symbols from production firmware",
            "Implement secure boot with signature verification",
            "Encrypt sensitive data and configuration",
            "Use modern cryptographic algorithms (AES-256, SHA-256+)",
            "Implement firmware integrity verification"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            report.append(f"\n{i}. {rec}")
            
        return "\n".join(report)


class AdvancedFirmwareAnalysis:
    """Main integration class for firmware analysis"""
    
    def __init__(self):
        self.engine: Optional[FirmwareAnalysisEngine] = None
        
    async def analyze_firmware(self, firmware_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Analyze firmware file"""
        self.engine = FirmwareAnalysisEngine(output_dir)
        return await self.engine.analyze(firmware_path)
        
    def generate_report(self, results: Dict) -> str:
        """Generate analysis report"""
        if self.engine:
            return self.engine.generate_report(results)
        return "No analysis results available"
