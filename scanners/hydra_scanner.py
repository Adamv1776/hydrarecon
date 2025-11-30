#!/usr/bin/env python3
"""
HydraRecon Hydra Brute-Force Scanner Module
Advanced Hydra integration with support for multiple protocols.
"""

import asyncio
import re
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import subprocess
from pathlib import Path

from .base import BaseScanner, ScanResult, ScanStatus


class HydraProtocol(Enum):
    """Supported Hydra protocols"""
    SSH = "ssh"
    FTP = "ftp"
    TELNET = "telnet"
    HTTP_GET = "http-get"
    HTTP_POST = "http-post"
    HTTP_FORM_GET = "http-form-get"
    HTTP_FORM_POST = "http-form-post"
    HTTPS_GET = "https-get"
    HTTPS_POST = "https-post"
    HTTPS_FORM_GET = "https-form-get"
    HTTPS_FORM_POST = "https-form-post"
    SMB = "smb"
    SMBNT = "smbnt"
    MYSQL = "mysql"
    MSSQL = "mssql"
    POSTGRES = "postgres"
    ORACLE = "oracle"
    VNC = "vnc"
    RDP = "rdp"
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"
    LDAP = "ldap"
    LDAPS = "ldaps"
    SNMP = "snmp"
    REDIS = "redis"
    MONGODB = "mongodb"
    MEMCACHED = "memcached"
    CISCO = "cisco"
    CISCO_ENABLE = "cisco-enable"


@dataclass
class HydraCredential:
    """Discovered credential from Hydra"""
    host: str
    port: int
    protocol: str
    username: str
    password: str
    discovered_at: datetime = field(default_factory=datetime.now)
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HydraTarget:
    """Hydra target configuration"""
    host: str
    port: int
    protocol: str
    service_path: str = ""  # For HTTP paths
    form_params: Dict[str, str] = field(default_factory=dict)  # For form attacks
    additional_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HydraScanResult:
    """Complete Hydra scan result"""
    target: HydraTarget
    command: str
    start_time: datetime
    end_time: Optional[datetime] = None
    credentials: List[HydraCredential] = field(default_factory=list)
    attempts: int = 0
    successful: int = 0
    failed: int = 0
    status: str = "pending"
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)


class HydraScanner(BaseScanner):
    """Advanced Hydra brute-force scanner"""
    
    DEFAULT_PORTS = {
        "ssh": 22,
        "ftp": 21,
        "telnet": 23,
        "http-get": 80,
        "http-post": 80,
        "http-form-get": 80,
        "http-form-post": 80,
        "https-get": 443,
        "https-post": 443,
        "https-form-get": 443,
        "https-form-post": 443,
        "smb": 445,
        "smbnt": 445,
        "mysql": 3306,
        "mssql": 1433,
        "postgres": 5432,
        "oracle": 1521,
        "vnc": 5900,
        "rdp": 3389,
        "smtp": 25,
        "pop3": 110,
        "imap": 143,
        "ldap": 389,
        "ldaps": 636,
        "snmp": 161,
        "redis": 6379,
        "mongodb": 27017,
        "memcached": 11211,
        "cisco": 23,
        "cisco-enable": 23
    }
    
    ATTACK_MODES = {
        'single_user': {
            'name': 'Single Username',
            'description': 'Attack with a single username against password list'
        },
        'single_pass': {
            'name': 'Single Password',
            'description': 'Attack with a single password against username list'
        },
        'combo': {
            'name': 'Combo Attack',
            'description': 'Attack with username:password combo file'
        },
        'spray': {
            'name': 'Password Spray',
            'description': 'Try each password against all users before next password'
        },
        'smart': {
            'name': 'Smart Attack',
            'description': 'Intelligent username/password correlation'
        }
    }
    
    def __init__(self, config, db):
        super().__init__(config, db)
        self.hydra_path = config.hydra.path
        self.hydra_available = False
        self.hydra_version = "unknown"
        self._verify_hydra()
        self._builtin_wordlists = self._init_builtin_wordlists()
    
    @property
    def scanner_name(self) -> str:
        return "Hydra Brute-Force Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "hydra"
    
    def _verify_hydra(self):
        """Verify Hydra is installed and accessible"""
        try:
            result = subprocess.run(
                [self.hydra_path, '-h'],
                capture_output=True, text=True, timeout=10
            )
            # Hydra returns non-zero even for help, check if output contains expected text
            if 'hydra' in result.stdout.lower() or 'hydra' in result.stderr.lower():
                self.hydra_available = True
                # Try to get version
                version_match = re.search(r'v(\d+\.\d+)', result.stdout + result.stderr)
                if version_match:
                    self.hydra_version = version_match.group(1)
                else:
                    self.hydra_version = "unknown"
            else:
                self.hydra_available = False
                
        except FileNotFoundError:
            self.hydra_available = False
        except subprocess.TimeoutExpired:
            self.hydra_available = False
        except Exception:
            self.hydra_available = False
    
    def _init_builtin_wordlists(self) -> Dict[str, Dict[str, str]]:
        """Initialize paths to common built-in wordlists"""
        wordlists = {
            'usernames': {
                'common': '/usr/share/wordlists/common-usernames.txt',
                'admin': '/usr/share/wordlists/admin-usernames.txt',
                'default': '/usr/share/wordlists/default-usernames.txt',
                'custom': str(self.config.wordlists_dir / 'usernames.txt')
            },
            'passwords': {
                'rockyou': '/usr/share/wordlists/rockyou.txt',
                'common': '/usr/share/wordlists/common-passwords.txt',
                'default': '/usr/share/wordlists/default-passwords.txt',
                'top1000': '/usr/share/wordlists/top1000.txt',
                'custom': str(self.config.wordlists_dir / 'passwords.txt')
            }
        }
        return wordlists
    
    async def validate_target(self, target: str) -> bool:
        """Validate target format"""
        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
        
        return bool(re.match(ip_pattern, target) or re.match(hostname_pattern, target))
    
    def build_command(self, target: HydraTarget,
                     usernames: List[str] = None,
                     passwords: List[str] = None,
                     username_file: str = None,
                     password_file: str = None,
                     combo_file: str = None,
                     tasks: int = None,
                     timeout: int = None,
                     exit_on_first: bool = None,
                     verbose: bool = None,
                     additional_args: List[str] = None,
                     output_file: str = None) -> List[str]:
        """Build Hydra command"""
        cmd = [self.hydra_path]
        
        # Verbosity
        if verbose is None:
            verbose = self.config.hydra.verbose
        if verbose:
            cmd.append('-v')
        
        # Exit on first found
        if exit_on_first is None:
            exit_on_first = self.config.hydra.exit_on_first
        if exit_on_first:
            cmd.append('-f')
        
        # Tasks (parallel connections)
        tasks = tasks or self.config.hydra.tasks
        cmd.extend(['-t', str(tasks)])
        
        # Timeout
        timeout = timeout or self.config.hydra.timeout
        cmd.extend(['-w', str(timeout)])
        
        # Usernames
        if usernames:
            if len(usernames) == 1:
                cmd.extend(['-l', usernames[0]])
            else:
                # Write to temp file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                    f.write('\n'.join(usernames))
                    cmd.extend(['-L', f.name])
        elif username_file:
            cmd.extend(['-L', username_file])
        
        # Passwords
        if passwords:
            if len(passwords) == 1:
                cmd.extend(['-p', passwords[0]])
            else:
                # Write to temp file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                    f.write('\n'.join(passwords))
                    cmd.extend(['-P', f.name])
        elif password_file:
            cmd.extend(['-P', password_file])
        
        # Combo file (user:pass format)
        if combo_file:
            cmd.extend(['-C', combo_file])
        
        # Output file
        if output_file:
            cmd.extend(['-o', output_file])
        
        # Additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        # Target specification
        cmd.extend(['-s', str(target.port)])
        cmd.append(target.host)
        
        # Protocol
        protocol = target.protocol
        
        # Handle HTTP forms specially
        if 'form' in protocol.lower():
            if target.form_params:
                form_spec = self._build_form_spec(target)
                cmd.append(f"{protocol}:{form_spec}")
            else:
                cmd.append(protocol)
        elif target.service_path:
            cmd.append(f"{protocol}:{target.service_path}")
        else:
            cmd.append(protocol)
        
        return cmd
    
    def _build_form_spec(self, target: HydraTarget) -> str:
        """Build HTTP form specification for Hydra"""
        params = target.form_params
        
        path = params.get('path', '/')
        user_field = params.get('user_field', 'username')
        pass_field = params.get('pass_field', 'password')
        fail_string = params.get('fail_string', 'Invalid')
        
        # Format: /path:user_field=^USER^&pass_field=^PASS^:F=fail_string
        form_data = f"{user_field}=^USER^&{pass_field}=^PASS^"
        
        # Add any additional parameters
        for key, value in params.items():
            if key not in ['path', 'user_field', 'pass_field', 'fail_string', 'success_string']:
                form_data += f"&{key}={value}"
        
        if 'success_string' in params:
            return f"{path}:{form_data}:S={params['success_string']}"
        else:
            return f"{path}:{form_data}:F={fail_string}"
    
    async def scan(self, target: str, protocol: str = "ssh",
                   port: int = None, **options) -> ScanResult:
        """Execute Hydra brute-force attack"""
        
        if not self.hydra_available:
            return ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.FAILED,
                started_at=datetime.now(),
                errors=["Hydra is not installed or not found. Install with: sudo apt install hydra"]
            )
        
        if not await self.validate_target(target):
            return ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.FAILED,
                started_at=datetime.now(),
                errors=["Invalid target format"]
            )
        
        # Resolve port
        if port is None:
            port = self.DEFAULT_PORTS.get(protocol, 22)
        
        # Create target object
        hydra_target = HydraTarget(
            host=target,
            port=port,
            protocol=protocol,
            service_path=options.get('service_path', ''),
            form_params=options.get('form_params', {})
        )
        
        self.status = ScanStatus.RUNNING
        start_time = datetime.now()
        
        # Create output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name
        
        try:
            # Build command
            cmd = self.build_command(
                hydra_target,
                usernames=options.get('usernames'),
                passwords=options.get('passwords'),
                username_file=options.get('username_file'),
                password_file=options.get('password_file'),
                combo_file=options.get('combo_file'),
                tasks=options.get('tasks'),
                timeout=options.get('timeout'),
                exit_on_first=options.get('exit_on_first'),
                verbose=options.get('verbose'),
                additional_args=options.get('additional_args'),
                output_file=output_file
            )
            
            self.emit_progress(0, 100, f"Starting brute-force: {target}:{port}/{protocol}", "initializing")
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if self.is_cancelled():
                return ScanResult(
                    scan_id=self.scan_id,
                    scan_type=self.scanner_type,
                    target=target,
                    status=ScanStatus.CANCELLED,
                    started_at=start_time
                )
            
            # Parse results
            hydra_result = self._parse_output(
                stdout.decode() if stdout else "",
                output_file,
                hydra_target,
                start_time
            )
            hydra_result.command = ' '.join(cmd)
            
            # Convert to generic ScanResult
            result = ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.COMPLETED if hydra_result.status == "completed" else ScanStatus.FAILED,
                started_at=start_time,
                completed_at=datetime.now(),
                data=self._hydra_result_to_dict(hydra_result),
                findings=[
                    {
                        'type': 'credential',
                        'host': cred.host,
                        'port': cred.port,
                        'protocol': cred.protocol,
                        'username': cred.username,
                        'password': cred.password,
                        'severity': 'critical'
                    }
                    for cred in hydra_result.credentials
                ],
                raw_output=hydra_result.raw_output
            )
            
            # Store credentials in database
            await self._store_credentials(result, hydra_result)
            
            cred_count = len(hydra_result.credentials)
            self.emit_progress(
                100, 100,
                f"Completed: Found {cred_count} credential(s)",
                "completed"
            )
            
            return result
            
        except Exception as e:
            return ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.FAILED,
                started_at=start_time,
                errors=[str(e)]
            )
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def _parse_output(self, stdout: str, output_file: str,
                      target: HydraTarget, start_time: datetime) -> HydraScanResult:
        """Parse Hydra output"""
        result = HydraScanResult(
            target=target,
            command="",
            start_time=start_time,
            end_time=datetime.now(),
            raw_output=stdout
        )
        
        # Parse credentials from stdout
        # Format: [port][protocol] host:ip   login: username   password: password
        cred_pattern = r'\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)'
        
        for match in re.finditer(cred_pattern, stdout, re.IGNORECASE):
            port, protocol, host, username, password = match.groups()
            result.credentials.append(HydraCredential(
                host=host,
                port=int(port),
                protocol=protocol,
                username=username,
                password=password
            ))
        
        # Also check output file
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(':')
                            if len(parts) >= 4:
                                # Format: host:port:login:password
                                host, port, login, password = parts[:4]
                                # Check if already found
                                existing = [c for c in result.credentials
                                           if c.username == login and c.password == password]
                                if not existing:
                                    result.credentials.append(HydraCredential(
                                        host=host,
                                        port=int(port),
                                        protocol=target.protocol,
                                        username=login,
                                        password=password
                                    ))
            except Exception:
                pass
        
        # Parse statistics
        attempts_match = re.search(r'(\d+) valid password', stdout, re.IGNORECASE)
        if attempts_match:
            result.successful = int(attempts_match.group(1))
        
        result.status = "completed"
        
        return result
    
    def _hydra_result_to_dict(self, result: HydraScanResult) -> Dict[str, Any]:
        """Convert HydraScanResult to dictionary"""
        return {
            'command': result.command,
            'start_time': result.start_time.isoformat(),
            'end_time': result.end_time.isoformat() if result.end_time else None,
            'target': {
                'host': result.target.host,
                'port': result.target.port,
                'protocol': result.target.protocol,
                'service_path': result.target.service_path
            },
            'credentials': [
                {
                    'host': c.host,
                    'port': c.port,
                    'protocol': c.protocol,
                    'username': c.username,
                    'password': c.password,
                    'discovered_at': c.discovered_at.isoformat()
                }
                for c in result.credentials
            ],
            'statistics': {
                'attempts': result.attempts,
                'successful': result.successful,
                'failed': result.failed
            },
            'status': result.status,
            'errors': result.errors
        }
    
    async def _store_credentials(self, scan_result: ScanResult, hydra_result: HydraScanResult):
        """Store discovered credentials in database"""
        # Would be implemented to store in database
        pass
    
    async def attack_ssh(self, target: str, port: int = 22, **options) -> ScanResult:
        """SSH brute-force attack"""
        return await self.scan(target, protocol="ssh", port=port, **options)
    
    async def attack_ftp(self, target: str, port: int = 21, **options) -> ScanResult:
        """FTP brute-force attack"""
        return await self.scan(target, protocol="ftp", port=port, **options)
    
    async def attack_http_form(self, target: str, port: int = 80,
                               form_params: Dict[str, str] = None, **options) -> ScanResult:
        """HTTP form brute-force attack"""
        return await self.scan(
            target,
            protocol="http-form-post",
            port=port,
            form_params=form_params or {},
            **options
        )
    
    async def attack_mysql(self, target: str, port: int = 3306, **options) -> ScanResult:
        """MySQL brute-force attack"""
        return await self.scan(target, protocol="mysql", port=port, **options)
    
    async def attack_rdp(self, target: str, port: int = 3389, **options) -> ScanResult:
        """RDP brute-force attack"""
        return await self.scan(target, protocol="rdp", port=port, **options)
    
    def get_supported_protocols(self) -> List[str]:
        """Get list of supported protocols"""
        return [p.value for p in HydraProtocol]
    
    def get_default_port(self, protocol: str) -> int:
        """Get default port for a protocol"""
        return self.DEFAULT_PORTS.get(protocol, 0)
    
    def get_attack_modes(self) -> Dict[str, Dict[str, str]]:
        """Get available attack modes"""
        return self.ATTACK_MODES.copy()
    
    def get_wordlists(self) -> Dict[str, Dict[str, str]]:
        """Get available wordlists"""
        return self._builtin_wordlists.copy()
