"""
HydraRecon Advanced API Security Testing Module
Comprehensive REST, GraphQL, gRPC, and WebSocket API security analysis
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlencode, urlparse, parse_qs
import logging

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

logger = logging.getLogger(__name__)


class APIType(Enum):
    """API types"""
    REST = "rest"
    GRAPHQL = "graphql"
    GRPC = "grpc"
    WEBSOCKET = "websocket"
    SOAP = "soap"
    JSONRPC = "jsonrpc"


class AuthType(Enum):
    """Authentication types"""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    HMAC = "hmac"
    MUTUAL_TLS = "mutual_tls"


class VulnerabilityType(Enum):
    """API vulnerability types"""
    BROKEN_AUTH = "broken_authentication"
    BROKEN_ACCESS = "broken_access_control"
    INJECTION = "injection"
    EXCESSIVE_DATA = "excessive_data_exposure"
    RATE_LIMITING = "lack_of_rate_limiting"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIG = "security_misconfiguration"
    IMPROPER_ASSETS = "improper_assets_management"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    LOGGING_MONITORING = "insufficient_logging"
    SSRF = "ssrf"
    BOLA = "bola"
    BFLA = "bfla"
    INFORMATION_DISCLOSURE = "information_disclosure"


class SeverityLevel(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class APIEndpoint:
    """API endpoint information"""
    method: str
    path: str
    full_url: str
    api_type: APIType = APIType.REST
    auth_type: AuthType = AuthType.NONE
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[Any] = None
    response_codes: List[int] = field(default_factory=list)
    content_types: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class APIVulnerability:
    """API vulnerability finding"""
    vuln_id: str
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    endpoint: APIEndpoint
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    owasp_category: Optional[str] = None
    cvss_score: float = 0.0
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class JWTAnalysis:
    """JWT token analysis result"""
    token: str
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    algorithm: str = ""
    is_expired: bool = False
    expiry_time: Optional[datetime] = None
    vulnerabilities: List[str] = field(default_factory=list)
    claims: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphQLSchema:
    """GraphQL schema information"""
    types: List[Dict[str, Any]] = field(default_factory=list)
    queries: List[Dict[str, Any]] = field(default_factory=list)
    mutations: List[Dict[str, Any]] = field(default_factory=list)
    subscriptions: List[Dict[str, Any]] = field(default_factory=list)
    directives: List[Dict[str, Any]] = field(default_factory=list)


class APIDiscovery:
    """API endpoint discovery engine"""
    
    def __init__(self, base_url: str, auth_headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_headers = auth_headers or {}
        self.discovered_endpoints: List[APIEndpoint] = []
        self.wordlist = self._load_wordlist()
        
    def _load_wordlist(self) -> List[str]:
        """Load API endpoint wordlist"""
        return [
            # Common API paths
            'api', 'v1', 'v2', 'v3', 'api/v1', 'api/v2', 'api/v3',
            # Authentication
            'auth', 'login', 'logout', 'register', 'signup', 'signin',
            'oauth', 'token', 'refresh', 'forgot-password', 'reset-password',
            'verify', 'confirm', '2fa', 'mfa', 'sso',
            # Users
            'users', 'user', 'profile', 'account', 'me', 'admin', 'admins',
            'members', 'roles', 'permissions', 'groups',
            # Resources
            'posts', 'articles', 'comments', 'products', 'items', 'orders',
            'payments', 'invoices', 'transactions', 'reports', 'analytics',
            'notifications', 'messages', 'files', 'uploads', 'images',
            # Operations
            'search', 'filter', 'sort', 'export', 'import', 'download',
            'upload', 'delete', 'update', 'create', 'read', 'list',
            # Special
            'health', 'status', 'ping', 'version', 'info', 'docs',
            'swagger', 'openapi', 'graphql', 'graphiql', 'playground',
            'debug', 'test', 'dev', 'internal', 'private', 'public',
            # Config/Admin
            'config', 'settings', 'options', 'preferences', 'admin/users',
            'admin/config', 'admin/settings', 'manage', 'dashboard',
            # WebSockets
            'ws', 'websocket', 'socket', 'realtime', 'live', 'stream',
            # Misc
            'callback', 'webhook', 'hook', 'notify', 'batch', 'bulk',
        ]
        
    async def discover_endpoints(self) -> List[APIEndpoint]:
        """Discover API endpoints"""
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available")
            return []
            
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for path in self.wordlist:
                url = f"{self.base_url}/{path}"
                tasks.append(self._probe_endpoint(session, url))
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, APIEndpoint):
                    self.discovered_endpoints.append(result)
                    
        return self.discovered_endpoints
        
    async def _probe_endpoint(self, session: aiohttp.ClientSession, 
                             url: str) -> Optional[APIEndpoint]:
        """Probe single endpoint"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            try:
                headers = {**self.auth_headers, 'Accept': 'application/json'}
                
                async with session.request(method, url, headers=headers, 
                                          timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status not in [404, 405, 503]:
                        return APIEndpoint(
                            method=method,
                            path=urlparse(url).path,
                            full_url=url,
                            response_codes=[resp.status],
                            content_types=[resp.headers.get('Content-Type', '')]
                        )
                        
            except Exception:
                pass
                
        return None
        
    async def discover_graphql(self) -> Optional[GraphQLSchema]:
        """Discover GraphQL schema via introspection"""
        if not AIOHTTP_AVAILABLE:
            return None
            
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args { name type { name kind } }
                type { name kind }
              }
            }
          }
        }
        """
        
        graphql_endpoints = [
            f"{self.base_url}/graphql",
            f"{self.base_url}/api/graphql",
            f"{self.base_url}/query",
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in graphql_endpoints:
                try:
                    async with session.post(
                        endpoint,
                        json={'query': introspection_query},
                        headers={**self.auth_headers, 'Content-Type': 'application/json'}
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if 'data' in data and '__schema' in data['data']:
                                return self._parse_graphql_schema(data['data']['__schema'])
                                
                except Exception:
                    pass
                    
        return None
        
    def _parse_graphql_schema(self, schema: Dict[str, Any]) -> GraphQLSchema:
        """Parse GraphQL schema"""
        gql_schema = GraphQLSchema()
        
        gql_schema.types = schema.get('types', [])
        
        # Extract queries, mutations, subscriptions
        for type_info in gql_schema.types:
            if type_info.get('name') == 'Query':
                gql_schema.queries = type_info.get('fields', [])
            elif type_info.get('name') == 'Mutation':
                gql_schema.mutations = type_info.get('fields', [])
            elif type_info.get('name') == 'Subscription':
                gql_schema.subscriptions = type_info.get('fields', [])
                
        return gql_schema


class JWTAnalyzer:
    """JWT token security analyzer"""
    
    def __init__(self):
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'key',
            'jwt_secret', 'jwt', 'token', 'supersecret',
        ]
        
    def analyze_token(self, token: str) -> JWTAnalysis:
        """Analyze JWT token for vulnerabilities"""
        parts = token.split('.')
        
        if len(parts) != 3:
            return JWTAnalysis(token=token, vulnerabilities=['Invalid JWT format'])
            
        try:
            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            # Decode payload
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            analysis = JWTAnalysis(
                token=token,
                header=header,
                payload=payload,
                signature=parts[2],
                algorithm=header.get('alg', 'unknown'),
                claims=payload
            )
            
            # Check for vulnerabilities
            self._check_vulnerabilities(analysis)
            
            # Check expiry
            if 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                analysis.expiry_time = exp_time
                analysis.is_expired = exp_time < datetime.now()
                if analysis.is_expired:
                    analysis.vulnerabilities.append('Token is expired')
                    
            return analysis
            
        except Exception as e:
            return JWTAnalysis(token=token, vulnerabilities=[f'Parse error: {str(e)}'])
            
    def _check_vulnerabilities(self, analysis: JWTAnalysis):
        """Check for JWT vulnerabilities"""
        alg = analysis.algorithm.lower()
        
        # Algorithm vulnerabilities
        if alg == 'none':
            analysis.vulnerabilities.append('Algorithm "none" is used (CVE-2015-9235)')
        elif alg == 'hs256' and analysis.header.get('typ', '').upper() == 'JWT':
            analysis.vulnerabilities.append('HS256 may be vulnerable to key confusion attacks')
        elif alg in ['hs384', 'hs512']:
            analysis.vulnerabilities.append('Symmetric algorithm used - ensure secret is strong')
            
        # Header vulnerabilities
        if 'kid' in analysis.header:
            kid = analysis.header['kid']
            if '../' in kid or '..\\' in kid:
                analysis.vulnerabilities.append('Path traversal in kid header')
            if kid.startswith('http://') or kid.startswith('https://'):
                analysis.vulnerabilities.append('URL in kid header - potential SSRF')
                
        if 'jku' in analysis.header:
            analysis.vulnerabilities.append('JKU header present - potential key injection')
            
        if 'jwk' in analysis.header:
            analysis.vulnerabilities.append('Embedded JWK - potential key forgery')
            
        if 'x5u' in analysis.header:
            analysis.vulnerabilities.append('X5U header present - potential certificate injection')
            
        # Payload vulnerabilities
        if 'admin' in analysis.payload and analysis.payload.get('admin'):
            analysis.vulnerabilities.append('Admin claim is set to true')
            
        if 'role' in analysis.payload and 'admin' in str(analysis.payload['role']).lower():
            analysis.vulnerabilities.append('Role claim contains admin')
            
        # Check for missing claims
        if 'iat' not in analysis.payload:
            analysis.vulnerabilities.append('Missing iat (issued at) claim')
        if 'exp' not in analysis.payload:
            analysis.vulnerabilities.append('Missing exp (expiration) claim')
        if 'nbf' not in analysis.payload:
            analysis.vulnerabilities.append('Missing nbf (not before) claim')
            
    def try_weak_secrets(self, token: str) -> Optional[str]:
        """Try to crack JWT with weak secrets"""
        if not JWT_AVAILABLE:
            return None
            
        parts = token.split('.')
        if len(parts) != 3:
            return None
            
        for secret in self.weak_secrets:
            try:
                jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                return secret
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue
                
        return None
        
    def generate_none_algorithm_token(self, payload: Dict[str, Any]) -> str:
        """Generate token with none algorithm (for testing)"""
        header = {"alg": "none", "typ": "JWT"}
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()
        
        return f"{header_b64}.{payload_b64}."


class APISecurityScanner:
    """API security vulnerability scanner"""
    
    def __init__(self, base_url: str, auth_headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_headers = auth_headers or {}
        self.vulnerabilities: List[APIVulnerability] = []
        self.jwt_analyzer = JWTAnalyzer()
        
    async def scan_endpoint(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Scan single endpoint for vulnerabilities"""
        vulns = []
        
        # Authentication tests
        vulns.extend(await self._test_authentication(endpoint))
        
        # Authorization tests (BOLA/BFLA)
        vulns.extend(await self._test_authorization(endpoint))
        
        # Injection tests
        vulns.extend(await self._test_injection(endpoint))
        
        # Rate limiting tests
        vulns.extend(await self._test_rate_limiting(endpoint))
        
        # Mass assignment tests
        vulns.extend(await self._test_mass_assignment(endpoint))
        
        # Information disclosure tests
        vulns.extend(await self._test_info_disclosure(endpoint))
        
        # Security headers
        vulns.extend(await self._test_security_headers(endpoint))
        
        self.vulnerabilities.extend(vulns)
        return vulns
        
    async def _test_authentication(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test authentication vulnerabilities"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        async with aiohttp.ClientSession() as session:
            # Test without authentication
            try:
                async with session.request(
                    endpoint.method,
                    endpoint.full_url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        vulns.append(APIVulnerability(
                            vuln_id=f"AUTH-BYPASS-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                            vuln_type=VulnerabilityType.BROKEN_AUTH,
                            severity=SeverityLevel.HIGH,
                            title="Endpoint Accessible Without Authentication",
                            description=f"Endpoint {endpoint.path} is accessible without authentication",
                            endpoint=endpoint,
                            owasp_category="API2:2023",
                            remediation="Implement proper authentication for this endpoint"
                        ))
            except Exception:
                pass
                
        return vulns
        
    async def _test_authorization(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test authorization vulnerabilities (BOLA/BFLA)"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        # Check for ID parameters in URL
        id_pattern = r'/(\d+)/?'
        match = re.search(id_pattern, endpoint.path)
        
        if match:
            original_id = match.group(1)
            test_ids = ['1', '2', '100', '999', '0', '-1']
            
            async with aiohttp.ClientSession() as session:
                for test_id in test_ids:
                    if test_id == original_id:
                        continue
                        
                    test_url = endpoint.full_url.replace(f'/{original_id}', f'/{test_id}')
                    
                    try:
                        headers = {**self.auth_headers}
                        async with session.request(
                            endpoint.method,
                            test_url,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if resp.status == 200:
                                vulns.append(APIVulnerability(
                                    vuln_id=f"BOLA-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                                    vuln_type=VulnerabilityType.BOLA,
                                    severity=SeverityLevel.HIGH,
                                    title="Broken Object Level Authorization (BOLA)",
                                    description=f"Endpoint accepts different object IDs: {original_id} -> {test_id}",
                                    endpoint=endpoint,
                                    evidence={'original_id': original_id, 'test_id': test_id},
                                    owasp_category="API1:2023",
                                    remediation="Implement proper object-level authorization checks"
                                ))
                                break
                    except Exception:
                        pass
                        
        return vulns
        
    async def _test_injection(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test injection vulnerabilities"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        injection_payloads = {
            'sql': ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT * FROM users--"],
            'nosql': ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}'],
            'ldap': ['*)(uid=*', '*)(&', '*))%00'],
            'xpath': ["' or '1'='1", "x' or name()='username' or 'x'='y"],
            'command': ['; ls -la', '| cat /etc/passwd', '`id`', '$(id)'],
        }
        
        async with aiohttp.ClientSession() as session:
            for injection_type, payloads in injection_payloads.items():
                for payload in payloads[:2]:  # Limit payloads
                    # Try in query parameters
                    test_url = f"{endpoint.full_url}?id={payload}"
                    
                    try:
                        async with session.request(
                            endpoint.method,
                            test_url,
                            headers=self.auth_headers,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            response_text = await resp.text()
                            
                            # Check for error-based indicators
                            error_indicators = [
                                'sql', 'syntax', 'mysql', 'postgresql', 'oracle',
                                'ldap', 'xpath', 'command', 'shell', 'bash',
                                'error', 'exception', 'stacktrace', 'traceback'
                            ]
                            
                            if any(ind in response_text.lower() for ind in error_indicators):
                                vulns.append(APIVulnerability(
                                    vuln_id=f"INJ-{injection_type.upper()}-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                                    vuln_type=VulnerabilityType.INJECTION,
                                    severity=SeverityLevel.CRITICAL,
                                    title=f"Potential {injection_type.upper()} Injection",
                                    description=f"Endpoint may be vulnerable to {injection_type} injection",
                                    endpoint=endpoint,
                                    evidence={'payload': payload, 'response_contains_error': True},
                                    owasp_category="API8:2023",
                                    remediation=f"Implement proper input validation and parameterized queries"
                                ))
                                break
                    except Exception:
                        pass
                        
        return vulns
        
    async def _test_rate_limiting(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test rate limiting"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        request_count = 50
        success_count = 0
        
        async with aiohttp.ClientSession() as session:
            for _ in range(request_count):
                try:
                    async with session.request(
                        endpoint.method,
                        endpoint.full_url,
                        headers=self.auth_headers,
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as resp:
                        if resp.status != 429:
                            success_count += 1
                except Exception:
                    pass
                    
        if success_count >= request_count * 0.9:  # 90% success = no rate limiting
            vulns.append(APIVulnerability(
                vuln_id=f"RATE-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                vuln_type=VulnerabilityType.RATE_LIMITING,
                severity=SeverityLevel.MEDIUM,
                title="No Rate Limiting",
                description=f"Endpoint accepts {success_count}/{request_count} requests without rate limiting",
                endpoint=endpoint,
                evidence={'requests_sent': request_count, 'successful': success_count},
                owasp_category="API4:2023",
                remediation="Implement rate limiting based on IP and/or user identity"
            ))
            
        return vulns
        
    async def _test_mass_assignment(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test mass assignment vulnerabilities"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        if endpoint.method not in ['POST', 'PUT', 'PATCH']:
            return vulns
            
        # Try adding sensitive fields
        sensitive_fields = {
            'admin': True,
            'role': 'admin',
            'is_admin': True,
            'permissions': ['all'],
            'verified': True,
            'balance': 999999,
            'credits': 999999,
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                headers = {**self.auth_headers, 'Content-Type': 'application/json'}
                
                async with session.request(
                    endpoint.method,
                    endpoint.full_url,
                    headers=headers,
                    json=sensitive_fields,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in [200, 201]:
                        response_data = await resp.json()
                        
                        # Check if sensitive fields were accepted
                        for field, value in sensitive_fields.items():
                            if field in str(response_data) and str(value) in str(response_data):
                                vulns.append(APIVulnerability(
                                    vuln_id=f"MASS-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                                    vuln_type=VulnerabilityType.MASS_ASSIGNMENT,
                                    severity=SeverityLevel.HIGH,
                                    title="Mass Assignment Vulnerability",
                                    description=f"Endpoint accepts sensitive field: {field}",
                                    endpoint=endpoint,
                                    evidence={'field': field, 'value': value},
                                    owasp_category="API6:2023",
                                    remediation="Implement field whitelisting and filter sensitive properties"
                                ))
                                break
            except Exception:
                pass
                
        return vulns
        
    async def _test_info_disclosure(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test information disclosure"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    endpoint.method,
                    endpoint.full_url,
                    headers=self.auth_headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    response_text = await resp.text()
                    headers = dict(resp.headers)
                    
                    # Check for sensitive information in response
                    sensitive_patterns = {
                        r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b': 'email',
                        r'\b\d{3}-\d{2}-\d{4}\b': 'ssn',
                        r'\b(?:\d{4}[-\s]?){4}\b': 'credit_card',
                        r'password["\s:=]+["\']?[^"\']+': 'password',
                        r'api[_-]?key["\s:=]+["\']?[^"\']+': 'api_key',
                        r'secret["\s:=]+["\']?[^"\']+': 'secret',
                    }
                    
                    for pattern, info_type in sensitive_patterns.items():
                        if re.search(pattern, response_text, re.IGNORECASE):
                            vulns.append(APIVulnerability(
                                vuln_id=f"DISCLOSURE-{info_type}-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                                vuln_type=VulnerabilityType.EXCESSIVE_DATA,
                                severity=SeverityLevel.MEDIUM,
                                title=f"Potential {info_type.replace('_', ' ').title()} Disclosure",
                                description=f"Response may contain {info_type} information",
                                endpoint=endpoint,
                                owasp_category="API3:2023",
                                remediation="Review response data and filter sensitive information"
                            ))
                            break
                            
                    # Check verbose headers
                    verbose_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version']
                    for header in verbose_headers:
                        if header in headers:
                            vulns.append(APIVulnerability(
                                vuln_id=f"HEADER-{header.replace('-', '_')}-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                                vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                severity=SeverityLevel.LOW,
                                title=f"Verbose Header: {header}",
                                description=f"Response includes {header}: {headers[header]}",
                                endpoint=endpoint,
                                evidence={'header': header, 'value': headers[header]},
                                remediation=f"Remove or sanitize {header} header"
                            ))
                            
            except Exception:
                pass
                
        return vulns
        
    async def _test_security_headers(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test security headers"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        required_headers = {
            'Content-Security-Policy': 'CSP',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'X-Frame-Options': 'X-Frame-Options',
            'Strict-Transport-Security': 'HSTS',
            'X-XSS-Protection': 'XSS Protection',
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    endpoint.method,
                    endpoint.full_url,
                    headers=self.auth_headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    response_headers = dict(resp.headers)
                    
                    for header, name in required_headers.items():
                        if header not in response_headers:
                            vulns.append(APIVulnerability(
                                vuln_id=f"SECHEADER-{header.replace('-', '_')}-{hashlib.md5(endpoint.full_url.encode()).hexdigest()[:8]}",
                                vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                                severity=SeverityLevel.LOW,
                                title=f"Missing Security Header: {name}",
                                description=f"Response is missing {header} header",
                                endpoint=endpoint,
                                remediation=f"Add {header} response header"
                            ))
                            
            except Exception:
                pass
                
        return vulns


class GraphQLSecurityScanner:
    """GraphQL-specific security scanner"""
    
    def __init__(self, endpoint: str, auth_headers: Optional[Dict[str, str]] = None):
        self.endpoint = endpoint
        self.auth_headers = auth_headers or {}
        self.vulnerabilities: List[APIVulnerability] = []
        
    async def scan(self) -> List[APIVulnerability]:
        """Scan GraphQL endpoint"""
        vulns = []
        
        vulns.extend(await self._test_introspection())
        vulns.extend(await self._test_query_depth())
        vulns.extend(await self._test_batching())
        vulns.extend(await self._test_field_suggestions())
        
        self.vulnerabilities = vulns
        return vulns
        
    async def _test_introspection(self) -> List[APIVulnerability]:
        """Test if introspection is enabled"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        query = '{ __schema { types { name } } }'
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    self.endpoint,
                    json={'query': query},
                    headers={**self.auth_headers, 'Content-Type': 'application/json'}
                ) as resp:
                    data = await resp.json()
                    
                    if 'data' in data and '__schema' in data.get('data', {}):
                        vulns.append(APIVulnerability(
                            vuln_id=f"GQL-INTROSPECTION-{hashlib.md5(self.endpoint.encode()).hexdigest()[:8]}",
                            vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                            severity=SeverityLevel.MEDIUM,
                            title="GraphQL Introspection Enabled",
                            description="GraphQL introspection is enabled, exposing schema information",
                            endpoint=APIEndpoint(
                                method='POST',
                                path=urlparse(self.endpoint).path,
                                full_url=self.endpoint,
                                api_type=APIType.GRAPHQL
                            ),
                            remediation="Disable introspection in production"
                        ))
            except Exception:
                pass
                
        return vulns
        
    async def _test_query_depth(self) -> List[APIVulnerability]:
        """Test for query depth attacks"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        # Deep nested query
        deep_query = '{ a' + '{ b' * 50 + ' }' * 50 + ' }'
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    self.endpoint,
                    json={'query': deep_query},
                    headers={**self.auth_headers, 'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        vulns.append(APIVulnerability(
                            vuln_id=f"GQL-DEPTH-{hashlib.md5(self.endpoint.encode()).hexdigest()[:8]}",
                            vuln_type=VulnerabilityType.RATE_LIMITING,
                            severity=SeverityLevel.MEDIUM,
                            title="No Query Depth Limit",
                            description="GraphQL endpoint accepts deeply nested queries",
                            endpoint=APIEndpoint(
                                method='POST',
                                path=urlparse(self.endpoint).path,
                                full_url=self.endpoint,
                                api_type=APIType.GRAPHQL
                            ),
                            remediation="Implement query depth limiting"
                        ))
            except asyncio.TimeoutError:
                # Server may have crashed or timed out
                vulns.append(APIVulnerability(
                    vuln_id=f"GQL-DOS-{hashlib.md5(self.endpoint.encode()).hexdigest()[:8]}",
                    vuln_type=VulnerabilityType.RATE_LIMITING,
                    severity=SeverityLevel.HIGH,
                    title="GraphQL DoS via Deep Query",
                    description="Deep nested queries cause server timeout",
                    endpoint=APIEndpoint(
                        method='POST',
                        path=urlparse(self.endpoint).path,
                        full_url=self.endpoint,
                        api_type=APIType.GRAPHQL
                    ),
                    remediation="Implement query depth and complexity limits"
                ))
            except Exception:
                pass
                
        return vulns
        
    async def _test_batching(self) -> List[APIVulnerability]:
        """Test for batch query attacks"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        # Batch query
        batch_query = [{'query': '{ __typename }'} for _ in range(100)]
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    self.endpoint,
                    json=batch_query,
                    headers={**self.auth_headers, 'Content-Type': 'application/json'}
                ) as resp:
                    if resp.status == 200:
                        vulns.append(APIVulnerability(
                            vuln_id=f"GQL-BATCH-{hashlib.md5(self.endpoint.encode()).hexdigest()[:8]}",
                            vuln_type=VulnerabilityType.RATE_LIMITING,
                            severity=SeverityLevel.MEDIUM,
                            title="GraphQL Batching Allowed",
                            description="GraphQL endpoint accepts batch queries without limits",
                            endpoint=APIEndpoint(
                                method='POST',
                                path=urlparse(self.endpoint).path,
                                full_url=self.endpoint,
                                api_type=APIType.GRAPHQL
                            ),
                            remediation="Limit batch query size"
                        ))
            except Exception:
                pass
                
        return vulns
        
    async def _test_field_suggestions(self) -> List[APIVulnerability]:
        """Test for field suggestion information disclosure"""
        vulns = []
        
        if not AIOHTTP_AVAILABLE:
            return vulns
            
        query = '{ useer }'  # Intentional typo
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    self.endpoint,
                    json={'query': query},
                    headers={**self.auth_headers, 'Content-Type': 'application/json'}
                ) as resp:
                    data = await resp.json()
                    response_text = json.dumps(data)
                    
                    if 'did you mean' in response_text.lower():
                        vulns.append(APIVulnerability(
                            vuln_id=f"GQL-SUGGEST-{hashlib.md5(self.endpoint.encode()).hexdigest()[:8]}",
                            vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                            severity=SeverityLevel.LOW,
                            title="GraphQL Field Suggestions Enabled",
                            description="GraphQL provides field suggestions in errors",
                            endpoint=APIEndpoint(
                                method='POST',
                                path=urlparse(self.endpoint).path,
                                full_url=self.endpoint,
                                api_type=APIType.GRAPHQL
                            ),
                            remediation="Disable field suggestions in production"
                        ))
            except Exception:
                pass
                
        return vulns


class AdvancedAPISecurityTesting:
    """Main API security testing integration"""
    
    def __init__(self, base_url: str, auth_headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url
        self.auth_headers = auth_headers or {}
        self.discovery = APIDiscovery(base_url, auth_headers)
        self.scanner = APISecurityScanner(base_url, auth_headers)
        self.jwt_analyzer = JWTAnalyzer()
        self.graphql_scanner: Optional[GraphQLSecurityScanner] = None
        
    async def full_assessment(self) -> Dict[str, Any]:
        """Perform full API security assessment"""
        results = {
            'base_url': self.base_url,
            'timestamp': datetime.now().isoformat(),
            'endpoints': [],
            'vulnerabilities': [],
            'jwt_analysis': [],
            'graphql_analysis': None,
            'summary': {
                'total_endpoints': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Discover endpoints
        endpoints = await self.discovery.discover_endpoints()
        results['summary']['total_endpoints'] = len(endpoints)
        
        for endpoint in endpoints:
            results['endpoints'].append({
                'method': endpoint.method,
                'path': endpoint.path,
                'url': endpoint.full_url,
                'response_codes': endpoint.response_codes
            })
            
            # Scan each endpoint
            vulns = await self.scanner.scan_endpoint(endpoint)
            
            for vuln in vulns:
                results['vulnerabilities'].append({
                    'id': vuln.vuln_id,
                    'type': vuln.vuln_type.value,
                    'severity': vuln.severity.value,
                    'title': vuln.title,
                    'description': vuln.description,
                    'endpoint': vuln.endpoint.path,
                    'owasp': vuln.owasp_category,
                    'remediation': vuln.remediation
                })
                results['summary'][vuln.severity.value] += 1
                
        # Check for GraphQL
        graphql_schema = await self.discovery.discover_graphql()
        if graphql_schema:
            self.graphql_scanner = GraphQLSecurityScanner(
                f"{self.base_url}/graphql",
                self.auth_headers
            )
            graphql_vulns = await self.graphql_scanner.scan()
            
            results['graphql_analysis'] = {
                'types_count': len(graphql_schema.types),
                'queries_count': len(graphql_schema.queries),
                'mutations_count': len(graphql_schema.mutations),
                'vulnerabilities': [
                    {
                        'id': v.vuln_id,
                        'title': v.title,
                        'severity': v.severity.value
                    }
                    for v in graphql_vulns
                ]
            }
            
            for vuln in graphql_vulns:
                results['summary'][vuln.severity.value] += 1
                
        return results
        
    def analyze_jwt(self, token: str) -> Dict[str, Any]:
        """Analyze JWT token"""
        analysis = self.jwt_analyzer.analyze_token(token)
        
        return {
            'algorithm': analysis.algorithm,
            'header': analysis.header,
            'payload': analysis.payload,
            'is_expired': analysis.is_expired,
            'expiry_time': analysis.expiry_time.isoformat() if analysis.expiry_time else None,
            'vulnerabilities': analysis.vulnerabilities
        }
        
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate security report"""
        report = []
        
        report.append("=" * 60)
        report.append("API SECURITY ASSESSMENT REPORT")
        report.append("=" * 60)
        
        report.append(f"\nTarget: {results['base_url']}")
        report.append(f"Scan Time: {results['timestamp']}")
        
        report.append(f"\n{'=' * 40}")
        report.append("SUMMARY")
        report.append("=" * 40)
        
        summary = results['summary']
        report.append(f"Endpoints Discovered: {summary['total_endpoints']}")
        report.append(f"\nVulnerabilities:")
        report.append(f"  Critical: {summary['critical']}")
        report.append(f"  High: {summary['high']}")
        report.append(f"  Medium: {summary['medium']}")
        report.append(f"  Low: {summary['low']}")
        
        for severity in ['critical', 'high', 'medium']:
            severity_vulns = [v for v in results['vulnerabilities'] if v['severity'] == severity]
            
            if severity_vulns:
                report.append(f"\n{'=' * 40}")
                report.append(f"{severity.upper()} VULNERABILITIES")
                report.append("=" * 40)
                
                for vuln in severity_vulns:
                    report.append(f"\n[{vuln['id']}] {vuln['title']}")
                    report.append(f"  Endpoint: {vuln['endpoint']}")
                    report.append(f"  Type: {vuln['type']}")
                    if vuln['owasp']:
                        report.append(f"  OWASP: {vuln['owasp']}")
                    report.append(f"  Remediation: {vuln['remediation']}")
                    
        return "\n".join(report)
