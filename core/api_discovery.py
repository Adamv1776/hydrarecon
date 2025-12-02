"""
Advanced API Endpoint Discovery Engine
Automated REST/GraphQL/SOAP API discovery and testing
"""

import asyncio
import aiohttp
import json
import re
import ssl
import hashlib
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from enum import Enum
import xml.etree.ElementTree as ET


class APIType(Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    GRPC = "grpc"
    WEBSOCKET = "websocket"
    JSONRPC = "json-rpc"
    UNKNOWN = "unknown"


class AuthType(Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    CUSTOM = "custom"


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint"""
    url: str
    method: str
    api_type: APIType
    auth_type: AuthType = AuthType.NONE
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    response_type: str = ""
    status_code: int = 0
    response_time: float = 0.0
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    vulnerabilities: List[str] = field(default_factory=list)
    documentation: str = ""
    rate_limit: Optional[Dict[str, Any]] = None
    cors_config: Optional[Dict[str, Any]] = None


@dataclass
class APISchema:
    """API Schema/Documentation structure"""
    title: str
    version: str
    description: str
    base_url: str
    endpoints: List[APIEndpoint]
    auth_schemes: List[Dict[str, Any]]
    schemas: Dict[str, Any]
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


class APIDiscoveryEngine:
    """
    Advanced API Discovery Engine
    Discovers, documents, and tests API endpoints
    """
    
    # Common API paths to check
    COMMON_API_PATHS = [
        # REST API common paths
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/v1", "/v2", "/v3",
        "/api/latest", "/api/current",
        
        # Documentation endpoints
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api-docs.json",
        "/docs", "/documentation",
        "/swagger-ui", "/swagger-ui.html",
        "/redoc",
        
        # GraphQL
        "/graphql", "/graphql/console",
        "/graphiql", "/playground",
        "/api/graphql", "/v1/graphql",
        
        # SOAP/WSDL
        "/wsdl", "/service.wsdl",
        "/soap", "/services",
        "?wsdl", "?WSDL",
        
        # Health/Status endpoints
        "/health", "/healthz", "/healthcheck",
        "/status", "/ping", "/ready",
        "/actuator", "/actuator/health",
        "/actuator/info", "/actuator/env",
        
        # Admin/Debug endpoints
        "/admin", "/admin/api",
        "/debug", "/debug/vars",
        "/metrics", "/prometheus",
        "/internal", "/_internal",
        
        # Auth endpoints
        "/auth", "/oauth", "/oauth2",
        "/login", "/logout", "/register",
        "/token", "/refresh", "/verify",
        "/.well-known/openid-configuration",
        
        # Common resource paths
        "/users", "/user", "/profile",
        "/accounts", "/account",
        "/items", "/products", "/orders",
        "/data", "/info", "/config",
        "/settings", "/preferences",
        "/search", "/query",
        "/upload", "/download", "/files",
        "/images", "/media", "/assets",
        "/webhooks", "/callbacks",
        "/events", "/notifications",
    ]
    
    # HTTP methods to test
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    
    # Common API parameters
    COMMON_PARAMS = [
        "id", "user_id", "userId", "uid",
        "page", "limit", "offset", "size",
        "sort", "order", "filter", "search",
        "q", "query", "keyword", "term",
        "token", "key", "api_key", "apiKey",
        "format", "type", "fields", "include",
        "start", "end", "from", "to", "date",
        "callback", "jsonp",
    ]
    
    def __init__(self, concurrency: int = 20, timeout: int = 10):
        self.concurrency = concurrency
        self.timeout = timeout
        self.discovered_endpoints: List[APIEndpoint] = []
        self.schemas: List[APISchema] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        
    async def __aenter__(self):
        await self.start()
        return self
        
    async def __aexit__(self, *args):
        await self.close()
        
    async def start(self):
        """Initialize the discovery engine"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json, application/xml, text/html, */*",
            }
        )
        self._semaphore = asyncio.Semaphore(self.concurrency)
        
    async def close(self):
        """Close the session"""
        if self.session:
            await self.session.close()
            
    async def discover(self, base_url: str, 
                       custom_paths: Optional[List[str]] = None,
                       wordlist: Optional[str] = None,
                       deep_scan: bool = False) -> Dict[str, Any]:
        """
        Main discovery function
        """
        results = {
            "target": base_url,
            "scan_time": datetime.now().isoformat(),
            "api_type": APIType.UNKNOWN.value,
            "endpoints": [],
            "schemas": [],
            "auth_detected": [],
            "technologies": [],
            "vulnerabilities": [],
            "statistics": {}
        }
        
        # Normalize base URL
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")
        
        # Build path list
        paths = list(self.COMMON_API_PATHS)
        if custom_paths:
            paths.extend(custom_paths)
        if wordlist:
            paths.extend(await self._load_wordlist(wordlist))
            
        # Phase 1: Initial reconnaissance
        print(f"[*] Phase 1: Initial reconnaissance on {base_url}")
        base_info = await self._analyze_base_url(base_url)
        results["technologies"] = base_info.get("technologies", [])
        
        # Phase 2: Schema discovery
        print("[*] Phase 2: Discovering API schemas...")
        schemas = await self._discover_schemas(base_url)
        for schema in schemas:
            results["schemas"].append(schema.__dict__)
            # Extract endpoints from schemas
            for endpoint in schema.endpoints:
                self.discovered_endpoints.append(endpoint)
                
        # Phase 3: Path enumeration
        print(f"[*] Phase 3: Enumerating {len(paths)} paths...")
        path_tasks = [self._probe_path(base_url, path) for path in paths]
        path_results = await asyncio.gather(*path_tasks, return_exceptions=True)
        
        for result in path_results:
            if isinstance(result, APIEndpoint):
                self.discovered_endpoints.append(result)
                
        # Phase 4: Deep scan if enabled
        if deep_scan:
            print("[*] Phase 4: Deep scanning discovered endpoints...")
            await self._deep_scan_endpoints()
            
        # Phase 5: Security analysis
        print("[*] Phase 5: Analyzing security configurations...")
        await self._analyze_security(base_url)
        
        # Compile results
        for endpoint in self.discovered_endpoints:
            results["endpoints"].append({
                "url": endpoint.url,
                "method": endpoint.method,
                "api_type": endpoint.api_type.value,
                "auth_type": endpoint.auth_type.value,
                "status_code": endpoint.status_code,
                "response_time": endpoint.response_time,
                "parameters": endpoint.parameters,
                "vulnerabilities": endpoint.vulnerabilities,
                "cors_config": endpoint.cors_config,
            })
            
        # Determine primary API type
        api_types = [e.api_type for e in self.discovered_endpoints]
        if api_types:
            from collections import Counter
            most_common = Counter(api_types).most_common(1)
            if most_common:
                results["api_type"] = most_common[0][0].value
                
        # Statistics
        results["statistics"] = {
            "total_endpoints": len(self.discovered_endpoints),
            "by_method": self._count_by_method(),
            "by_status": self._count_by_status(),
            "by_auth": self._count_by_auth(),
            "vulnerable_endpoints": len([e for e in self.discovered_endpoints if e.vulnerabilities]),
        }
        
        return results
        
    async def _analyze_base_url(self, url: str) -> Dict[str, Any]:
        """Analyze the base URL for technology fingerprinting"""
        info = {"technologies": [], "headers": {}, "cookies": []}
        
        async with self._semaphore:
            try:
                async with self.session.get(url) as response:
                    headers = dict(response.headers)
                    info["headers"] = headers
                    
                    # Technology detection
                    tech_patterns = {
                        "nginx": r"nginx",
                        "Apache": r"Apache",
                        "Express": r"Express",
                        "Django": r"Django|csrftoken",
                        "Flask": r"Werkzeug",
                        "ASP.NET": r"ASP\.NET|X-AspNet",
                        "Spring": r"X-Application-Context",
                        "Laravel": r"laravel_session",
                        "Rails": r"X-Powered-By.*Phusion|_rails",
                        "Node.js": r"X-Powered-By.*Express",
                        "PHP": r"X-Powered-By.*PHP|PHPSESSID",
                        "Cloudflare": r"cloudflare|cf-ray",
                        "AWS": r"x-amz|AmazonS3",
                        "Kong": r"Kong|via.*kong",
                    }
                    
                    header_str = json.dumps(headers)
                    for tech, pattern in tech_patterns.items():
                        if re.search(pattern, header_str, re.IGNORECASE):
                            info["technologies"].append(tech)
                            
            except Exception:
                pass
                
        return info
        
    async def _discover_schemas(self, base_url: str) -> List[APISchema]:
        """Discover API documentation schemas"""
        schemas = []
        
        schema_endpoints = [
            ("/swagger.json", "swagger"),
            ("/swagger.yaml", "swagger"),
            ("/openapi.json", "openapi"),
            ("/openapi.yaml", "openapi"),
            ("/api-docs", "swagger"),
            ("/api-docs.json", "swagger"),
            ("/v2/api-docs", "swagger"),
            ("/v3/api-docs", "openapi"),
            ("/.well-known/openapi.json", "openapi"),
            ("/graphql", "graphql"),
        ]
        
        for path, schema_type in schema_endpoints:
            url = urljoin(base_url, path)
            schema = await self._fetch_schema(url, schema_type)
            if schema:
                schemas.append(schema)
                
        return schemas
        
    async def _fetch_schema(self, url: str, schema_type: str) -> Optional[APISchema]:
        """Fetch and parse API schema"""
        async with self._semaphore:
            try:
                # For GraphQL, try introspection
                if schema_type == "graphql":
                    return await self._introspect_graphql(url)
                    
                async with self.session.get(url) as response:
                    if response.status != 200:
                        return None
                        
                    content = await response.text()
                    
                    # Parse based on content type
                    if url.endswith(".yaml") or url.endswith(".yml"):
                        import yaml
                        data = yaml.safe_load(content)
                    else:
                        data = json.loads(content)
                        
                    return self._parse_openapi_schema(data, url)
                    
            except Exception:
                return None
                
    def _parse_openapi_schema(self, data: Dict, source_url: str) -> Optional[APISchema]:
        """Parse OpenAPI/Swagger schema"""
        try:
            info = data.get("info", {})
            
            # Determine base URL from servers or host
            base_url = ""
            if "servers" in data:
                base_url = data["servers"][0].get("url", "")
            elif "host" in data:
                scheme = data.get("schemes", ["https"])[0]
                base_url = f"{scheme}://{data['host']}{data.get('basePath', '')}"
                
            endpoints = []
            paths = data.get("paths", {})
            
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in self.HTTP_METHODS:
                        endpoint = APIEndpoint(
                            url=urljoin(base_url or source_url, path),
                            method=method.upper(),
                            api_type=APIType.REST,
                            parameters=self._extract_parameters(details),
                            documentation=details.get("summary", details.get("description", "")),
                        )
                        
                        # Check security requirements
                        if details.get("security") or data.get("security"):
                            endpoint.auth_type = AuthType.BEARER  # Simplified
                            
                        endpoints.append(endpoint)
                        
            return APISchema(
                title=info.get("title", "Unknown API"),
                version=info.get("version", "1.0"),
                description=info.get("description", ""),
                base_url=base_url,
                endpoints=endpoints,
                auth_schemes=list(data.get("securityDefinitions", data.get("components", {}).get("securitySchemes", {})).values()),
                schemas=data.get("definitions", data.get("components", {}).get("schemas", {})),
            )
            
        except Exception:
            return None
            
    def _extract_parameters(self, operation: Dict) -> Dict[str, Any]:
        """Extract parameters from OpenAPI operation"""
        params = {"query": [], "path": [], "header": [], "body": None}
        
        for param in operation.get("parameters", []):
            param_in = param.get("in", "query")
            if param_in in params:
                if isinstance(params[param_in], list):
                    params[param_in].append({
                        "name": param.get("name"),
                        "type": param.get("type", param.get("schema", {}).get("type")),
                        "required": param.get("required", False),
                    })
                    
        # Handle request body
        if "requestBody" in operation:
            params["body"] = operation["requestBody"]
            
        return params
        
    async def _introspect_graphql(self, url: str) -> Optional[APISchema]:
        """Perform GraphQL introspection"""
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type {
            ...TypeRef
          }
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        """
        
        async with self._semaphore:
            try:
                async with self.session.post(
                    url,
                    json={"query": introspection_query},
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status != 200:
                        return None
                        
                    data = await response.json()
                    
                    if "errors" in data:
                        return None
                        
                    schema_data = data.get("data", {}).get("__schema", {})
                    
                    endpoints = []
                    types = schema_data.get("types", [])
                    
                    for type_def in types:
                        if type_def.get("name", "").startswith("__"):
                            continue
                            
                        fields = type_def.get("fields") or []
                        for field in fields:
                            endpoint = APIEndpoint(
                                url=url,
                                method="POST",
                                api_type=APIType.GRAPHQL,
                                parameters={
                                    "field": field.get("name"),
                                    "type": type_def.get("name"),
                                    "args": field.get("args", []),
                                },
                                documentation=field.get("description", ""),
                            )
                            endpoints.append(endpoint)
                            
                    return APISchema(
                        title="GraphQL API",
                        version="1.0",
                        description="GraphQL API discovered via introspection",
                        base_url=url,
                        endpoints=endpoints,
                        auth_schemes=[],
                        schemas={"types": types},
                    )
                    
            except Exception:
                return None
                
    async def _probe_path(self, base_url: str, path: str) -> Optional[APIEndpoint]:
        """Probe a single path"""
        url = urljoin(base_url, path)
        
        async with self._semaphore:
            try:
                start_time = datetime.now()
                
                async with self.session.get(url) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    
                    if response.status in [200, 201, 204, 301, 302, 401, 403]:
                        content_type = response.headers.get("Content-Type", "")
                        
                        # Determine API type from response
                        api_type = APIType.UNKNOWN
                        if "application/json" in content_type:
                            api_type = APIType.REST
                        elif "application/xml" in content_type or "text/xml" in content_type:
                            api_type = APIType.SOAP
                        elif "graphql" in path.lower():
                            api_type = APIType.GRAPHQL
                            
                        # Detect auth type
                        auth_type = AuthType.NONE
                        if response.status in [401, 403]:
                            www_auth = response.headers.get("WWW-Authenticate", "")
                            if "Bearer" in www_auth:
                                auth_type = AuthType.BEARER
                            elif "Basic" in www_auth:
                                auth_type = AuthType.BASIC
                            else:
                                auth_type = AuthType.CUSTOM
                                
                        return APIEndpoint(
                            url=url,
                            method="GET",
                            api_type=api_type,
                            auth_type=auth_type,
                            status_code=response.status,
                            response_time=elapsed,
                            response_type=content_type,
                            headers=dict(response.headers),
                        )
                        
            except Exception:
                pass
                
        return None
        
    async def _deep_scan_endpoints(self):
        """Deep scan discovered endpoints for more details"""
        for endpoint in self.discovered_endpoints:
            # Try different HTTP methods
            for method in self.HTTP_METHODS:
                if method != endpoint.method:
                    new_endpoint = await self._probe_method(endpoint.url, method)
                    if new_endpoint and new_endpoint.status_code not in [404, 405]:
                        self.discovered_endpoints.append(new_endpoint)
                        
            # Parameter fuzzing
            await self._fuzz_parameters(endpoint)
            
    async def _probe_method(self, url: str, method: str) -> Optional[APIEndpoint]:
        """Probe a URL with a specific HTTP method"""
        async with self._semaphore:
            try:
                start_time = datetime.now()
                
                request_method = getattr(self.session, method.lower())
                async with request_method(url) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    
                    return APIEndpoint(
                        url=url,
                        method=method,
                        api_type=APIType.REST,
                        status_code=response.status,
                        response_time=elapsed,
                    )
                    
            except Exception:
                pass
                
        return None
        
    async def _fuzz_parameters(self, endpoint: APIEndpoint):
        """Fuzz common parameters on an endpoint"""
        for param in self.COMMON_PARAMS:
            test_url = f"{endpoint.url}?{param}=test"
            
            async with self._semaphore:
                try:
                    async with self.session.get(test_url) as response:
                        if response.status in [200, 201]:
                            if param not in endpoint.parameters:
                                endpoint.parameters[param] = "string"
                except Exception:
                    pass
                    
    async def _analyze_security(self, base_url: str):
        """Analyze security configurations"""
        for endpoint in self.discovered_endpoints:
            vulnerabilities = []
            
            # CORS analysis
            cors_config = await self._check_cors(endpoint.url)
            endpoint.cors_config = cors_config
            
            if cors_config:
                if cors_config.get("allow_origin") == "*":
                    vulnerabilities.append("CORS: Wildcard origin allowed")
                if cors_config.get("allow_credentials") and cors_config.get("allow_origin") == "*":
                    vulnerabilities.append("CORS: Credentials allowed with wildcard origin")
                    
            # Check for information disclosure
            if any(path in endpoint.url for path in ["/debug", "/actuator", "/env", "/config"]):
                vulnerabilities.append("Potential information disclosure endpoint")
                
            # Check for missing auth on sensitive endpoints
            if endpoint.auth_type == AuthType.NONE:
                if any(path in endpoint.url.lower() for path in ["/admin", "/user", "/account", "/internal"]):
                    vulnerabilities.append("Sensitive endpoint without authentication")
                    
            # Check rate limiting
            if not endpoint.rate_limit:
                vulnerabilities.append("No rate limiting detected")
                
            endpoint.vulnerabilities = vulnerabilities
            
    async def _check_cors(self, url: str) -> Optional[Dict[str, Any]]:
        """Check CORS configuration"""
        async with self._semaphore:
            try:
                headers = {"Origin": "https://evil.com"}
                async with self.session.options(url, headers=headers) as response:
                    cors_headers = {
                        "allow_origin": response.headers.get("Access-Control-Allow-Origin"),
                        "allow_methods": response.headers.get("Access-Control-Allow-Methods"),
                        "allow_headers": response.headers.get("Access-Control-Allow-Headers"),
                        "allow_credentials": response.headers.get("Access-Control-Allow-Credentials"),
                        "max_age": response.headers.get("Access-Control-Max-Age"),
                    }
                    return cors_headers if any(cors_headers.values()) else None
            except Exception:
                return None
                
    async def _load_wordlist(self, path: str) -> List[str]:
        """Load custom wordlist"""
        try:
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            return []
            
    def _count_by_method(self) -> Dict[str, int]:
        """Count endpoints by HTTP method"""
        counts = {}
        for endpoint in self.discovered_endpoints:
            counts[endpoint.method] = counts.get(endpoint.method, 0) + 1
        return counts
        
    def _count_by_status(self) -> Dict[int, int]:
        """Count endpoints by status code"""
        counts = {}
        for endpoint in self.discovered_endpoints:
            counts[endpoint.status_code] = counts.get(endpoint.status_code, 0) + 1
        return counts
        
    def _count_by_auth(self) -> Dict[str, int]:
        """Count endpoints by auth type"""
        counts = {}
        for endpoint in self.discovered_endpoints:
            auth = endpoint.auth_type.value
            counts[auth] = counts.get(auth, 0) + 1
        return counts


class APISecurityTester:
    """
    API Security Testing Engine
    Tests discovered APIs for common vulnerabilities
    """
    
    def __init__(self, discovery_engine: APIDiscoveryEngine):
        self.discovery = discovery_engine
        self.findings: List[Dict[str, Any]] = []
        
    async def run_security_tests(self, endpoints: List[APIEndpoint]) -> List[Dict[str, Any]]:
        """Run comprehensive security tests on discovered endpoints"""
        tests = [
            self._test_authentication_bypass,
            self._test_injection,
            self._test_rate_limiting,
            self._test_verbose_errors,
            self._test_mass_assignment,
            self._test_broken_object_level_auth,
        ]
        
        for endpoint in endpoints:
            for test in tests:
                try:
                    findings = await test(endpoint)
                    self.findings.extend(findings)
                except Exception:
                    pass
                    
        return self.findings
        
    async def _test_authentication_bypass(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        findings = []
        
        if endpoint.auth_type != AuthType.NONE:
            # Try accessing without auth
            async with self.discovery._semaphore:
                try:
                    async with self.discovery.session.get(endpoint.url) as response:
                        if response.status == 200:
                            findings.append({
                                "type": "Authentication Bypass",
                                "severity": "CRITICAL",
                                "endpoint": endpoint.url,
                                "method": endpoint.method,
                                "description": "Endpoint accessible without authentication",
                            })
                except Exception:
                    pass
                    
        return findings
        
    async def _test_injection(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Test for injection vulnerabilities"""
        findings = []
        
        payloads = {
            "sql": ["' OR '1'='1", "1; DROP TABLE users--", "1 UNION SELECT NULL--"],
            "nosql": ['{"$gt": ""}', '{"$ne": null}'],
            "cmd": ["; ls -la", "| cat /etc/passwd", "`id`"],
            "xss": ["<script>alert(1)</script>", "javascript:alert(1)"],
        }
        
        for param in endpoint.parameters.get("query", []):
            param_name = param.get("name") if isinstance(param, dict) else param
            
            for injection_type, test_payloads in payloads.items():
                for payload in test_payloads[:1]:  # Test first payload only
                    test_url = f"{endpoint.url}?{param_name}={payload}"
                    
                    async with self.discovery._semaphore:
                        try:
                            async with self.discovery.session.get(test_url) as response:
                                content = await response.text()
                                
                                # Check for error messages that indicate injection worked
                                error_patterns = [
                                    r"sql.*syntax",
                                    r"mysql.*error",
                                    r"mongodb.*error",
                                    r"root:.*:0:0:",
                                    r"uid=\d+",
                                ]
                                
                                for pattern in error_patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        findings.append({
                                            "type": f"{injection_type.upper()} Injection",
                                            "severity": "CRITICAL",
                                            "endpoint": endpoint.url,
                                            "parameter": param_name,
                                            "payload": payload,
                                            "description": f"Potential {injection_type} injection vulnerability",
                                        })
                                        break
                                        
                        except Exception:
                            pass
                            
        return findings
        
    async def _test_rate_limiting(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Test for rate limiting"""
        findings = []
        
        # Send rapid requests
        responses = []
        for _ in range(20):
            async with self.discovery._semaphore:
                try:
                    async with self.discovery.session.get(endpoint.url) as response:
                        responses.append(response.status)
                except Exception:
                    break
                    
        # Check if any rate limiting was triggered
        if 429 not in responses and len(responses) >= 20:
            findings.append({
                "type": "Missing Rate Limiting",
                "severity": "MEDIUM",
                "endpoint": endpoint.url,
                "description": "No rate limiting detected after 20 rapid requests",
            })
            
        return findings
        
    async def _test_verbose_errors(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Test for verbose error messages"""
        findings = []
        
        # Send malformed requests
        test_cases = [
            ("invalid_json", {"Content-Type": "application/json"}, "not valid json"),
            ("missing_param", {}, None),
        ]
        
        for test_name, headers, body in test_cases:
            async with self.discovery._semaphore:
                try:
                    async with self.discovery.session.post(
                        endpoint.url,
                        headers=headers,
                        data=body
                    ) as response:
                        content = await response.text()
                        
                        # Check for verbose errors
                        verbose_patterns = [
                            r"stack trace",
                            r"traceback",
                            r"exception",
                            r"at \w+\.\w+\(",
                            r"line \d+",
                            r"file.*\.py",
                            r"internal server error",
                        ]
                        
                        for pattern in verbose_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append({
                                    "type": "Verbose Error Messages",
                                    "severity": "LOW",
                                    "endpoint": endpoint.url,
                                    "description": "Endpoint reveals detailed error information",
                                })
                                break
                                
                except Exception:
                    pass
                    
        return findings
        
    async def _test_mass_assignment(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Test for mass assignment vulnerabilities"""
        findings = []
        
        if endpoint.method in ["POST", "PUT", "PATCH"]:
            # Try adding unexpected fields
            test_payloads = [
                {"admin": True, "role": "admin"},
                {"is_superuser": True, "privileges": ["all"]},
                {"status": "active", "verified": True},
            ]
            
            for payload in test_payloads:
                async with self.discovery._semaphore:
                    try:
                        async with self.discovery.session.post(
                            endpoint.url,
                            json=payload,
                            headers={"Content-Type": "application/json"}
                        ) as response:
                            if response.status in [200, 201]:
                                content = await response.json()
                                
                                # Check if our fields were accepted
                                for key in payload:
                                    if key in content:
                                        findings.append({
                                            "type": "Mass Assignment",
                                            "severity": "HIGH",
                                            "endpoint": endpoint.url,
                                            "field": key,
                                            "description": f"Endpoint accepts unexpected field: {key}",
                                        })
                                        
                    except Exception:
                        pass
                        
        return findings
        
    async def _test_broken_object_level_auth(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Test for Broken Object Level Authorization (BOLA/IDOR)"""
        findings = []
        
        # Check if endpoint has ID parameter
        id_patterns = [
            r"/(\d+)$",
            r"/([a-f0-9-]{36})$",  # UUID
            r"\?id=(\d+)",
            r"\?user_id=(\d+)",
        ]
        
        for pattern in id_patterns:
            match = re.search(pattern, endpoint.url)
            if match:
                original_id = match.group(1)
                
                # Try accessing different IDs
                test_ids = ["1", "2", "admin", "0", "-1"]
                
                for test_id in test_ids:
                    if test_id != original_id:
                        test_url = re.sub(pattern, lambda m: m.group(0).replace(original_id, test_id), endpoint.url)
                        
                        async with self.discovery._semaphore:
                            try:
                                async with self.discovery.session.get(test_url) as response:
                                    if response.status == 200:
                                        findings.append({
                                            "type": "Broken Object Level Authorization",
                                            "severity": "HIGH",
                                            "endpoint": endpoint.url,
                                            "test_url": test_url,
                                            "description": "Endpoint may be vulnerable to IDOR/BOLA",
                                        })
                                        break
                                        
                            except Exception:
                                pass
                                
        return findings


class APIFuzzer:
    """
    Advanced API Fuzzing Engine
    Fuzzes API endpoints for edge cases and vulnerabilities
    """
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.results: List[Dict[str, Any]] = []
        
    async def fuzz_endpoint(self, endpoint: APIEndpoint, 
                           intensity: str = "medium") -> List[Dict[str, Any]]:
        """Fuzz an endpoint with various payloads"""
        
        fuzz_categories = {
            "boundaries": self._generate_boundary_payloads(),
            "special_chars": self._generate_special_char_payloads(),
            "type_confusion": self._generate_type_confusion_payloads(),
            "encoding": self._generate_encoding_payloads(),
        }
        
        for category, payloads in fuzz_categories.items():
            for payload in payloads:
                result = await self._send_fuzz_request(endpoint, payload, category)
                if result:
                    self.results.append(result)
                    
        return self.results
        
    def _generate_boundary_payloads(self) -> List[Any]:
        """Generate boundary test payloads"""
        return [
            0, -1, 1, 2147483647, -2147483648,  # Integer boundaries
            0.0, -0.0, float('inf'), float('-inf'),  # Float boundaries
            "", " ", "a" * 10000,  # String boundaries
            [], [None] * 1000, {},  # Collection boundaries
            None, True, False,
        ]
        
    def _generate_special_char_payloads(self) -> List[str]:
        """Generate special character payloads"""
        return [
            "\\", "/", "//", "../", "..\\",
            "\x00", "\x0a", "\x0d", "\xff",
            "<>", "\"'", "{}[]", "()",
            "{{", "}}", "${}", "#{",
            "<!--", "-->", "<![CDATA[",
            "\u0000", "\u200b", "\ufeff",
        ]
        
    def _generate_type_confusion_payloads(self) -> List[Any]:
        """Generate type confusion payloads"""
        return [
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"admin": True}}},
            ["__proto__"],
            {"$where": "1==1"},
            {"$regex": ".*"},
        ]
        
    def _generate_encoding_payloads(self) -> List[str]:
        """Generate encoding payloads"""
        return [
            "%00", "%0a", "%0d", "%20",
            "%252f", "%c0%af", "%e0%80%af",
            "&#x3c;", "&#60;", "&lt;",
            "\\u003c", "\\x3c",
        ]
        
    async def _send_fuzz_request(self, endpoint: APIEndpoint, 
                                  payload: Any, category: str) -> Optional[Dict[str, Any]]:
        """Send a fuzz request and analyze response"""
        try:
            # Build request based on endpoint method
            if endpoint.method == "GET":
                test_url = f"{endpoint.url}?fuzz={payload}"
                async with self.session.get(test_url) as response:
                    return await self._analyze_fuzz_response(
                        endpoint, payload, category, response
                    )
            else:
                async with self.session.request(
                    endpoint.method,
                    endpoint.url,
                    json={"fuzz": payload} if isinstance(payload, (dict, list)) else {"fuzz": str(payload)}
                ) as response:
                    return await self._analyze_fuzz_response(
                        endpoint, payload, category, response
                    )
                    
        except Exception as e:
            # Exceptions might indicate interesting behavior
            return {
                "endpoint": endpoint.url,
                "method": endpoint.method,
                "payload": str(payload),
                "category": category,
                "result": "exception",
                "error": str(e),
            }
            
    async def _analyze_fuzz_response(self, endpoint: APIEndpoint,
                                      payload: Any, category: str,
                                      response: aiohttp.ClientResponse) -> Optional[Dict[str, Any]]:
        """Analyze fuzz response for interesting behavior"""
        content = await response.text()
        
        # Interesting status codes
        interesting_status = [500, 502, 503, 504]
        
        # Check for interesting behavior
        if response.status in interesting_status:
            return {
                "endpoint": endpoint.url,
                "method": endpoint.method,
                "payload": str(payload),
                "category": category,
                "status_code": response.status,
                "finding": "Server error triggered",
                "severity": "MEDIUM",
            }
            
        # Check for payload reflection
        if str(payload) in content:
            return {
                "endpoint": endpoint.url,
                "method": endpoint.method,
                "payload": str(payload),
                "category": category,
                "finding": "Payload reflected in response",
                "severity": "LOW",
            }
            
        return None


# Async helper function
async def discover_apis(target: str, **kwargs) -> Dict[str, Any]:
    """Convenience function to discover APIs on a target"""
    async with APIDiscoveryEngine() as engine:
        results = await engine.discover(target, **kwargs)
        
        # Run security tests
        tester = APISecurityTester(engine)
        security_findings = await tester.run_security_tests(engine.discovered_endpoints)
        results["security_findings"] = security_findings
        
        return results


if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python api_discovery.py <target_url>")
            sys.exit(1)
            
        target = sys.argv[1]
        print(f"\n{'='*60}")
        print(f"API Discovery Engine - Target: {target}")
        print(f"{'='*60}\n")
        
        results = await discover_apis(target, deep_scan=True)
        
        print(f"\n[+] Discovered {results['statistics']['total_endpoints']} endpoints")
        print(f"[+] API Type: {results['api_type']}")
        print(f"[+] Technologies: {', '.join(results['technologies']) or 'Unknown'}")
        
        print(f"\n[*] Endpoints by method:")
        for method, count in results['statistics']['by_method'].items():
            print(f"    {method}: {count}")
            
        print(f"\n[!] Security Findings: {len(results.get('security_findings', []))}")
        for finding in results.get('security_findings', [])[:10]:
            print(f"    [{finding['severity']}] {finding['type']}: {finding['endpoint']}")
            
    asyncio.run(main())
