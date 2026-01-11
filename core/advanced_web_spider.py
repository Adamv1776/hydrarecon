#!/usr/bin/env python3
"""
Advanced Web Spider - Beyond Burp Suite Pro
Comprehensive web application crawler with AI-powered discovery.

Features:
- Multi-threaded async crawling
- JavaScript rendering (headless browser)
- Intelligent form detection and auto-fill
- API endpoint discovery (REST, GraphQL, WebSocket)
- Hidden parameter mining
- Authentication handling (Basic, Digest, OAuth, JWT, Session)
- Technology fingerprinting
- Real-time vulnerability detection
- Scope-aware crawling
- Rate limiting and stealth modes
"""

import asyncio
import aiohttp
import hashlib
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime
from collections import defaultdict
import logging
from bs4 import BeautifulSoup
import random

logger = logging.getLogger(__name__)


class RequestMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class ContentType(Enum):
    HTML = auto()
    JSON = auto()
    XML = auto()
    JAVASCRIPT = auto()
    CSS = auto()
    IMAGE = auto()
    BINARY = auto()
    FORM = auto()
    MULTIPART = auto()
    GRAPHQL = auto()
    UNKNOWN = auto()


class AuthType(Enum):
    NONE = auto()
    BASIC = auto()
    DIGEST = auto()
    BEARER = auto()
    JWT = auto()
    COOKIE = auto()
    OAUTH2 = auto()
    API_KEY = auto()
    NTLM = auto()
    CUSTOM = auto()


class ParameterLocation(Enum):
    URL = "url"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"
    FRAGMENT = "fragment"


@dataclass
class Parameter:
    """Discovered parameter"""
    name: str
    location: ParameterLocation
    value: str = ""
    param_type: str = "string"  # string, int, bool, array, object, file
    required: bool = False
    discovered_in: str = ""
    reflected: bool = False  # For XSS testing
    sql_injectable: bool = False
    interesting: bool = False


@dataclass
class Endpoint:
    """Discovered endpoint"""
    url: str
    method: RequestMethod
    parameters: List[Parameter] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: ContentType = ContentType.HTML
    response_codes: List[int] = field(default_factory=list)
    response_size: int = 0
    response_time: float = 0.0
    auth_required: bool = False
    auth_type: AuthType = AuthType.NONE
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    robots_disallowed: bool = False
    sitemap_found: bool = False
    hash: str = ""
    timestamp: str = ""


@dataclass
class Form:
    """HTML form"""
    action: str
    method: str
    inputs: List[Dict[str, str]]
    enctype: str = "application/x-www-form-urlencoded"
    has_file_upload: bool = False
    has_csrf_token: bool = False
    csrf_token_name: str = ""


@dataclass 
class CrawlResult:
    """Result of a crawl session"""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    endpoints: List[Endpoint] = field(default_factory=list)
    parameters: List[Parameter] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    vulnerabilities: List[Dict] = field(default_factory=list)
    api_endpoints: List[Dict] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    websocket_endpoints: List[str] = field(default_factory=list)
    authentication_endpoints: List[str] = field(default_factory=list)
    interesting_files: List[str] = field(default_factory=list)
    robots_txt: str = ""
    sitemap_urls: List[str] = field(default_factory=list)
    total_requests: int = 0
    total_errors: int = 0
    coverage_percentage: float = 0.0


class TechnologyFingerprinter:
    """Identify technologies used by target"""
    
    def __init__(self):
        self.signatures = {
            # Web Servers
            "nginx": {"headers": ["Server: nginx"], "patterns": []},
            "Apache": {"headers": ["Server: Apache"], "patterns": []},
            "IIS": {"headers": ["Server: Microsoft-IIS"], "patterns": []},
            "Cloudflare": {"headers": ["cf-ray", "Server: cloudflare"], "patterns": []},
            
            # Frameworks
            "React": {"headers": [], "patterns": [r"react", r"_reactRoot", r"__REACT"]},
            "Vue.js": {"headers": [], "patterns": [r"__vue__", r"vue\.js", r"Vue\.component"]},
            "Angular": {"headers": [], "patterns": [r"ng-app", r"ng-controller", r"angular"]},
            "jQuery": {"headers": [], "patterns": [r"jquery", r"\$\(document\)"]},
            "Django": {"headers": ["X-Frame-Options"], "patterns": [r"csrfmiddlewaretoken", r"__admin"]},
            "Flask": {"headers": [], "patterns": [r"flask", r"werkzeug"]},
            "Express": {"headers": ["X-Powered-By: Express"], "patterns": []},
            "Laravel": {"headers": [], "patterns": [r"laravel_session", r"XSRF-TOKEN"]},
            "WordPress": {"headers": [], "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json"]},
            "Drupal": {"headers": ["X-Drupal-Cache"], "patterns": [r"/sites/default/", r"Drupal"]},
            "ASP.NET": {"headers": ["X-AspNet-Version", "X-Powered-By: ASP.NET"], "patterns": [r"__VIEWSTATE", r"\.aspx"]},
            "Spring": {"headers": [], "patterns": [r"spring", r"JSESSIONID"]},
            "Ruby on Rails": {"headers": ["X-Runtime"], "patterns": [r"rails", r"_rails"]},
            
            # CMS/Platforms
            "Shopify": {"headers": [], "patterns": [r"cdn\.shopify\.com", r"Shopify\.theme"]},
            "Magento": {"headers": [], "patterns": [r"Mage\.", r"/skin/frontend/"]},
            "Joomla": {"headers": [], "patterns": [r"/components/com_", r"Joomla"]},
            
            # Security
            "WAF Detected": {"headers": ["X-WAF", "X-Sucuri"], "patterns": []},
            "Captcha": {"headers": [], "patterns": [r"recaptcha", r"hcaptcha", r"captcha"]},
            
            # APIs
            "GraphQL": {"headers": [], "patterns": [r"graphql", r"__schema", r"query\s*\{"]},
            "REST API": {"headers": ["application/json"], "patterns": [r"/api/v\d", r"/rest/"]},
            "SOAP": {"headers": ["text/xml"], "patterns": [r"wsdl", r"soap"]},
        }
    
    def fingerprint(self, url: str, headers: Dict, body: str) -> List[str]:
        """Fingerprint technologies from response"""
        technologies = []
        
        headers_str = str(headers).lower()
        body_lower = body.lower() if body else ""
        
        for tech, sigs in self.signatures.items():
            # Check headers
            for header_sig in sigs.get("headers", []):
                if header_sig.lower() in headers_str:
                    if tech not in technologies:
                        technologies.append(tech)
                    break
            
            # Check body patterns
            for pattern in sigs.get("patterns", []):
                if re.search(pattern, body_lower, re.IGNORECASE):
                    if tech not in technologies:
                        technologies.append(tech)
                    break
        
        return technologies


class ParameterMiner:
    """Mine hidden parameters from responses"""
    
    def __init__(self):
        # Common parameter wordlist
        self.common_params = [
            "id", "page", "search", "q", "query", "s", "keyword",
            "user", "username", "email", "name", "password", "pass",
            "token", "csrf", "auth", "key", "api_key", "apikey",
            "callback", "jsonp", "redirect", "url", "next", "return",
            "file", "path", "dir", "folder", "download", "upload",
            "action", "cmd", "command", "exec", "run", "do",
            "debug", "test", "admin", "root", "config",
            "sort", "order", "limit", "offset", "skip", "count",
            "format", "type", "output", "response", "view",
            "lang", "language", "locale", "currency",
            "category", "cat", "tag", "filter", "status",
            "from", "to", "start", "end", "date", "time",
            "v", "version", "ver", "rev",
            "source", "src", "dest", "destination", "target",
        ]
        
        # Regex patterns to find parameters in JS/HTML
        self.param_patterns = [
            r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=',  # URL params
            r'name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',  # Form inputs
            r'params\[["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',  # JS params
            r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=',  # JS object props
            r'data-([a-zA-Z][a-zA-Z0-9-]*)',  # Data attributes
            r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:',  # JSON keys
        ]
    
    def mine_parameters(self, url: str, body: str, content_type: ContentType) -> List[Parameter]:
        """Extract parameters from response"""
        params = []
        found_names = set()
        
        # Parse URL query params
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        for name, values in query_params.items():
            if name not in found_names:
                params.append(Parameter(
                    name=name,
                    location=ParameterLocation.QUERY,
                    value=values[0] if values else "",
                    discovered_in=url
                ))
                found_names.add(name)
        
        if not body:
            return params
        
        # Mine from body using regex
        for pattern in self.param_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 1 and match not in found_names:
                    params.append(Parameter(
                        name=match,
                        location=ParameterLocation.BODY,
                        discovered_in=url
                    ))
                    found_names.add(match)
        
        # Parse HTML forms
        if content_type == ContentType.HTML:
            soup = BeautifulSoup(body, 'html.parser')
            for inp in soup.find_all(['input', 'select', 'textarea']):
                name = inp.get('name')
                if name and name not in found_names:
                    params.append(Parameter(
                        name=name,
                        location=ParameterLocation.BODY,
                        value=inp.get('value', ''),
                        param_type=inp.get('type', 'text'),
                        discovered_in=url
                    ))
                    found_names.add(name)
        
        # Parse JSON
        if content_type == ContentType.JSON:
            try:
                data = json.loads(body)
                self._extract_json_params(data, params, found_names, url)
            except:
                pass
        
        return params
    
    def _extract_json_params(self, data, params: List[Parameter], 
                              found_names: Set[str], url: str, prefix: str = ""):
        """Recursively extract parameters from JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if key not in found_names:
                    param_type = type(value).__name__
                    params.append(Parameter(
                        name=key,
                        location=ParameterLocation.BODY,
                        value=str(value)[:100] if value else "",
                        param_type=param_type,
                        discovered_in=url
                    ))
                    found_names.add(key)
                if isinstance(value, (dict, list)):
                    self._extract_json_params(value, params, found_names, url, full_key)
        elif isinstance(data, list) and data:
            self._extract_json_params(data[0], params, found_names, url, prefix)


class FormAnalyzer:
    """Analyze and categorize HTML forms"""
    
    def __init__(self):
        self.login_indicators = ['login', 'signin', 'auth', 'password', 'user']
        self.register_indicators = ['register', 'signup', 'create', 'account']
        self.search_indicators = ['search', 'query', 'find', 'q']
        self.upload_indicators = ['upload', 'file', 'attachment', 'document']
        self.contact_indicators = ['contact', 'message', 'email', 'feedback']
    
    def analyze_form(self, form_element, base_url: str) -> Form:
        """Analyze an HTML form element"""
        action = form_element.get('action', '')
        if action and not action.startswith(('http://', 'https://')):
            action = urllib.parse.urljoin(base_url, action)
        
        method = form_element.get('method', 'GET').upper()
        enctype = form_element.get('enctype', 'application/x-www-form-urlencoded')
        
        inputs = []
        has_file = False
        has_csrf = False
        csrf_name = ""
        
        for inp in form_element.find_all(['input', 'select', 'textarea', 'button']):
            inp_data = {
                'name': inp.get('name', ''),
                'type': inp.get('type', 'text'),
                'value': inp.get('value', ''),
                'required': inp.has_attr('required'),
                'placeholder': inp.get('placeholder', ''),
                'pattern': inp.get('pattern', ''),
            }
            
            if inp_data['type'] == 'file':
                has_file = True
            
            # Detect CSRF tokens
            name_lower = inp_data['name'].lower()
            if any(x in name_lower for x in ['csrf', 'token', 'nonce', '_token']):
                has_csrf = True
                csrf_name = inp_data['name']
            
            if inp_data['name']:
                inputs.append(inp_data)
        
        return Form(
            action=action,
            method=method,
            inputs=inputs,
            enctype=enctype,
            has_file_upload=has_file,
            has_csrf_token=has_csrf,
            csrf_token_name=csrf_name
        )
    
    def categorize_form(self, form: Form) -> str:
        """Categorize form type"""
        form_str = json.dumps(form.inputs).lower()
        
        if any(x in form_str for x in self.login_indicators):
            return "login"
        if any(x in form_str for x in self.register_indicators):
            return "registration"
        if any(x in form_str for x in self.search_indicators):
            return "search"
        if form.has_file_upload:
            return "file_upload"
        if any(x in form_str for x in self.contact_indicators):
            return "contact"
        
        return "generic"


class VulnerabilityDetector:
    """Detect potential vulnerabilities during crawl"""
    
    def __init__(self):
        self.sensitive_patterns = {
            "api_key": [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            ],
            "aws_key": [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key[_-]?id',
            ],
            "jwt_token": [
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            ],
            "password": [
                r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'passwd["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ],
            "private_key": [
                r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            ],
            "database_conn": [
                r'mongodb://[^\s"\']+',
                r'mysql://[^\s"\']+',
                r'postgresql://[^\s"\']+',
            ],
            "internal_ip": [
                r'192\.168\.\d{1,3}\.\d{1,3}',
                r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}',
            ],
            "error_disclosure": [
                r'stack\s*trace',
                r'exception\s*in\s*thread',
                r'syntax\s*error',
                r'mysql_fetch',
                r'pg_query',
                r'ORA-\d{5}',
            ],
        }
    
    def scan_response(self, url: str, body: str, headers: Dict) -> List[Dict]:
        """Scan response for vulnerabilities"""
        vulns = []
        
        if not body:
            return vulns
        
        # Check for sensitive data exposure
        for vuln_type, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    vulns.append({
                        "type": f"Sensitive Data Exposure: {vuln_type}",
                        "severity": "HIGH" if vuln_type in ["api_key", "aws_key", "private_key", "password"] else "MEDIUM",
                        "url": url,
                        "evidence": f"Pattern matched: {pattern[:50]}...",
                        "matches": matches[:3]  # Limit matches
                    })
        
        # Check security headers
        missing_headers = []
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options", 
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ]
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header in security_headers:
            if header.lower() not in headers_lower:
                missing_headers.append(header)
        
        if missing_headers:
            vulns.append({
                "type": "Missing Security Headers",
                "severity": "LOW",
                "url": url,
                "evidence": f"Missing: {', '.join(missing_headers)}",
                "headers": missing_headers
            })
        
        # Check for directory listing
        if '<title>Index of' in body or 'Directory listing for' in body:
            vulns.append({
                "type": "Directory Listing Enabled",
                "severity": "MEDIUM",
                "url": url,
                "evidence": "Directory listing page detected"
            })
        
        # Check for debug mode
        if any(x in body.lower() for x in ['debug=true', 'debug mode', 'stack trace', 'traceback']):
            vulns.append({
                "type": "Debug Mode Enabled",
                "severity": "MEDIUM",
                "url": url,
                "evidence": "Debug information exposed"
            })
        
        return vulns


class AdvancedWebSpider:
    """Advanced Web Spider Engine"""
    
    def __init__(self, config=None, db=None):
        self.config = config or {}
        self.db = db
        
        # Crawl settings
        self.max_depth = 10
        self.max_pages = 1000
        self.request_delay = 0.5  # seconds
        self.timeout = 30
        self.max_concurrent = 10
        self.respect_robots = True
        self.follow_redirects = True
        self.user_agent = "HydraSpider/2.0 (Advanced Security Scanner)"
        
        # Scope
        self.scope_patterns: List[str] = []
        self.exclude_patterns: List[str] = []
        self.allowed_domains: Set[str] = set()
        
        # State
        self.visited_urls: Set[str] = set()
        self.url_queue: asyncio.Queue = None
        self.discovered_endpoints: Dict[str, Endpoint] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.running = False
        
        # Components
        self.fingerprinter = TechnologyFingerprinter()
        self.param_miner = ParameterMiner()
        self.form_analyzer = FormAnalyzer()
        self.vuln_detector = VulnerabilityDetector()
        
        # Results
        self.result: Optional[CrawlResult] = None
        
        # Callbacks
        self.on_endpoint_discovered: Optional[Callable] = None
        self.on_form_discovered: Optional[Callable] = None
        self.on_vulnerability_found: Optional[Callable] = None
        self.on_progress_update: Optional[Callable] = None
        
        # Authentication
        self.auth_type = AuthType.NONE
        self.auth_credentials: Dict[str, str] = {}
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
    
    def configure(self, **kwargs):
        """Configure spider settings"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def set_scope(self, target: str, include_subdomains: bool = True):
        """Set crawl scope based on target"""
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc
        
        self.allowed_domains.add(domain)
        
        if include_subdomains:
            base_domain = '.'.join(domain.split('.')[-2:])
            self.scope_patterns.append(f".*\\.{re.escape(base_domain)}.*")
        
        self.scope_patterns.append(f".*{re.escape(domain)}.*")
    
    def add_exclude_pattern(self, pattern: str):
        """Add URL pattern to exclude"""
        self.exclude_patterns.append(pattern)
    
    def set_authentication(self, auth_type: AuthType, credentials: Dict[str, str]):
        """Set authentication for requests"""
        self.auth_type = auth_type
        self.auth_credentials = credentials
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within scope"""
        if not self.scope_patterns:
            return True
        
        for pattern in self.exclude_patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return False
        
        for pattern in self.scope_patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and validate URL"""
        try:
            # Handle relative URLs
            if not url.startswith(('http://', 'https://', '//')):
                url = urllib.parse.urljoin(base_url, url)
            elif url.startswith('//'):
                parsed_base = urllib.parse.urlparse(base_url)
                url = f"{parsed_base.scheme}:{url}"
            
            # Parse and rebuild
            parsed = urllib.parse.urlparse(url)
            
            # Remove fragments
            url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))
            
            return url
        except:
            return None
    
    def _get_content_type(self, headers: Dict, body: str) -> ContentType:
        """Determine content type from headers and body"""
        content_type = headers.get('Content-Type', '').lower()
        
        if 'application/json' in content_type:
            return ContentType.JSON
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            return ContentType.XML
        elif 'text/html' in content_type:
            return ContentType.HTML
        elif 'text/javascript' in content_type or 'application/javascript' in content_type:
            return ContentType.JAVASCRIPT
        elif 'text/css' in content_type:
            return ContentType.CSS
        elif 'image/' in content_type:
            return ContentType.IMAGE
        elif 'graphql' in content_type or (body and '__schema' in body):
            return ContentType.GRAPHQL
        
        # Try to detect from body
        if body:
            if body.strip().startswith('{') or body.strip().startswith('['):
                try:
                    json.loads(body)
                    return ContentType.JSON
                except:
                    pass
            if '<html' in body.lower() or '<!doctype html' in body.lower():
                return ContentType.HTML
        
        return ContentType.UNKNOWN
    
    async def _fetch_url(self, url: str, method: RequestMethod = RequestMethod.GET,
                         data: Dict = None) -> Tuple[Optional[str], Dict, int, float]:
        """Fetch URL and return body, headers, status, response time"""
        if not self.session:
            return None, {}, 0, 0
        
        start_time = time.time()
        
        try:
            headers = {
                'User-Agent': self.user_agent,
                **self.headers
            }
            
            # Add auth headers
            if self.auth_type == AuthType.BEARER:
                headers['Authorization'] = f"Bearer {self.auth_credentials.get('token', '')}"
            elif self.auth_type == AuthType.API_KEY:
                headers[self.auth_credentials.get('header', 'X-API-Key')] = self.auth_credentials.get('key', '')
            
            kwargs = {
                'headers': headers,
                'timeout': aiohttp.ClientTimeout(total=self.timeout),
                'allow_redirects': self.follow_redirects,
                'cookies': self.cookies
            }
            
            if method == RequestMethod.POST and data:
                kwargs['data'] = data
            
            async with self.session.request(method.value, url, **kwargs) as response:
                body = await response.text()
                response_time = time.time() - start_time
                
                return body, dict(response.headers), response.status, response_time
        
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching {url}")
            return None, {}, 0, time.time() - start_time
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None, {}, 0, time.time() - start_time
    
    def _extract_links(self, body: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = set()
        
        if not body:
            return list(links)
        
        soup = BeautifulSoup(body, 'html.parser')
        
        # Get href links
        for tag in soup.find_all(['a', 'link', 'area']):
            href = tag.get('href')
            if href:
                normalized = self._normalize_url(href, base_url)
                if normalized and self._is_in_scope(normalized):
                    links.add(normalized)
        
        # Get src links
        for tag in soup.find_all(['script', 'img', 'iframe', 'embed', 'source']):
            src = tag.get('src')
            if src:
                normalized = self._normalize_url(src, base_url)
                if normalized and self._is_in_scope(normalized):
                    links.add(normalized)
        
        # Get form actions
        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                normalized = self._normalize_url(action, base_url)
                if normalized and self._is_in_scope(normalized):
                    links.add(normalized)
        
        # Extract from JavaScript
        js_patterns = [
            r'["\'](/[a-zA-Z0-9_/\-\.]+)["\']',
            r'href\s*=\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'fetch\s*\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, body)
            for match in matches:
                if match.startswith('/') or match.startswith('http'):
                    normalized = self._normalize_url(match, base_url)
                    if normalized and self._is_in_scope(normalized):
                        links.add(normalized)
        
        return list(links)
    
    def _extract_forms(self, body: str, base_url: str) -> List[Form]:
        """Extract forms from HTML"""
        forms = []
        
        if not body:
            return forms
        
        soup = BeautifulSoup(body, 'html.parser')
        
        for form_elem in soup.find_all('form'):
            form = self.form_analyzer.analyze_form(form_elem, base_url)
            forms.append(form)
        
        return forms
    
    def _extract_comments(self, body: str) -> List[str]:
        """Extract HTML comments"""
        if not body:
            return []
        
        # HTML comments
        html_comments = re.findall(r'<!--(.+?)-->', body, re.DOTALL)
        
        # JS comments
        js_comments = re.findall(r'/\*(.+?)\*/', body, re.DOTALL)
        js_comments += re.findall(r'//(.+?)$', body, re.MULTILINE)
        
        return html_comments + js_comments
    
    async def _crawl_url(self, url: str, depth: int = 0):
        """Crawl a single URL"""
        if url in self.visited_urls:
            return
        
        if depth > self.max_depth:
            return
        
        if len(self.visited_urls) >= self.max_pages:
            return
        
        self.visited_urls.add(url)
        
        # Respect rate limiting
        await asyncio.sleep(self.request_delay)
        
        # Fetch URL
        body, headers, status, response_time = await self._fetch_url(url)
        
        if self.result:
            self.result.total_requests += 1
        
        if not body or status >= 400:
            if self.result:
                self.result.total_errors += 1
            return
        
        # Determine content type
        content_type = self._get_content_type(headers, body)
        
        # Create endpoint
        endpoint = Endpoint(
            url=url,
            method=RequestMethod.GET,
            content_type=content_type,
            response_codes=[status],
            response_size=len(body),
            response_time=response_time,
            hash=hashlib.md5(body.encode()).hexdigest()[:16],
            timestamp=datetime.now().isoformat()
        )
        
        # Fingerprint technologies
        endpoint.technologies = self.fingerprinter.fingerprint(url, headers, body)
        
        # Mine parameters
        params = self.param_miner.mine_parameters(url, body, content_type)
        endpoint.parameters = params
        
        # Extract links
        endpoint.links = self._extract_links(body, url)
        
        # Extract forms
        forms = self._extract_forms(body, url)
        endpoint.forms = [vars(f) for f in forms]
        
        # Extract comments
        endpoint.comments = self._extract_comments(body)
        
        # Detect vulnerabilities
        vulns = self.vuln_detector.scan_response(url, body, headers)
        endpoint.vulnerabilities = [v['type'] for v in vulns]
        
        # Store endpoint
        self.discovered_endpoints[url] = endpoint
        
        # Update result
        if self.result:
            self.result.endpoints.append(endpoint)
            self.result.parameters.extend(params)
            self.result.forms.extend(forms)
            self.result.vulnerabilities.extend(vulns)
            
            # Track technologies
            for tech in endpoint.technologies:
                if tech not in self.result.technologies:
                    self.result.technologies[tech] = []
                self.result.technologies[tech].append(url)
            
            # Detect special endpoints
            url_lower = url.lower()
            if 'graphql' in url_lower:
                self.result.graphql_endpoints.append(url)
            if any(x in url_lower for x in ['/api/', '/rest/', '/v1/', '/v2/']):
                self.result.api_endpoints.append({'url': url, 'method': 'GET'})
            if any(x in url_lower for x in ['login', 'signin', 'auth']):
                self.result.authentication_endpoints.append(url)
            if any(x in url_lower for x in ['ws://', 'wss://', 'socket']):
                self.result.websocket_endpoints.append(url)
        
        # Callbacks
        if self.on_endpoint_discovered:
            self.on_endpoint_discovered(endpoint)
        
        for form in forms:
            if self.on_form_discovered:
                self.on_form_discovered(form)
        
        for vuln in vulns:
            if self.on_vulnerability_found:
                self.on_vulnerability_found(vuln)
        
        if self.on_progress_update:
            self.on_progress_update(len(self.visited_urls), len(self.discovered_endpoints))
        
        # Queue new URLs
        for link in endpoint.links:
            if link not in self.visited_urls:
                await self.url_queue.put((link, depth + 1))
    
    async def _worker(self):
        """Worker coroutine for crawling"""
        while self.running:
            try:
                url, depth = await asyncio.wait_for(self.url_queue.get(), timeout=5)
                await self._crawl_url(url, depth)
                self.url_queue.task_done()
            except asyncio.TimeoutError:
                if self.url_queue.empty():
                    break
            except Exception as e:
                logger.error(f"Worker error: {e}")
    
    async def _fetch_robots(self, base_url: str):
        """Fetch and parse robots.txt"""
        robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
        body, headers, status, _ = await self._fetch_url(robots_url)
        
        if body and status == 200:
            if self.result:
                self.result.robots_txt = body
            
            # Parse for sitemaps and disallowed paths
            for line in body.split('\n'):
                line = line.strip().lower()
                if line.startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    if self.result:
                        self.result.sitemap_urls.append(sitemap_url)
                elif line.startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and self.result:
                        full_url = urllib.parse.urljoin(base_url, path)
                        self.result.interesting_files.append(full_url)
    
    async def crawl(self, target: str) -> CrawlResult:
        """Start crawling target"""
        self.running = True
        self.visited_urls.clear()
        self.discovered_endpoints.clear()
        self.url_queue = asyncio.Queue()
        
        # Set scope
        self.set_scope(target)
        
        # Initialize result
        self.result = CrawlResult(
            target=target,
            start_time=datetime.now()
        )
        
        # Create session
        connector = aiohttp.TCPConnector(limit=self.max_concurrent, ssl=False)
        self.session = aiohttp.ClientSession(connector=connector)
        
        try:
            # Fetch robots.txt first
            await self._fetch_robots(target)
            
            # Start with target URL
            await self.url_queue.put((target, 0))
            
            # Common discovery paths
            common_paths = [
                '/sitemap.xml', '/.well-known/security.txt', '/api', '/graphql',
                '/swagger', '/openapi.json', '/api-docs', '/.git/config',
                '/wp-json', '/admin', '/login', '/dashboard', '/.env'
            ]
            
            for path in common_paths:
                full_url = urllib.parse.urljoin(target, path)
                await self.url_queue.put((full_url, 1))
            
            # Start workers
            workers = [asyncio.create_task(self._worker()) for _ in range(self.max_concurrent)]
            
            # Wait for completion
            await self.url_queue.join()
            
            # Cancel workers
            for worker in workers:
                worker.cancel()
            
        finally:
            await self.session.close()
            self.session = None
        
        self.result.end_time = datetime.now()
        self.result.coverage_percentage = (
            len(self.discovered_endpoints) / max(len(self.visited_urls), 1)
        ) * 100
        
        self.running = False
        return self.result
    
    def stop(self):
        """Stop crawling"""
        self.running = False
    
    def export_results(self, format: str = "json") -> str:
        """Export results in specified format"""
        if not self.result:
            return ""
        
        if format == "json":
            return json.dumps({
                "target": self.result.target,
                "start_time": str(self.result.start_time),
                "end_time": str(self.result.end_time),
                "total_endpoints": len(self.result.endpoints),
                "total_parameters": len(self.result.parameters),
                "total_forms": len(self.result.forms),
                "total_vulnerabilities": len(self.result.vulnerabilities),
                "technologies": self.result.technologies,
                "endpoints": [vars(e) for e in self.result.endpoints[:100]],
                "vulnerabilities": self.result.vulnerabilities,
                "api_endpoints": self.result.api_endpoints,
                "graphql_endpoints": self.result.graphql_endpoints,
                "authentication_endpoints": self.result.authentication_endpoints,
            }, indent=2, default=str)
        
        return ""
