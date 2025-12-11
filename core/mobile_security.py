"""
Mobile Security Scanner - Comprehensive Mobile App Security Testing
Android & iOS application analysis, reverse engineering, and vulnerability assessment
"""

import asyncio
import hashlib
import struct
import zipfile
import xml.etree.ElementTree as ET
import json
import re
import os
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from enum import Enum
from datetime import datetime
import logging
import subprocess
import tempfile
import shutil


class MobilePlatform(Enum):
    """Mobile platforms"""
    ANDROID = "android"
    IOS = "ios"


class AppRiskLevel(Enum):
    """Application risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(Enum):
    """Vulnerability categories"""
    INSECURE_DATA_STORAGE = "insecure_data_storage"
    INSECURE_COMMUNICATION = "insecure_communication"
    INSECURE_AUTHENTICATION = "insecure_authentication"
    INSUFFICIENT_CRYPTOGRAPHY = "insufficient_cryptography"
    CODE_TAMPERING = "code_tampering"
    REVERSE_ENGINEERING = "reverse_engineering"
    EXTRANEOUS_FUNCTIONALITY = "extraneous_functionality"
    CLIENT_CODE_QUALITY = "client_code_quality"


@dataclass
class MobileApp:
    """Represents a mobile application"""
    id: str
    name: str
    package_name: str
    version: str
    platform: MobilePlatform
    file_path: str
    file_hash: str
    file_size: int
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    signatures: List[Dict[str, str]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    analysis_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityFinding:
    """Security analysis finding"""
    id: str
    category: VulnCategory
    risk_level: AppRiskLevel
    title: str
    description: str
    location: str
    evidence: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: float = 0.0


@dataclass
class StaticAnalysisResult:
    """Static analysis results"""
    app_id: str
    findings: List[SecurityFinding] = field(default_factory=list)
    hardcoded_secrets: List[Dict[str, str]] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    api_keys: List[Dict[str, str]] = field(default_factory=list)
    crypto_issues: List[Dict[str, Any]] = field(default_factory=list)
    exported_components: List[Dict[str, str]] = field(default_factory=list)
    webview_issues: List[Dict[str, Any]] = field(default_factory=list)
    analysis_time: float = 0.0


@dataclass
class DynamicAnalysisResult:
    """Dynamic analysis results"""
    app_id: str
    network_traffic: List[Dict[str, Any]] = field(default_factory=list)
    file_access: List[Dict[str, Any]] = field(default_factory=list)
    database_access: List[Dict[str, Any]] = field(default_factory=list)
    crypto_operations: List[Dict[str, Any]] = field(default_factory=list)
    ipc_calls: List[Dict[str, Any]] = field(default_factory=list)
    runtime_findings: List[SecurityFinding] = field(default_factory=list)


class MobileSecurityScanner:
    """
    Advanced Mobile Security Scanner
    
    Features:
    - APK/IPA analysis
    - Manifest parsing
    - Permission analysis
    - Hardcoded secret detection
    - Cryptography analysis
    - SSL/TLS verification
    - Component security
    - Dynamic instrumentation
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.apps: Dict[str, MobileApp] = {}
        self.analyses: Dict[str, StaticAnalysisResult] = {}
        self.is_running = False
        self.callbacks: List[Callable] = []
        
        # Dangerous permissions database
        self.dangerous_permissions = self._load_dangerous_permissions()
        
        # Secret patterns
        self.secret_patterns = self._load_secret_patterns()
        
        # Known vulnerable libraries
        self.vuln_libraries = self._load_vulnerable_libraries()
    
    def _load_dangerous_permissions(self) -> Dict[str, Dict[str, Any]]:
        """Load dangerous Android permissions"""
        return {
            "android.permission.READ_CONTACTS": {
                "risk": "HIGH",
                "description": "Access to contacts data",
                "category": "PRIVACY",
            },
            "android.permission.READ_CALL_LOG": {
                "risk": "HIGH",
                "description": "Access to call history",
                "category": "PRIVACY",
            },
            "android.permission.READ_SMS": {
                "risk": "CRITICAL",
                "description": "Access to SMS messages",
                "category": "PRIVACY",
            },
            "android.permission.SEND_SMS": {
                "risk": "CRITICAL",
                "description": "Can send SMS (premium SMS fraud)",
                "category": "FINANCIAL",
            },
            "android.permission.RECORD_AUDIO": {
                "risk": "CRITICAL",
                "description": "Can record audio/calls",
                "category": "SURVEILLANCE",
            },
            "android.permission.CAMERA": {
                "risk": "HIGH",
                "description": "Camera access",
                "category": "SURVEILLANCE",
            },
            "android.permission.ACCESS_FINE_LOCATION": {
                "risk": "HIGH",
                "description": "Precise GPS location",
                "category": "TRACKING",
            },
            "android.permission.READ_EXTERNAL_STORAGE": {
                "risk": "MEDIUM",
                "description": "Read external storage",
                "category": "DATA_ACCESS",
            },
            "android.permission.WRITE_EXTERNAL_STORAGE": {
                "risk": "MEDIUM",
                "description": "Write to external storage",
                "category": "DATA_ACCESS",
            },
            "android.permission.SYSTEM_ALERT_WINDOW": {
                "risk": "HIGH",
                "description": "Draw over other apps (tapjacking)",
                "category": "SECURITY",
            },
            "android.permission.INSTALL_PACKAGES": {
                "risk": "CRITICAL",
                "description": "Can install applications",
                "category": "SECURITY",
            },
            "android.permission.RECEIVE_BOOT_COMPLETED": {
                "risk": "MEDIUM",
                "description": "Run at system boot",
                "category": "PERSISTENCE",
            },
            "android.permission.GET_ACCOUNTS": {
                "risk": "MEDIUM",
                "description": "Access account names",
                "category": "PRIVACY",
            },
        }
    
    def _load_secret_patterns(self) -> List[Dict[str, Any]]:
        """Load patterns for detecting secrets"""
        return [
            {
                "name": "AWS Access Key",
                "pattern": r'AKIA[0-9A-Z]{16}',
                "risk": "CRITICAL",
            },
            {
                "name": "AWS Secret Key",
                "pattern": r'[A-Za-z0-9/+=]{40}',
                "risk": "CRITICAL",
            },
            {
                "name": "Google API Key",
                "pattern": r'AIza[0-9A-Za-z_-]{35}',
                "risk": "HIGH",
            },
            {
                "name": "Firebase URL",
                "pattern": r'https://[a-z0-9-]+\.firebaseio\.com',
                "risk": "HIGH",
            },
            {
                "name": "Private Key",
                "pattern": r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
                "risk": "CRITICAL",
            },
            {
                "name": "Hardcoded Password",
                "pattern": r'password\s*[=:]\s*["\'][^"\']{4,}["\']',
                "risk": "HIGH",
            },
            {
                "name": "API Secret",
                "pattern": r'api[_-]?secret\s*[=:]\s*["\'][^"\']+["\']',
                "risk": "HIGH",
            },
            {
                "name": "Bearer Token",
                "pattern": r'Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                "risk": "CRITICAL",
            },
            {
                "name": "Slack Token",
                "pattern": r'xox[baprs]-[0-9A-Za-z-]+',
                "risk": "HIGH",
            },
            {
                "name": "GitHub Token",
                "pattern": r'ghp_[A-Za-z0-9]{36}',
                "risk": "CRITICAL",
            },
        ]
    
    def _load_vulnerable_libraries(self) -> Dict[str, Dict[str, Any]]:
        """Load known vulnerable libraries"""
        return {
            "okhttp-2.": {
                "cve": "Multiple",
                "risk": "MEDIUM",
                "description": "Outdated OkHttp with known vulnerabilities",
            },
            "gson-2.2": {
                "cve": "CVE-2022-25647",
                "risk": "HIGH",
                "description": "Gson deserialization vulnerability",
            },
            "jackson-databind-2.9": {
                "cve": "Multiple",
                "risk": "CRITICAL",
                "description": "Jackson deserialization vulnerabilities",
            },
            "log4j-1.": {
                "cve": "CVE-2021-44228",
                "risk": "CRITICAL",
                "description": "Log4j RCE vulnerability",
            },
            "commons-collections-3.": {
                "cve": "CVE-2015-7501",
                "risk": "CRITICAL",
                "description": "Apache Commons Collections deserialization",
            },
            "retrofit-1.": {
                "cve": "Multiple",
                "risk": "MEDIUM",
                "description": "Outdated Retrofit library",
            },
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
    
    async def analyze_apk(self, apk_path: str) -> MobileApp:
        """
        Analyze Android APK file
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            MobileApp with analysis results
        """
        start_time = datetime.now()
        self._emit("analysis_started", {"path": apk_path})
        
        # Calculate file hash
        with open(apk_path, 'rb') as f:
            file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        app = MobileApp(
            id=hashlib.md5(apk_path.encode()).hexdigest()[:12],
            name="Unknown",
            package_name="",
            version="Unknown",
            platform=MobilePlatform.ANDROID,
            file_path=apk_path,
            file_hash=file_hash,
            file_size=len(file_data),
        )
        
        # Extract and parse APK
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    zf.extractall(temp_dir)
                
                # Parse AndroidManifest.xml
                manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    await self._parse_manifest(app, manifest_path)
                
                # Analyze DEX files
                for filename in os.listdir(temp_dir):
                    if filename.endswith('.dex'):
                        dex_path = os.path.join(temp_dir, filename)
                        await self._analyze_dex(app, dex_path)
                
                # Check native libraries
                lib_dir = os.path.join(temp_dir, "lib")
                if os.path.exists(lib_dir):
                    await self._analyze_native_libs(app, lib_dir)
                
                # Analyze resources
                res_dir = os.path.join(temp_dir, "res")
                if os.path.exists(res_dir):
                    await self._analyze_resources(app, res_dir)
                
            except Exception as e:
                self.logger.error(f"APK extraction error: {e}")
        
        app.analysis_time = (datetime.now() - start_time).total_seconds()
        app.risk_score = self._calculate_risk_score(app)
        
        self.apps[app.id] = app
        self._emit("analysis_completed", {"app": app})
        
        return app
    
    async def _parse_manifest(self, app: MobileApp, manifest_path: str):
        """Parse AndroidManifest.xml (binary or text)"""
        try:
            # Try to read as text first
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if '<?xml' in content:
                # Text XML
                root = ET.fromstring(content)
            else:
                # Binary XML - extract basic info via strings
                with open(manifest_path, 'rb') as f:
                    binary_data = f.read()
                
                # Extract strings from binary manifest
                strings = self._extract_strings_binary(binary_data)
                
                for s in strings:
                    if s.startswith("com.") or s.startswith("org.") or s.startswith("net."):
                        if not app.package_name and "." in s:
                            app.package_name = s
                    if "android.permission." in s:
                        app.permissions.append(s)
                
                return
            
            # Parse XML manifest
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            
            # Package info
            app.package_name = root.get('package', 'Unknown')
            app.version = root.get('{http://schemas.android.com/apk/res/android}versionName', 'Unknown')
            
            # SDK versions
            uses_sdk = root.find('uses-sdk')
            if uses_sdk is not None:
                app.min_sdk = int(uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', 0) or 0)
                app.target_sdk = int(uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', 0) or 0)
            
            # Permissions
            for perm in root.findall('uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                if perm_name:
                    app.permissions.append(perm_name)
            
            # Application components
            application = root.find('application')
            if application is not None:
                app.name = application.get('{http://schemas.android.com/apk/res/android}label', 'Unknown')
                
                # Activities
                for activity in application.findall('activity'):
                    name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                    if name:
                        app.activities.append(name)
                
                # Services
                for service in application.findall('service'):
                    name = service.get('{http://schemas.android.com/apk/res/android}name', '')
                    if name:
                        app.services.append(name)
                
                # Receivers
                for receiver in application.findall('receiver'):
                    name = receiver.get('{http://schemas.android.com/apk/res/android}name', '')
                    if name:
                        app.receivers.append(name)
                
                # Content providers
                for provider in application.findall('provider'):
                    name = provider.get('{http://schemas.android.com/apk/res/android}name', '')
                    if name:
                        app.providers.append(name)
                
        except Exception as e:
            self.logger.error(f"Manifest parsing error: {e}")
    
    def _extract_strings_binary(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings
    
    async def _analyze_dex(self, app: MobileApp, dex_path: str):
        """Analyze DEX file for security issues"""
        with open(dex_path, 'rb') as f:
            dex_data = f.read()
        
        # Extract strings for analysis
        strings = self._extract_strings_binary(dex_data)
        
        # Look for security issues
        for string in strings:
            # Check for hardcoded URLs
            if string.startswith('http://'):
                app.vulnerabilities.append({
                    "type": VulnCategory.INSECURE_COMMUNICATION.value,
                    "severity": "MEDIUM",
                    "title": "HTTP URL Found",
                    "description": f"Insecure HTTP URL: {string[:100]}",
                })
            
            # Check for debugging flags
            if 'android:debuggable' in string or 'setDebugMode' in string:
                app.vulnerabilities.append({
                    "type": VulnCategory.REVERSE_ENGINEERING.value,
                    "severity": "HIGH",
                    "title": "Debug Mode Detected",
                    "description": "Application may have debugging enabled",
                })
            
            # Check for weak crypto
            if any(weak in string.lower() for weak in ['des', 'md5', 'sha1', 'ecb']):
                if 'encrypt' in string.lower() or 'cipher' in string.lower():
                    app.vulnerabilities.append({
                        "type": VulnCategory.INSUFFICIENT_CRYPTOGRAPHY.value,
                        "severity": "HIGH",
                        "title": "Weak Cryptography",
                        "description": f"Potentially weak crypto: {string[:50]}",
                    })
    
    async def _analyze_native_libs(self, app: MobileApp, lib_dir: str):
        """Analyze native libraries"""
        for arch in os.listdir(lib_dir):
            arch_dir = os.path.join(lib_dir, arch)
            if os.path.isdir(arch_dir):
                for lib in os.listdir(arch_dir):
                    app.libraries.append(f"{arch}/{lib}")
                    
                    # Check for known vulnerable libraries
                    for vuln_lib, info in self.vuln_libraries.items():
                        if vuln_lib in lib.lower():
                            app.vulnerabilities.append({
                                "type": "vulnerable_library",
                                "severity": info["risk"],
                                "title": f"Vulnerable Library: {lib}",
                                "description": info["description"],
                                "cve": info.get("cve"),
                            })
    
    async def _analyze_resources(self, app: MobileApp, res_dir: str):
        """Analyze resources for sensitive data"""
        for root, dirs, files in os.walk(res_dir):
            for filename in files:
                if filename.endswith('.xml'):
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Search for secrets in resources
                        for pattern in self.secret_patterns:
                            matches = re.findall(pattern["pattern"], content, re.I)
                            for match in matches:
                                app.vulnerabilities.append({
                                    "type": VulnCategory.INSECURE_DATA_STORAGE.value,
                                    "severity": pattern["risk"],
                                    "title": f"Hardcoded {pattern['name']}",
                                    "description": f"Found in {filename}",
                                    "evidence": match[:50] if isinstance(match, str) else str(match)[:50],
                                })
                    except:
                        pass
    
    async def perform_static_analysis(self, app_id: str) -> StaticAnalysisResult:
        """
        Perform comprehensive static analysis
        
        Args:
            app_id: Application ID
            
        Returns:
            Static analysis results
        """
        app = self.apps.get(app_id)
        if not app:
            raise ValueError(f"App {app_id} not found")
        
        start_time = datetime.now()
        self._emit("static_analysis_started", {"app": app_id})
        
        result = StaticAnalysisResult(app_id=app_id)
        
        # Analyze permissions
        await self._analyze_permissions(app, result)
        
        # Check for exported components
        await self._check_exported_components(app, result)
        
        # Analyze cryptography
        await self._analyze_cryptography(app, result)
        
        # Check for WebView issues
        await self._check_webview_issues(app, result)
        
        # Extract sensitive data
        await self._extract_sensitive_data(app, result)
        
        result.analysis_time = (datetime.now() - start_time).total_seconds()
        
        self.analyses[app_id] = result
        self._emit("static_analysis_completed", {"result": result})
        
        return result
    
    async def _analyze_permissions(self, app: MobileApp, result: StaticAnalysisResult):
        """Analyze permission usage"""
        for perm in app.permissions:
            if perm in self.dangerous_permissions:
                info = self.dangerous_permissions[perm]
                finding = SecurityFinding(
                    id=hashlib.md5(perm.encode()).hexdigest()[:8],
                    category=VulnCategory.INSECURE_DATA_STORAGE,
                    risk_level=AppRiskLevel[info["risk"]],
                    title=f"Dangerous Permission: {perm.split('.')[-1]}",
                    description=info["description"],
                    location="AndroidManifest.xml",
                    recommendation=f"Review necessity of {perm}",
                    owasp_category="M1-M2",
                )
                result.findings.append(finding)
    
    async def _check_exported_components(self, app: MobileApp, result: StaticAnalysisResult):
        """Check for exported components security"""
        # Check activities with potential issues
        for activity in app.activities:
            if any(word in activity.lower() for word in ['main', 'launcher', 'splash']):
                continue  # Skip main activities
            
            result.exported_components.append({
                "type": "activity",
                "name": activity,
                "risk": "Review for unintended export",
            })
        
        # Check content providers
        for provider in app.providers:
            finding = SecurityFinding(
                id=hashlib.md5(provider.encode()).hexdigest()[:8],
                category=VulnCategory.INSECURE_DATA_STORAGE,
                risk_level=AppRiskLevel.MEDIUM,
                title=f"Content Provider: {provider.split('.')[-1]}",
                description="Content provider may expose sensitive data",
                location=provider,
                recommendation="Verify provider permissions and path restrictions",
            )
            result.findings.append(finding)
    
    async def _analyze_cryptography(self, app: MobileApp, result: StaticAnalysisResult):
        """Analyze cryptographic implementations"""
        crypto_issues = []
        
        # Check for weak algorithms in vulnerabilities already found
        for vuln in app.vulnerabilities:
            if vuln.get("type") == VulnCategory.INSUFFICIENT_CRYPTOGRAPHY.value:
                crypto_issues.append({
                    "issue": vuln.get("title"),
                    "description": vuln.get("description"),
                    "recommendation": "Use AES-256-GCM or ChaCha20-Poly1305",
                })
        
        result.crypto_issues = crypto_issues
    
    async def _check_webview_issues(self, app: MobileApp, result: StaticAnalysisResult):
        """Check for WebView security issues"""
        webview_issues = []
        
        # Check for activities that might use WebView
        for activity in app.activities:
            if 'webview' in activity.lower() or 'web' in activity.lower():
                webview_issues.append({
                    "activity": activity,
                    "potential_issues": [
                        "JavaScript enabled without verification",
                        "File access from JavaScript",
                        "Mixed content allowed",
                    ],
                })
        
        result.webview_issues = webview_issues
    
    async def _extract_sensitive_data(self, app: MobileApp, result: StaticAnalysisResult):
        """Extract sensitive data from app"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(app.file_path, 'r') as zf:
                    zf.extractall(temp_dir)
                
                # Search all files for sensitive data
                for root, dirs, files in os.walk(temp_dir):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        try:
                            with open(file_path, 'rb') as f:
                                content = f.read()
                            
                            text = content.decode('utf-8', errors='ignore')
                            
                            # Extract URLs
                            urls = re.findall(r'https?://[^\s<>"\']+', text)
                            result.urls.extend(urls[:100])
                            
                            # Extract IPs
                            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
                            result.ip_addresses.extend(ips[:50])
                            
                            # Extract emails
                            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
                            result.email_addresses.extend(emails[:50])
                            
                            # Check for API keys
                            for pattern in self.secret_patterns:
                                matches = re.findall(pattern["pattern"], text, re.I)
                                for match in matches:
                                    result.api_keys.append({
                                        "type": pattern["name"],
                                        "value": match[:50] if isinstance(match, str) else str(match)[:50],
                                        "file": filename,
                                    })
                        except:
                            pass
                
                # Deduplicate
                result.urls = list(set(result.urls))
                result.ip_addresses = list(set(result.ip_addresses))
                result.email_addresses = list(set(result.email_addresses))
                
        except Exception as e:
            self.logger.error(f"Sensitive data extraction error: {e}")
    
    def _calculate_risk_score(self, app: MobileApp) -> float:
        """Calculate overall risk score"""
        score = 0.0
        
        # Permission-based scoring
        dangerous_count = sum(1 for p in app.permissions if p in self.dangerous_permissions)
        score += dangerous_count * 0.5
        
        # Vulnerability-based scoring
        severity_weights = {
            "CRITICAL": 3.0,
            "HIGH": 2.0,
            "MEDIUM": 1.0,
            "LOW": 0.5,
        }
        
        for vuln in app.vulnerabilities:
            severity = vuln.get("severity", "LOW")
            score += severity_weights.get(severity, 0.5)
        
        # SDK version penalty
        if app.min_sdk and app.min_sdk < 21:
            score += 1.0  # Old Android version
        
        if app.target_sdk and app.target_sdk < 28:
            score += 0.5  # Not targeting recent Android
        
        return min(score, 10.0)
    
    async def analyze_ipa(self, ipa_path: str) -> MobileApp:
        """
        Analyze iOS IPA file
        
        Args:
            ipa_path: Path to IPA file
            
        Returns:
            MobileApp with analysis results
        """
        start_time = datetime.now()
        self._emit("analysis_started", {"path": ipa_path})
        
        with open(ipa_path, 'rb') as f:
            file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        app = MobileApp(
            id=hashlib.md5(ipa_path.encode()).hexdigest()[:12],
            name="Unknown",
            package_name="",
            version="Unknown",
            platform=MobilePlatform.IOS,
            file_path=ipa_path,
            file_hash=file_hash,
            file_size=len(file_data),
        )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                with zipfile.ZipFile(ipa_path, 'r') as zf:
                    zf.extractall(temp_dir)
                
                # Find Info.plist
                payload_dir = os.path.join(temp_dir, "Payload")
                if os.path.exists(payload_dir):
                    for item in os.listdir(payload_dir):
                        if item.endswith('.app'):
                            app_dir = os.path.join(payload_dir, item)
                            plist_path = os.path.join(app_dir, "Info.plist")
                            
                            if os.path.exists(plist_path):
                                await self._parse_info_plist(app, plist_path)
                            
                            # Analyze binary
                            for filename in os.listdir(app_dir):
                                file_path = os.path.join(app_dir, filename)
                                if os.path.isfile(file_path) and not filename.endswith(('.plist', '.nib', '.car')):
                                    await self._analyze_ios_binary(app, file_path)
                            
                            break
                
            except Exception as e:
                self.logger.error(f"IPA extraction error: {e}")
        
        app.analysis_time = (datetime.now() - start_time).total_seconds()
        app.risk_score = self._calculate_risk_score(app)
        
        self.apps[app.id] = app
        self._emit("analysis_completed", {"app": app})
        
        return app
    
    async def _parse_info_plist(self, app: MobileApp, plist_path: str):
        """Parse iOS Info.plist"""
        try:
            # Try to read as text (some plists are XML)
            with open(plist_path, 'rb') as f:
                content = f.read()
            
            # Check if it's binary plist
            if content.startswith(b'bplist'):
                # Would need plistlib for binary plist
                strings = self._extract_strings_binary(content)
                for s in strings:
                    if s.startswith('com.') or s.startswith('org.'):
                        if not app.package_name:
                            app.package_name = s
                            break
            else:
                # XML plist
                text = content.decode('utf-8', errors='ignore')
                
                # Extract bundle identifier
                bundle_match = re.search(r'<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>', text)
                if bundle_match:
                    app.package_name = bundle_match.group(1)
                
                # Extract version
                version_match = re.search(r'<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>', text)
                if version_match:
                    app.version = version_match.group(1)
                
                # Extract app name
                name_match = re.search(r'<key>CFBundleName</key>\s*<string>([^<]+)</string>', text)
                if name_match:
                    app.name = name_match.group(1)
                
                # Check for transport security
                if 'NSAppTransportSecurity' in text and 'NSAllowsArbitraryLoads' in text:
                    if 'true' in text.lower():
                        app.vulnerabilities.append({
                            "type": VulnCategory.INSECURE_COMMUNICATION.value,
                            "severity": "HIGH",
                            "title": "ATS Disabled",
                            "description": "App Transport Security allows arbitrary loads",
                        })
                
        except Exception as e:
            self.logger.error(f"Info.plist parsing error: {e}")
    
    async def _analyze_ios_binary(self, app: MobileApp, binary_path: str):
        """Analyze iOS binary for security issues"""
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Check for anti-debugging measures
            if b'ptrace' in binary_data:
                app.metadata["anti_debug"] = True
            
            # Check for encryption
            if b'_encrypt' in binary_data or b'CCCrypt' in binary_data:
                app.metadata["uses_crypto"] = True
            
            # Check for jailbreak detection
            jb_indicators = [b'cydia://', b'/Applications/Cydia.app', b'substrate']
            for indicator in jb_indicators:
                if indicator in binary_data:
                    app.metadata["jailbreak_detection"] = True
                    break
            
            # Extract strings for sensitive data
            strings = self._extract_strings_binary(binary_data)
            
            for string in strings:
                # Check for hardcoded URLs
                if string.startswith('http://'):
                    app.vulnerabilities.append({
                        "type": VulnCategory.INSECURE_COMMUNICATION.value,
                        "severity": "MEDIUM",
                        "title": "HTTP URL Found",
                        "description": f"Insecure URL: {string[:80]}",
                    })
                
                # Check for API keys
                for pattern in self.secret_patterns:
                    if re.match(pattern["pattern"], string):
                        app.vulnerabilities.append({
                            "type": VulnCategory.INSECURE_DATA_STORAGE.value,
                            "severity": pattern["risk"],
                            "title": f"Hardcoded {pattern['name']}",
                            "description": f"Found in binary",
                        })
                        break
                        
        except Exception as e:
            self.logger.error(f"Binary analysis error: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        total_vulns = sum(len(a.vulnerabilities) for a in self.apps.values())
        
        platform_counts = {"android": 0, "ios": 0}
        for app in self.apps.values():
            platform_counts[app.platform.value] += 1
        
        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for app in self.apps.values():
            if app.risk_score >= 8:
                risk_distribution["critical"] += 1
            elif app.risk_score >= 6:
                risk_distribution["high"] += 1
            elif app.risk_score >= 4:
                risk_distribution["medium"] += 1
            else:
                risk_distribution["low"] += 1
        
        return {
            "total_apps": len(self.apps),
            "total_vulnerabilities": total_vulns,
            "platform_distribution": platform_counts,
            "risk_distribution": risk_distribution,
            "analyses_completed": len(self.analyses),
        }
