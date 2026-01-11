"""
HydraRecon Advanced Mobile Security Module
Comprehensive Android and iOS security analysis
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class MobilePlatform(Enum):
    """Mobile platform types"""
    ANDROID = "android"
    IOS = "ios"
    FLUTTER = "flutter"
    REACT_NATIVE = "react_native"
    XAMARIN = "xamarin"


class SeverityLevel(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    """OWASP Mobile Top 10 categories"""
    M1_IMPROPER_PLATFORM = "M1 - Improper Platform Usage"
    M2_INSECURE_DATA = "M2 - Insecure Data Storage"
    M3_INSECURE_COMM = "M3 - Insecure Communication"
    M4_INSECURE_AUTH = "M4 - Insecure Authentication"
    M5_CRYPTO = "M5 - Insufficient Cryptography"
    M6_INSECURE_AUTH = "M6 - Insecure Authorization"
    M7_CODE_QUALITY = "M7 - Client Code Quality"
    M8_CODE_TAMPERING = "M8 - Code Tampering"
    M9_REVERSE_ENG = "M9 - Reverse Engineering"
    M10_EXTRANEOUS = "M10 - Extraneous Functionality"


@dataclass
class MobileAppInfo:
    """Mobile application metadata"""
    app_name: str
    package_name: str
    version_name: str
    version_code: int
    platform: MobilePlatform
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    signing_info: Dict[str, Any] = field(default_factory=dict)
    file_path: str = ""
    file_hash: str = ""
    file_size: int = 0


@dataclass
class SecurityFinding:
    """Security analysis finding"""
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel
    category: VulnerabilityCategory
    location: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: float = 0.0


@dataclass
class APIEndpoint:
    """Discovered API endpoint"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    parameters: List[str] = field(default_factory=list)
    requires_auth: bool = False
    found_in: str = ""


@dataclass
class HardcodedSecret:
    """Hardcoded secret detection"""
    secret_type: str
    value: str
    location: str
    line_number: int = 0
    entropy: float = 0.0


class AndroidAnalyzer:
    """Android APK analysis engine"""
    
    def __init__(self):
        self.dangerous_permissions = {
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
        }
        
        self.secret_patterns = {
            'api_key': [
                r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                r'(?:x-api-key|api-key)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            ],
            'aws_key': [
                r'AKIA[0-9A-Z]{16}',
                r'(?:aws[_-]?access[_-]?key|access[_-]?key[_-]?id)\s*[=:]\s*["\']([A-Z0-9]{20})["\']',
            ],
            'google_api': [
                r'AIza[0-9A-Za-z_-]{35}',
            ],
            'firebase': [
                r'(?:firebase|fcm)[_-]?(?:key|token|secret)\s*[=:]\s*["\']([a-zA-Z0-9_-]+)["\']',
            ],
            'oauth': [
                r'(?:client[_-]?secret|oauth[_-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            ],
            'jwt': [
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            ],
            'private_key': [
                r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            ],
            'password': [
                r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
            ],
        }
        
    def extract_apk(self, apk_path: str, output_dir: str) -> bool:
        """Extract APK contents"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                apk.extractall(output_dir)
            return True
        except Exception as e:
            logger.error(f"Failed to extract APK: {e}")
            return False
            
    def parse_manifest(self, manifest_path: str) -> Optional[MobileAppInfo]:
        """Parse AndroidManifest.xml (binary or decoded)"""
        try:
            # Try to read as text first (decoded manifest)
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse basic info from manifest
            app_info = MobileAppInfo(
                app_name=self._extract_xml_attr(content, 'android:label'),
                package_name=self._extract_xml_attr(content, 'package'),
                version_name=self._extract_xml_attr(content, 'android:versionName'),
                version_code=int(self._extract_xml_attr(content, 'android:versionCode') or '1'),
                platform=MobilePlatform.ANDROID,
                min_sdk=self._parse_sdk(self._extract_xml_attr(content, 'android:minSdkVersion')),
                target_sdk=self._parse_sdk(self._extract_xml_attr(content, 'android:targetSdkVersion')),
            )
            
            # Extract permissions
            app_info.permissions = self._extract_permissions(content)
            
            # Extract components
            app_info.activities = self._extract_components(content, 'activity')
            app_info.services = self._extract_components(content, 'service')
            app_info.receivers = self._extract_components(content, 'receiver')
            app_info.providers = self._extract_components(content, 'provider')
            
            return app_info
            
        except Exception as e:
            logger.error(f"Failed to parse manifest: {e}")
            return None
            
    def _extract_xml_attr(self, content: str, attr: str) -> str:
        """Extract XML attribute value"""
        pattern = rf'{attr}\s*=\s*["\']([^"\']*)["\']'
        match = re.search(pattern, content)
        return match.group(1) if match else ""
        
    def _parse_sdk(self, value: str) -> Optional[int]:
        """Parse SDK version"""
        try:
            return int(value) if value else None
        except ValueError:
            return None
            
    def _extract_permissions(self, content: str) -> List[str]:
        """Extract used permissions"""
        pattern = r'<uses-permission[^>]*android:name\s*=\s*["\']([^"\']+)["\']'
        return re.findall(pattern, content)
        
    def _extract_components(self, content: str, component_type: str) -> List[str]:
        """Extract component names"""
        pattern = rf'<{component_type}[^>]*android:name\s*=\s*["\']([^"\']+)["\']'
        return re.findall(pattern, content)
        
    def analyze_permissions(self, app_info: MobileAppInfo) -> List[SecurityFinding]:
        """Analyze permission usage"""
        findings = []
        
        dangerous = set(app_info.permissions) & self.dangerous_permissions
        
        for perm in dangerous:
            findings.append(SecurityFinding(
                finding_id=f"PERM_{hashlib.md5(perm.encode()).hexdigest()[:8]}",
                title=f"Dangerous Permission: {perm.split('.')[-1]}",
                description=f"Application requests dangerous permission: {perm}",
                severity=SeverityLevel.MEDIUM,
                category=VulnerabilityCategory.M1_IMPROPER_PLATFORM,
                evidence=perm,
                remediation="Review if this permission is necessary and implement runtime permission requests"
            ))
            
        # Check for permission combinations
        location_perms = [p for p in app_info.permissions if 'LOCATION' in p]
        if len(location_perms) > 1:
            findings.append(SecurityFinding(
                finding_id="PERM_LOC_MULT",
                title="Multiple Location Permissions",
                description="Application requests multiple location permissions",
                severity=SeverityLevel.LOW,
                category=VulnerabilityCategory.M1_IMPROPER_PLATFORM,
                evidence=str(location_perms)
            ))
            
        return findings
        
    def analyze_exported_components(self, app_info: MobileAppInfo, manifest_content: str) -> List[SecurityFinding]:
        """Analyze exported components"""
        findings = []
        
        # Check for exported components without permission protection
        exported_pattern = r'android:exported\s*=\s*["\']true["\']'
        protected_pattern = r'android:permission\s*='
        
        for activity in app_info.activities:
            activity_block = self._extract_component_block(manifest_content, 'activity', activity)
            
            if activity_block:
                is_exported = re.search(exported_pattern, activity_block)
                is_protected = re.search(protected_pattern, activity_block)
                
                if is_exported and not is_protected:
                    findings.append(SecurityFinding(
                        finding_id=f"EXP_ACT_{hashlib.md5(activity.encode()).hexdigest()[:8]}",
                        title=f"Exported Activity Without Protection: {activity.split('.')[-1]}",
                        description=f"Activity {activity} is exported without permission protection",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.M1_IMPROPER_PLATFORM,
                        location=activity,
                        remediation="Add android:permission attribute or set android:exported='false'"
                    ))
                    
        return findings
        
    def _extract_component_block(self, content: str, comp_type: str, name: str) -> Optional[str]:
        """Extract component XML block"""
        pattern = rf'<{comp_type}[^>]*android:name\s*=\s*["\']\.?{re.escape(name.split(".")[-1])}["\'][^>]*(?:/>|>.*?</{comp_type}>)'
        match = re.search(pattern, content, re.DOTALL)
        return match.group(0) if match else None
        
    def scan_for_secrets(self, extracted_dir: str) -> List[HardcodedSecret]:
        """Scan for hardcoded secrets"""
        secrets = []
        
        # Scan relevant files
        file_extensions = ['.java', '.kt', '.xml', '.json', '.properties', '.js']
        
        for root, dirs, files in os.walk(extracted_dir):
            # Skip compiled files
            dirs[:] = [d for d in dirs if d not in ['build', 'bin', '.git']]
            
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    secrets.extend(self._scan_file_for_secrets(file_path))
                    
        return secrets
        
    def _scan_file_for_secrets(self, file_path: str) -> List[HardcodedSecret]:
        """Scan single file for secrets"""
        secrets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                for secret_type, patterns in self.secret_patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            value = match.group(1) if match.groups() else match.group(0)
                            
                            # Calculate entropy
                            entropy = self._calculate_entropy(value)
                            
                            if entropy > 3.0:  # Only report high-entropy strings
                                secrets.append(HardcodedSecret(
                                    secret_type=secret_type,
                                    value=value[:20] + "..." if len(value) > 20 else value,
                                    location=file_path,
                                    line_number=line_num,
                                    entropy=entropy
                                ))
                                
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
            
        return secrets
        
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string"""
        if not s:
            return 0.0
            
        import math
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)
        
    def extract_urls(self, extracted_dir: str) -> List[str]:
        """Extract URLs and endpoints from code"""
        urls = set()
        
        url_patterns = [
            r'https?://[^\s"\'<>\\)}\]]+',
            r'wss?://[^\s"\'<>\\)}\]]+',
        ]
        
        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                if file.endswith(('.java', '.kt', '.xml', '.json', '.js', '.html')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern in url_patterns:
                            matches = re.findall(pattern, content)
                            urls.update(matches)
                            
                    except Exception as e:
                        pass
                        
        return list(urls)


class IOSAnalyzer:
    """iOS IPA analysis engine"""
    
    def __init__(self):
        self.sensitive_apis = {
            'keychain': ['SecItemAdd', 'SecItemCopyMatching', 'SecItemUpdate', 'SecItemDelete'],
            'crypto': ['CCCrypt', 'SecKeyEncrypt', 'SecKeyDecrypt'],
            'network': ['NSURLSession', 'URLSession', 'Alamofire', 'AFNetworking'],
            'data': ['NSUserDefaults', 'UserDefaults', 'FileManager', 'CoreData'],
            'biometric': ['LAContext', 'canEvaluatePolicy', 'evaluatePolicy'],
        }
        
    def extract_ipa(self, ipa_path: str, output_dir: str) -> bool:
        """Extract IPA contents"""
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa:
                ipa.extractall(output_dir)
            return True
        except Exception as e:
            logger.error(f"Failed to extract IPA: {e}")
            return False
            
    def parse_info_plist(self, plist_path: str) -> Optional[MobileAppInfo]:
        """Parse Info.plist"""
        try:
            import plistlib
            
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
                
            return MobileAppInfo(
                app_name=plist.get('CFBundleDisplayName', plist.get('CFBundleName', '')),
                package_name=plist.get('CFBundleIdentifier', ''),
                version_name=plist.get('CFBundleShortVersionString', ''),
                version_code=int(plist.get('CFBundleVersion', '1').split('.')[0]),
                platform=MobilePlatform.IOS,
                min_sdk=self._parse_ios_version(plist.get('MinimumOSVersion')),
            )
            
        except ImportError:
            logger.warning("plistlib not available, using fallback parser")
            return self._parse_plist_fallback(plist_path)
        except Exception as e:
            logger.error(f"Failed to parse Info.plist: {e}")
            return None
            
    def _parse_ios_version(self, version: Optional[str]) -> Optional[int]:
        """Parse iOS version to major number"""
        if version:
            try:
                return int(version.split('.')[0])
            except ValueError:
                return None
        return None
        
    def _parse_plist_fallback(self, plist_path: str) -> Optional[MobileAppInfo]:
        """Fallback plist parser for XML format"""
        try:
            with open(plist_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            def extract_value(key: str) -> str:
                pattern = rf'<key>{key}</key>\s*<string>([^<]*)</string>'
                match = re.search(pattern, content)
                return match.group(1) if match else ""
                
            return MobileAppInfo(
                app_name=extract_value('CFBundleDisplayName') or extract_value('CFBundleName'),
                package_name=extract_value('CFBundleIdentifier'),
                version_name=extract_value('CFBundleShortVersionString'),
                version_code=int(extract_value('CFBundleVersion').split('.')[0] or '1'),
                platform=MobilePlatform.IOS,
            )
            
        except Exception as e:
            logger.error(f"Fallback plist parsing failed: {e}")
            return None
            
    def analyze_ats_settings(self, plist_content: str) -> List[SecurityFinding]:
        """Analyze App Transport Security settings"""
        findings = []
        
        # Check for ATS disabled
        if 'NSAllowsArbitraryLoads' in plist_content:
            if '<true/>' in plist_content[plist_content.find('NSAllowsArbitraryLoads'):
                                         plist_content.find('NSAllowsArbitraryLoads') + 100]:
                findings.append(SecurityFinding(
                    finding_id="IOS_ATS_DISABLED",
                    title="App Transport Security Disabled",
                    description="NSAllowsArbitraryLoads is set to true, disabling ATS",
                    severity=SeverityLevel.HIGH,
                    category=VulnerabilityCategory.M3_INSECURE_COMM,
                    remediation="Enable ATS by removing NSAllowsArbitraryLoads or setting to false"
                ))
                
        # Check for HTTP exceptions
        if 'NSExceptionDomains' in plist_content:
            http_exception_pattern = r'NSExceptionAllowsInsecureHTTPLoads\s*</key>\s*<true/>'
            if re.search(http_exception_pattern, plist_content):
                findings.append(SecurityFinding(
                    finding_id="IOS_ATS_HTTP_EXCEPTION",
                    title="ATS HTTP Exception Configured",
                    description="Application allows insecure HTTP connections to specific domains",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.M3_INSECURE_COMM,
                    remediation="Review HTTP exceptions and use HTTPS where possible"
                ))
                
        return findings
        
    def analyze_entitlements(self, extracted_dir: str) -> List[SecurityFinding]:
        """Analyze iOS entitlements"""
        findings = []
        
        # Find embedded mobileprovision
        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                if file.endswith('.mobileprovision') or file.endswith('.entitlements'):
                    file_path = os.path.join(root, file)
                    findings.extend(self._check_entitlements(file_path))
                    
        return findings
        
    def _check_entitlements(self, file_path: str) -> List[SecurityFinding]:
        """Check entitlement file"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check for debug entitlement
            if 'get-task-allow' in content:
                if '<true/>' in content[content.find('get-task-allow'):content.find('get-task-allow') + 80]:
                    findings.append(SecurityFinding(
                        finding_id="IOS_DEBUG_ENTITLEMENT",
                        title="Debug Entitlement Present",
                        description="get-task-allow entitlement is true, allowing debugging",
                        severity=SeverityLevel.MEDIUM,
                        category=VulnerabilityCategory.M9_REVERSE_ENG,
                        location=file_path,
                        remediation="Ensure production builds have get-task-allow set to false"
                    ))
                    
        except Exception as e:
            logger.debug(f"Error checking entitlements: {e}")
            
        return findings


class MobileSecurityScanner:
    """Unified mobile security scanner"""
    
    def __init__(self):
        self.android_analyzer = AndroidAnalyzer()
        self.ios_analyzer = IOSAnalyzer()
        
    async def scan_app(self, app_path: str) -> Dict[str, Any]:
        """Scan mobile application"""
        results = {
            'scan_id': hashlib.md5(f"{app_path}{datetime.now()}".encode()).hexdigest()[:12],
            'timestamp': datetime.now().isoformat(),
            'app_path': app_path,
            'platform': None,
            'app_info': None,
            'findings': [],
            'secrets': [],
            'urls': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Detect platform
        if app_path.endswith('.apk'):
            results['platform'] = 'android'
            await self._scan_android(app_path, results)
        elif app_path.endswith('.ipa'):
            results['platform'] = 'ios'
            await self._scan_ios(app_path, results)
        else:
            raise ValueError(f"Unsupported file type: {app_path}")
            
        # Calculate summary
        for finding in results['findings']:
            results['summary'][finding['severity'].lower()] += 1
            
        return results
        
    async def _scan_android(self, apk_path: str, results: Dict) -> None:
        """Scan Android APK"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Extract APK
            if not self.android_analyzer.extract_apk(apk_path, tmpdir):
                raise RuntimeError("Failed to extract APK")
                
            # Parse manifest
            manifest_path = os.path.join(tmpdir, 'AndroidManifest.xml')
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    manifest_content = f.read()
                    
                app_info = self.android_analyzer.parse_manifest(manifest_path)
                
                if app_info:
                    results['app_info'] = {
                        'name': app_info.app_name,
                        'package': app_info.package_name,
                        'version': app_info.version_name,
                        'min_sdk': app_info.min_sdk,
                        'target_sdk': app_info.target_sdk,
                        'permissions_count': len(app_info.permissions),
                        'activities_count': len(app_info.activities),
                        'services_count': len(app_info.services),
                    }
                    
                    # Analyze permissions
                    perm_findings = self.android_analyzer.analyze_permissions(app_info)
                    
                    # Analyze exported components
                    export_findings = self.android_analyzer.analyze_exported_components(app_info, manifest_content)
                    
                    for finding in perm_findings + export_findings:
                        results['findings'].append({
                            'id': finding.finding_id,
                            'title': finding.title,
                            'description': finding.description,
                            'severity': finding.severity.value,
                            'category': finding.category.value,
                            'location': finding.location,
                            'remediation': finding.remediation
                        })
                        
            # Scan for secrets
            secrets = self.android_analyzer.scan_for_secrets(tmpdir)
            for secret in secrets:
                results['secrets'].append({
                    'type': secret.secret_type,
                    'value': secret.value,
                    'location': secret.location,
                    'line': secret.line_number,
                    'entropy': round(secret.entropy, 2)
                })
                
                # Add finding for each secret
                results['findings'].append({
                    'id': f"SECRET_{secret.secret_type.upper()}",
                    'title': f"Hardcoded {secret.secret_type.replace('_', ' ').title()}",
                    'description': f"Potential hardcoded {secret.secret_type} found",
                    'severity': SeverityLevel.HIGH.value,
                    'category': VulnerabilityCategory.M2_INSECURE_DATA.value,
                    'location': f"{secret.location}:{secret.line_number}",
                    'remediation': "Move secrets to secure storage or environment variables"
                })
                
            # Extract URLs
            results['urls'] = self.android_analyzer.extract_urls(tmpdir)
            
    async def _scan_ios(self, ipa_path: str, results: Dict) -> None:
        """Scan iOS IPA"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Extract IPA
            if not self.ios_analyzer.extract_ipa(ipa_path, tmpdir):
                raise RuntimeError("Failed to extract IPA")
                
            # Find Info.plist
            for root, dirs, files in os.walk(tmpdir):
                if 'Info.plist' in files:
                    plist_path = os.path.join(root, 'Info.plist')
                    app_info = self.ios_analyzer.parse_info_plist(plist_path)
                    
                    if app_info:
                        results['app_info'] = {
                            'name': app_info.app_name,
                            'bundle_id': app_info.package_name,
                            'version': app_info.version_name,
                            'min_ios': app_info.min_sdk,
                        }
                        
                    # Check ATS settings
                    try:
                        with open(plist_path, 'r', encoding='utf-8', errors='ignore') as f:
                            plist_content = f.read()
                        ats_findings = self.ios_analyzer.analyze_ats_settings(plist_content)
                        
                        for finding in ats_findings:
                            results['findings'].append({
                                'id': finding.finding_id,
                                'title': finding.title,
                                'description': finding.description,
                                'severity': finding.severity.value,
                                'category': finding.category.value,
                                'remediation': finding.remediation
                            })
                    except Exception:
                        pass
                        
                    break
                    
            # Analyze entitlements
            entitlement_findings = self.ios_analyzer.analyze_entitlements(tmpdir)
            for finding in entitlement_findings:
                results['findings'].append({
                    'id': finding.finding_id,
                    'title': finding.title,
                    'description': finding.description,
                    'severity': finding.severity.value,
                    'category': finding.category.value,
                    'location': finding.location,
                    'remediation': finding.remediation
                })


class DynamicAnalyzer:
    """Dynamic mobile app analysis"""
    
    def __init__(self):
        self.frida_scripts = self._load_frida_scripts()
        
    def _load_frida_scripts(self) -> Dict[str, str]:
        """Load Frida scripts for hooking"""
        return {
            'ssl_pinning_bypass': '''
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManagerImpl = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    console.log("[*] SSL Pinning Bypass Loaded");
});
''',
            'root_detection_bypass': '''
Java.perform(function() {
    var RootPackages = ["com.topjohnwu.magisk", "eu.chainfire.supersu"];
    
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1) {
            console.log("[*] Root detection bypass: " + path);
            return false;
        }
        return this.exists();
    };
    
    console.log("[*] Root Detection Bypass Loaded");
});
''',
            'crypto_logging': '''
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    
    Cipher.doFinal.overload("[B").implementation = function(input) {
        console.log("[CRYPTO] Input: " + bytesToHex(input));
        var result = this.doFinal(input);
        console.log("[CRYPTO] Output: " + bytesToHex(result));
        return result;
    };
    
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
    
    console.log("[*] Crypto Logging Loaded");
});
''',
        }
        
    async def start_frida_session(self, package_name: str, script_name: str) -> Dict[str, Any]:
        """Start Frida hooking session"""
        if script_name not in self.frida_scripts:
            return {'error': f'Unknown script: {script_name}'}
            
        # Return script for manual execution
        return {
            'status': 'ready',
            'package': package_name,
            'script': self.frida_scripts[script_name],
            'instructions': [
                'Install Frida on host: pip install frida-tools',
                'Install frida-server on device',
                f'Run: frida -U -f {package_name} -l script.js --no-pause'
            ]
        }


class MobileTrafficAnalyzer:
    """Mobile network traffic analysis"""
    
    def __init__(self):
        self.captured_requests = []
        
    def analyze_traffic_capture(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Analyze captured traffic"""
        findings = []
        
        try:
            # Try to use scapy if available
            from scapy.all import rdpcap, TCP, IP, Raw
            
            packets = rdpcap(pcap_path)
            
            for packet in packets:
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Check for sensitive data in plain HTTP
                    if not payload.startswith('HTTP') and packet[TCP].dport == 80:
                        findings.append({
                            'type': 'insecure_http',
                            'severity': 'high',
                            'description': 'Unencrypted HTTP traffic detected',
                            'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'unknown'
                        })
                        
                    # Check for credentials in traffic
                    if 'password' in payload.lower() or 'token' in payload.lower():
                        findings.append({
                            'type': 'sensitive_data',
                            'severity': 'critical',
                            'description': 'Potential credentials in network traffic',
                            'sample': payload[:200]
                        })
                        
        except ImportError:
            logger.warning("Scapy not available for traffic analysis")
        except Exception as e:
            logger.error(f"Traffic analysis error: {e}")
            
        return findings


class AdvancedMobileSecurity:
    """Main integration class for mobile security analysis"""
    
    def __init__(self):
        self.scanner = MobileSecurityScanner()
        self.dynamic = DynamicAnalyzer()
        self.traffic = MobileTrafficAnalyzer()
        
    async def full_analysis(self, app_path: str, include_dynamic: bool = False) -> Dict[str, Any]:
        """Perform comprehensive mobile security analysis"""
        results = {
            'analysis_id': hashlib.md5(f"{app_path}{datetime.now()}".encode()).hexdigest()[:12],
            'timestamp': datetime.now().isoformat(),
            'static_analysis': None,
            'dynamic_analysis': None,
            'traffic_analysis': None,
            'risk_score': 0.0,
            'recommendations': []
        }
        
        # Static analysis
        results['static_analysis'] = await self.scanner.scan_app(app_path)
        
        # Calculate risk score
        summary = results['static_analysis']['summary']
        risk_score = (
            summary['critical'] * 25 +
            summary['high'] * 15 +
            summary['medium'] * 5 +
            summary['low'] * 1
        )
        results['risk_score'] = min(risk_score, 100)
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results['static_analysis'])
        
        return results
        
    def _generate_recommendations(self, static_results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        findings = static_results.get('findings', [])
        
        # Check for common issues
        severity_counts = static_results.get('summary', {})
        
        if severity_counts.get('critical', 0) > 0:
            recommendations.append("CRITICAL: Address all critical findings immediately before release")
            
        if severity_counts.get('high', 0) > 0:
            recommendations.append("HIGH: Review and fix high severity issues before production")
            
        # Check for secrets
        secrets = static_results.get('secrets', [])
        if secrets:
            recommendations.append("Remove all hardcoded secrets and use secure storage mechanisms")
            
        # Check for specific categories
        categories = [f.get('category', '') for f in findings]
        
        if VulnerabilityCategory.M3_INSECURE_COMM.value in categories:
            recommendations.append("Implement certificate pinning and ensure all communication uses TLS 1.2+")
            
        if VulnerabilityCategory.M2_INSECURE_DATA.value in categories:
            recommendations.append("Use platform-provided secure storage (Keychain/Keystore) for sensitive data")
            
        if VulnerabilityCategory.M9_REVERSE_ENG.value in categories:
            recommendations.append("Implement code obfuscation and anti-tampering measures")
            
        # General recommendations
        recommendations.extend([
            "Implement root/jailbreak detection",
            "Enable ProGuard/R8 obfuscation for Android",
            "Remove debug logging and test credentials before release",
            "Implement runtime application self-protection (RASP)"
        ])
        
        return recommendations
        
    def generate_report(self, results: Dict) -> str:
        """Generate security analysis report"""
        report = []
        
        report.append("=" * 70)
        report.append("MOBILE APPLICATION SECURITY ANALYSIS REPORT")
        report.append("=" * 70)
        
        report.append(f"\nAnalysis ID: {results['analysis_id']}")
        report.append(f"Timestamp: {results['timestamp']}")
        
        static = results.get('static_analysis', {})
        
        if static:
            report.append(f"\nPlatform: {static.get('platform', 'Unknown').upper()}")
            
            app_info = static.get('app_info', {})
            if app_info:
                report.append(f"\n{'=' * 40}")
                report.append("APPLICATION INFO")
                report.append("=" * 40)
                report.append(f"Name: {app_info.get('name', 'N/A')}")
                report.append(f"Package: {app_info.get('package', app_info.get('bundle_id', 'N/A'))}")
                report.append(f"Version: {app_info.get('version', 'N/A')}")
                
            report.append(f"\n{'=' * 40}")
            report.append("SUMMARY")
            report.append("=" * 40)
            
            summary = static.get('summary', {})
            report.append(f"Critical: {summary.get('critical', 0)}")
            report.append(f"High: {summary.get('high', 0)}")
            report.append(f"Medium: {summary.get('medium', 0)}")
            report.append(f"Low: {summary.get('low', 0)}")
            report.append(f"Info: {summary.get('info', 0)}")
            
            report.append(f"\nRisk Score: {results.get('risk_score', 0)}/100")
            
            report.append(f"\n{'=' * 40}")
            report.append("FINDINGS")
            report.append("=" * 40)
            
            for finding in static.get('findings', [])[:20]:
                report.append(f"\n[{finding['severity'].upper()}] {finding['title']}")
                report.append(f"  Category: {finding['category']}")
                report.append(f"  Description: {finding['description']}")
                if finding.get('remediation'):
                    report.append(f"  Remediation: {finding['remediation']}")
                    
            # Secrets section
            secrets = static.get('secrets', [])
            if secrets:
                report.append(f"\n{'=' * 40}")
                report.append("HARDCODED SECRETS")
                report.append("=" * 40)
                
                for secret in secrets[:10]:
                    report.append(f"\n[{secret['type'].upper()}]")
                    report.append(f"  Value: {secret['value']}")
                    report.append(f"  Location: {secret['location']}:{secret['line']}")
                    
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            report.append(f"\n{'=' * 40}")
            report.append("RECOMMENDATIONS")
            report.append("=" * 40)
            
            for i, rec in enumerate(recommendations, 1):
                report.append(f"\n{i}. {rec}")
                
        return "\n".join(report)
