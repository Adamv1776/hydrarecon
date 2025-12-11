"""
HydraRecon Supply Chain Security Module
Software supply chain risk analysis and monitoring
"""

import asyncio
import hashlib
import json
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class DependencyType(Enum):
    """Types of software dependencies"""
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"
    GO = "go"
    CARGO = "cargo"
    COMPOSER = "composer"
    COCOAPODS = "cocoapods"
    DOCKER = "docker"
    APT = "apt"
    YUM = "yum"
    BREW = "brew"


class RiskLevel(Enum):
    """Risk levels for supply chain threats"""
    CRITICAL = ("critical", 10, "#dc3545")
    HIGH = ("high", 7, "#fd7e14")
    MEDIUM = ("medium", 4, "#ffc107")
    LOW = ("low", 1, "#17a2b8")
    NONE = ("none", 0, "#28a745")
    
    @property
    def name_str(self) -> str:
        return self.value[0]
    
    @property
    def score(self) -> int:
        return self.value[1]
    
    @property
    def color(self) -> str:
        return self.value[2]


class ThreatType(Enum):
    """Types of supply chain threats"""
    VULNERABILITY = "vulnerability"
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    MALICIOUS_PACKAGE = "malicious_package"
    COMPROMISED_MAINTAINER = "compromised_maintainer"
    ABANDONED_PACKAGE = "abandoned_package"
    LICENSE_ISSUE = "license_issue"
    OUTDATED = "outdated"
    PHANTOM_DEPENDENCY = "phantom_dependency"
    BUILD_TAMPERING = "build_tampering"
    CRYPTOJACKING = "cryptojacking"
    BACKDOOR = "backdoor"


@dataclass
class Package:
    """Software package information"""
    name: str
    version: str
    package_type: DependencyType
    registry_url: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    description: str = ""
    author: Optional[str] = None
    maintainers: List[str] = field(default_factory=list)
    license: Optional[str] = None
    published_date: Optional[datetime] = None
    download_count: int = 0
    dependencies: List[str] = field(default_factory=list)
    dev_dependencies: List[str] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)
    checksums: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'version': self.version,
            'package_type': self.package_type.value,
            'registry_url': self.registry_url,
            'homepage': self.homepage,
            'repository': self.repository,
            'description': self.description,
            'author': self.author,
            'maintainers': self.maintainers,
            'license': self.license,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'download_count': self.download_count,
            'dependencies': self.dependencies,
            'dev_dependencies': self.dev_dependencies,
            'scripts': self.scripts
        }


@dataclass
class SupplyChainThreat:
    """Supply chain security threat"""
    threat_id: str
    threat_type: ThreatType
    package: Package
    risk_level: RiskLevel
    title: str
    description: str
    cve_ids: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_version: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.now)
    indicators: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'threat_id': self.threat_id,
            'threat_type': self.threat_type.value,
            'package': self.package.to_dict(),
            'risk_level': self.risk_level.name_str,
            'risk_score': self.risk_level.score,
            'title': self.title,
            'description': self.description,
            'cve_ids': self.cve_ids,
            'affected_versions': self.affected_versions,
            'fixed_version': self.fixed_version,
            'remediation': self.remediation,
            'references': self.references,
            'detected_at': self.detected_at.isoformat(),
            'indicators': self.indicators
        }


@dataclass
class SBOM:
    """Software Bill of Materials"""
    sbom_id: str
    project_name: str
    version: str
    created_at: datetime
    format_type: str  # spdx, cyclonedx, swid
    packages: List[Package]
    dependencies_graph: Dict[str, List[str]]
    metadata: Dict = field(default_factory=dict)
    
    def to_cyclonedx(self) -> Dict:
        """Export as CycloneDX format"""
        return {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'metadata': {
                'timestamp': self.created_at.isoformat(),
                'component': {
                    'type': 'application',
                    'name': self.project_name,
                    'version': self.version
                }
            },
            'components': [
                {
                    'type': 'library',
                    'name': pkg.name,
                    'version': pkg.version,
                    'purl': f"pkg:{pkg.package_type.value}/{pkg.name}@{pkg.version}",
                    'licenses': [{'license': {'id': pkg.license}}] if pkg.license else []
                }
                for pkg in self.packages
            ],
            'dependencies': [
                {
                    'ref': pkg_name,
                    'dependsOn': deps
                }
                for pkg_name, deps in self.dependencies_graph.items()
            ]
        }
    
    def to_spdx(self) -> Dict:
        """Export as SPDX format"""
        return {
            'spdxVersion': 'SPDX-2.3',
            'dataLicense': 'CC0-1.0',
            'SPDXID': f'SPDXRef-{self.sbom_id}',
            'name': self.project_name,
            'documentNamespace': f'https://spdx.org/spdxdocs/{self.project_name}-{self.version}',
            'creationInfo': {
                'created': self.created_at.isoformat(),
                'creators': ['Tool: HydraRecon']
            },
            'packages': [
                {
                    'SPDXID': f'SPDXRef-{pkg.name}',
                    'name': pkg.name,
                    'versionInfo': pkg.version,
                    'downloadLocation': pkg.registry_url or 'NOASSERTION',
                    'licenseDeclared': pkg.license or 'NOASSERTION'
                }
                for pkg in self.packages
            ]
        }


class DependencyScanner:
    """Scan projects for dependencies"""
    
    def __init__(self):
        self.lockfile_patterns = {
            DependencyType.NPM: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
            DependencyType.PYPI: ['Pipfile.lock', 'poetry.lock', 'requirements.txt'],
            DependencyType.MAVEN: ['pom.xml'],
            DependencyType.NUGET: ['packages.lock.json', '*.csproj'],
            DependencyType.GO: ['go.sum', 'go.mod'],
            DependencyType.CARGO: ['Cargo.lock'],
            DependencyType.RUBYGEMS: ['Gemfile.lock'],
            DependencyType.COMPOSER: ['composer.lock'],
        }
    
    def parse_package_json(self, content: str) -> List[Package]:
        """Parse package.json for npm dependencies"""
        packages = []
        
        try:
            data = json.loads(content)
            
            # Regular dependencies
            for name, version in data.get('dependencies', {}).items():
                packages.append(Package(
                    name=name,
                    version=version.lstrip('^~>=<'),
                    package_type=DependencyType.NPM
                ))
            
            # Dev dependencies
            for name, version in data.get('devDependencies', {}).items():
                pkg = Package(
                    name=name,
                    version=version.lstrip('^~>=<'),
                    package_type=DependencyType.NPM
                )
                packages.append(pkg)
        except json.JSONDecodeError:
            pass
        
        return packages
    
    def parse_requirements_txt(self, content: str) -> List[Package]:
        """Parse requirements.txt for Python dependencies"""
        packages = []
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Parse package==version format
            match = re.match(r'^([a-zA-Z0-9_-]+)([=<>!~]+)?(.+)?$', line)
            if match:
                name = match.group(1)
                version = match.group(3) or 'latest'
                packages.append(Package(
                    name=name,
                    version=version,
                    package_type=DependencyType.PYPI
                ))
        
        return packages
    
    def parse_go_mod(self, content: str) -> List[Package]:
        """Parse go.mod for Go dependencies"""
        packages = []
        
        for line in content.split('\n'):
            match = re.match(r'\t([^\s]+)\s+v?([^\s]+)', line)
            if match:
                packages.append(Package(
                    name=match.group(1),
                    version=match.group(2),
                    package_type=DependencyType.GO
                ))
        
        return packages
    
    def parse_cargo_toml(self, content: str) -> List[Package]:
        """Parse Cargo.toml for Rust dependencies"""
        packages = []
        
        in_deps = False
        for line in content.split('\n'):
            if '[dependencies]' in line or '[dev-dependencies]' in line:
                in_deps = True
                continue
            elif line.startswith('[') and in_deps:
                in_deps = False
                continue
            
            if in_deps:
                match = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*["\']?([^"\']+)["\']?', line)
                if match:
                    packages.append(Package(
                        name=match.group(1),
                        version=match.group(2),
                        package_type=DependencyType.CARGO
                    ))
        
        return packages
    
    def build_dependency_graph(self, packages: List[Package]) -> Dict[str, List[str]]:
        """Build dependency graph from packages"""
        graph = {}
        
        for pkg in packages:
            pkg_id = f"{pkg.name}@{pkg.version}"
            graph[pkg_id] = pkg.dependencies
        
        return graph
    
    def generate_sbom(self, project_name: str, version: str,
                     packages: List[Package]) -> SBOM:
        """Generate SBOM from packages"""
        return SBOM(
            sbom_id=hashlib.sha256(
                f"{project_name}-{version}-{time.time()}".encode()
            ).hexdigest()[:16],
            project_name=project_name,
            version=version,
            created_at=datetime.now(),
            format_type='cyclonedx',
            packages=packages,
            dependencies_graph=self.build_dependency_graph(packages)
        )


class VulnerabilityDatabase:
    """Database of known vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities: Dict[str, List[Dict]] = defaultdict(list)
        self._load_known_vulnerabilities()
    
    def _load_known_vulnerabilities(self):
        """Load known vulnerabilities"""
        known_vulns = [
            {
                'package': 'lodash',
                'ecosystem': 'npm',
                'cve': 'CVE-2021-23337',
                'severity': 'high',
                'title': 'Command Injection in lodash',
                'affected': '<4.17.21',
                'fixed': '4.17.21'
            },
            {
                'package': 'log4j-core',
                'ecosystem': 'maven',
                'cve': 'CVE-2021-44228',
                'severity': 'critical',
                'title': 'Log4Shell RCE',
                'affected': '>=2.0-beta9,<2.17.0',
                'fixed': '2.17.0'
            },
            {
                'package': 'requests',
                'ecosystem': 'pypi',
                'cve': 'CVE-2023-32681',
                'severity': 'medium',
                'title': 'Sensitive information leak',
                'affected': '<2.31.0',
                'fixed': '2.31.0'
            },
            {
                'package': 'minimist',
                'ecosystem': 'npm',
                'cve': 'CVE-2021-44906',
                'severity': 'critical',
                'title': 'Prototype Pollution',
                'affected': '<1.2.6',
                'fixed': '1.2.6'
            },
            {
                'package': 'axios',
                'ecosystem': 'npm',
                'cve': 'CVE-2023-45857',
                'severity': 'high',
                'title': 'SSRF vulnerability',
                'affected': '<1.6.0',
                'fixed': '1.6.0'
            },
            {
                'package': 'django',
                'ecosystem': 'pypi',
                'cve': 'CVE-2023-43665',
                'severity': 'medium',
                'title': 'Denial of Service',
                'affected': '<4.2.6',
                'fixed': '4.2.6'
            },
            {
                'package': 'express',
                'ecosystem': 'npm',
                'cve': 'CVE-2024-29041',
                'severity': 'medium',
                'title': 'Open Redirect vulnerability',
                'affected': '<4.19.2',
                'fixed': '4.19.2'
            }
        ]
        
        for vuln in known_vulns:
            key = f"{vuln['ecosystem']}:{vuln['package']}"
            self.vulnerabilities[key].append(vuln)
    
    def check_package(self, package: Package) -> List[Dict]:
        """Check a package for known vulnerabilities"""
        key = f"{package.package_type.value}:{package.name}"
        vulns = self.vulnerabilities.get(key, [])
        
        # Filter by version (simplified)
        matching = []
        for vuln in vulns:
            # Simplified version check
            if self._version_affected(package.version, vuln.get('affected', '')):
                matching.append(vuln)
        
        return matching
    
    def _version_affected(self, version: str, affected_range: str) -> bool:
        """Check if version is in affected range (simplified)"""
        if '<' in affected_range:
            # Extract version from range like "<4.17.21"
            fixed = affected_range.replace('<', '').replace('=', '').strip()
            try:
                return self._compare_versions(version, fixed) < 0
            except:
                return True
        return True
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare semantic versions"""
        parts1 = [int(x) for x in re.findall(r'\d+', v1)[:3]]
        parts2 = [int(x) for x in re.findall(r'\d+', v2)[:3]]
        
        # Pad with zeros
        while len(parts1) < 3:
            parts1.append(0)
        while len(parts2) < 3:
            parts2.append(0)
        
        for i in range(3):
            if parts1[i] < parts2[i]:
                return -1
            if parts1[i] > parts2[i]:
                return 1
        return 0


class TyposquattingDetector:
    """Detect typosquatting attacks"""
    
    def __init__(self):
        self.popular_packages = {
            'npm': ['lodash', 'express', 'react', 'axios', 'moment', 'request',
                   'chalk', 'commander', 'debug', 'async', 'uuid', 'underscore'],
            'pypi': ['requests', 'numpy', 'pandas', 'flask', 'django', 'pytest',
                    'boto3', 'pillow', 'tensorflow', 'scikit-learn', 'matplotlib']
        }
    
    def generate_typosquat_variants(self, package_name: str) -> List[str]:
        """Generate potential typosquatting variants"""
        variants = set()
        
        # Character swapping
        for i in range(len(package_name) - 1):
            swapped = list(package_name)
            swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
            variants.add(''.join(swapped))
        
        # Character omission
        for i in range(len(package_name)):
            variants.add(package_name[:i] + package_name[i+1:])
        
        # Character duplication
        for i in range(len(package_name)):
            variants.add(package_name[:i] + package_name[i] + package_name[i:])
        
        # Character substitution (common typos)
        typo_map = {'a': 's', 's': 'a', 'e': 'r', 'r': 'e', 'i': 'o', 'o': 'i'}
        for i, char in enumerate(package_name):
            if char in typo_map:
                variants.add(package_name[:i] + typo_map[char] + package_name[i+1:])
        
        # Separator changes
        variants.add(package_name.replace('-', '_'))
        variants.add(package_name.replace('_', '-'))
        variants.add(package_name.replace('-', ''))
        variants.add(package_name.replace('_', ''))
        
        return list(variants - {package_name})
    
    def is_typosquat(self, package_name: str, ecosystem: str) -> Optional[str]:
        """Check if package name is a typosquat of a popular package"""
        popular = self.popular_packages.get(ecosystem, [])
        
        for pop_pkg in popular:
            variants = self.generate_typosquat_variants(pop_pkg)
            if package_name.lower() in [v.lower() for v in variants]:
                return pop_pkg
        
        return None
    
    def analyze_package_similarity(self, pkg1: str, pkg2: str) -> float:
        """Calculate similarity between two package names"""
        # Levenshtein distance
        if len(pkg1) < len(pkg2):
            pkg1, pkg2 = pkg2, pkg1
        
        if len(pkg2) == 0:
            return 0.0
        
        distances = range(len(pkg2) + 1)
        for i, c1 in enumerate(pkg1):
            new_distances = [i + 1]
            for j, c2 in enumerate(pkg2):
                if c1 == c2:
                    new_distances.append(distances[j])
                else:
                    new_distances.append(1 + min((distances[j], distances[j+1], new_distances[-1])))
            distances = new_distances
        
        distance = distances[-1]
        max_len = max(len(pkg1), len(pkg2))
        return 1 - (distance / max_len)


class MaliciousPatternDetector:
    """Detect malicious patterns in packages"""
    
    def __init__(self):
        self.suspicious_patterns = [
            # Network access
            (r'require\([\'"]child_process[\'"]\)', 'child_process import'),
            (r'require\([\'"]net[\'"]\)', 'network module import'),
            (r'require\([\'"]http[s]?[\'"]\)', 'http module import'),
            (r'\.exec\s*\(', 'exec call'),
            (r'eval\s*\(', 'eval call'),
            
            # File system access
            (r'fs\.write', 'file write'),
            (r'fs\.read', 'file read'),
            (r'require\([\'"]fs[\'"]\)', 'fs import'),
            
            # Obfuscation indicators
            (r'Buffer\.from\s*\([\'"][A-Za-z0-9+/=]+[\'"]\s*,\s*[\'"]base64[\'"]\)', 'base64 decode'),
            (r'String\.fromCharCode', 'char code conversion'),
            (r'\\x[0-9a-fA-F]{2}', 'hex encoded strings'),
            
            # Crypto mining
            (r'stratum\+tcp://', 'mining pool connection'),
            (r'coinhive', 'coinhive reference'),
            (r'cryptonight', 'cryptonight reference'),
            
            # Data exfiltration
            (r'process\.env', 'environment variable access'),
            (r'\.npmrc', 'npmrc access'),
            (r'ssh.*key', 'ssh key access'),
            (r'aws.*credential', 'AWS credential access'),
        ]
        
        self.suspicious_scripts = [
            'preinstall', 'postinstall', 'preuninstall', 'postuninstall'
        ]
    
    def analyze_package_content(self, content: str) -> List[Dict]:
        """Analyze package content for suspicious patterns"""
        findings = []
        
        for pattern, description in self.suspicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': 'suspicious_pattern',
                    'pattern': pattern,
                    'description': description,
                    'count': len(matches),
                    'matches': matches[:5]  # Limit matches
                })
        
        return findings
    
    def analyze_package_scripts(self, scripts: Dict[str, str]) -> List[Dict]:
        """Analyze package scripts for suspicious behavior"""
        findings = []
        
        for script_name in self.suspicious_scripts:
            if script_name in scripts:
                script_content = scripts[script_name]
                
                # Check for suspicious commands
                if any(cmd in script_content.lower() for cmd in ['curl', 'wget', 'nc ', 'netcat']):
                    findings.append({
                        'type': 'suspicious_script',
                        'script': script_name,
                        'description': f'Suspicious network command in {script_name}',
                        'content': script_content[:200]
                    })
                
                if 'eval' in script_content or 'base64' in script_content:
                    findings.append({
                        'type': 'obfuscated_script',
                        'script': script_name,
                        'description': f'Possible obfuscation in {script_name}',
                        'content': script_content[:200]
                    })
        
        return findings
    
    def calculate_risk_score(self, findings: List[Dict]) -> Tuple[int, RiskLevel]:
        """Calculate overall risk score from findings"""
        score = 0
        
        for finding in findings:
            if finding['type'] == 'suspicious_pattern':
                score += 10 * finding.get('count', 1)
            elif finding['type'] == 'suspicious_script':
                score += 30
            elif finding['type'] == 'obfuscated_script':
                score += 20
        
        if score >= 50:
            return score, RiskLevel.CRITICAL
        elif score >= 30:
            return score, RiskLevel.HIGH
        elif score >= 15:
            return score, RiskLevel.MEDIUM
        elif score > 0:
            return score, RiskLevel.LOW
        return 0, RiskLevel.NONE


class LicenseAnalyzer:
    """Analyze software licenses for compliance"""
    
    def __init__(self):
        self.license_compatibility = {
            'MIT': {'compatible': ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0'],
                   'restricted': ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0']},
            'Apache-2.0': {'compatible': ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0'],
                          'restricted': ['GPL-2.0']},
            'GPL-3.0': {'compatible': ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'GPL-2.0', 'GPL-3.0'],
                       'restricted': []},
            'AGPL-3.0': {'compatible': ['MIT', 'ISC', 'BSD-2-Clause', 'Apache-2.0', 'GPL-3.0', 'AGPL-3.0'],
                        'restricted': []},
            'UNLICENSED': {'compatible': [], 'restricted': ['ALL']}
        }
        
        self.copyleft_licenses = ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0']
        self.permissive_licenses = ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0']
    
    def check_compatibility(self, project_license: str, 
                           dependency_license: str) -> Dict:
        """Check license compatibility"""
        result = {
            'compatible': True,
            'risk': 'low',
            'notes': []
        }
        
        project_info = self.license_compatibility.get(project_license, {})
        
        if dependency_license in project_info.get('restricted', []):
            result['compatible'] = False
            result['risk'] = 'high'
            result['notes'].append(f"{dependency_license} may not be compatible with {project_license}")
        
        if dependency_license in self.copyleft_licenses and project_license in self.permissive_licenses:
            result['risk'] = 'medium'
            result['notes'].append(f"Copyleft {dependency_license} may affect distribution")
        
        if dependency_license == 'UNLICENSED' or not dependency_license:
            result['risk'] = 'high'
            result['notes'].append("No license specified - usage rights unclear")
        
        return result
    
    def analyze_dependencies_licenses(self, packages: List[Package],
                                      project_license: str) -> Dict:
        """Analyze all dependency licenses"""
        analysis = {
            'total_packages': len(packages),
            'license_distribution': defaultdict(int),
            'issues': [],
            'copyleft_count': 0,
            'permissive_count': 0,
            'unknown_count': 0
        }
        
        for pkg in packages:
            license_id = pkg.license or 'UNKNOWN'
            analysis['license_distribution'][license_id] += 1
            
            if license_id in self.copyleft_licenses:
                analysis['copyleft_count'] += 1
            elif license_id in self.permissive_licenses:
                analysis['permissive_count'] += 1
            else:
                analysis['unknown_count'] += 1
            
            # Check compatibility
            compat = self.check_compatibility(project_license, license_id)
            if not compat['compatible'] or compat['risk'] in ['medium', 'high']:
                analysis['issues'].append({
                    'package': pkg.name,
                    'version': pkg.version,
                    'license': license_id,
                    'compatibility': compat
                })
        
        analysis['license_distribution'] = dict(analysis['license_distribution'])
        return analysis


class SupplyChainSecurity:
    """
    Main supply chain security platform
    Comprehensive software supply chain risk analysis
    """
    
    def __init__(self):
        self.scanner = DependencyScanner()
        self.vuln_db = VulnerabilityDatabase()
        self.typosquat_detector = TyposquattingDetector()
        self.malware_detector = MaliciousPatternDetector()
        self.license_analyzer = LicenseAnalyzer()
        
        self.threats: List[SupplyChainThreat] = []
        self.sboms: Dict[str, SBOM] = {}
        self.monitored_packages: Set[str] = set()
    
    async def analyze_project(self, project_path: str,
                             manifest_content: str,
                             manifest_type: DependencyType) -> Dict:
        """Analyze a project for supply chain risks"""
        results = {
            'project_path': project_path,
            'analysis_time': datetime.now().isoformat(),
            'packages': [],
            'vulnerabilities': [],
            'typosquatting': [],
            'malicious_indicators': [],
            'license_issues': [],
            'risk_summary': {}
        }
        
        # Parse dependencies
        if manifest_type == DependencyType.NPM:
            packages = self.scanner.parse_package_json(manifest_content)
        elif manifest_type == DependencyType.PYPI:
            packages = self.scanner.parse_requirements_txt(manifest_content)
        elif manifest_type == DependencyType.GO:
            packages = self.scanner.parse_go_mod(manifest_content)
        elif manifest_type == DependencyType.CARGO:
            packages = self.scanner.parse_cargo_toml(manifest_content)
        else:
            packages = []
        
        results['packages'] = [p.to_dict() for p in packages]
        
        # Check vulnerabilities
        for pkg in packages:
            vulns = self.vuln_db.check_package(pkg)
            for vuln in vulns:
                threat = SupplyChainThreat(
                    threat_id=hashlib.sha256(
                        f"{pkg.name}-{vuln['cve']}".encode()
                    ).hexdigest()[:16],
                    threat_type=ThreatType.VULNERABILITY,
                    package=pkg,
                    risk_level=self._severity_to_risk(vuln['severity']),
                    title=vuln['title'],
                    description=f"Vulnerable package: {pkg.name}@{pkg.version}",
                    cve_ids=[vuln['cve']],
                    affected_versions=[vuln['affected']],
                    fixed_version=vuln.get('fixed'),
                    remediation=f"Upgrade to version {vuln.get('fixed', 'latest')}"
                )
                self.threats.append(threat)
                results['vulnerabilities'].append(threat.to_dict())
        
        # Check typosquatting
        for pkg in packages:
            similar = self.typosquat_detector.is_typosquat(
                pkg.name, pkg.package_type.value
            )
            if similar:
                results['typosquatting'].append({
                    'package': pkg.name,
                    'similar_to': similar,
                    'risk': 'high',
                    'recommendation': f"Verify this is not a typosquat of '{similar}'"
                })
        
        # Calculate risk summary
        results['risk_summary'] = self._calculate_risk_summary(results)
        
        return results
    
    async def scan_package(self, package_name: str,
                          package_type: DependencyType) -> Dict:
        """Scan a specific package for threats"""
        pkg = Package(
            name=package_name,
            version='latest',
            package_type=package_type
        )
        
        results = {
            'package': pkg.to_dict(),
            'vulnerabilities': [],
            'typosquatting_check': None,
            'malicious_indicators': [],
            'metadata': {}
        }
        
        # Check vulnerabilities
        vulns = self.vuln_db.check_package(pkg)
        results['vulnerabilities'] = vulns
        
        # Check typosquatting
        similar = self.typosquat_detector.is_typosquat(
            package_name, package_type.value
        )
        if similar:
            results['typosquatting_check'] = {
                'is_potential_typosquat': True,
                'similar_to': similar
            }
        
        return results
    
    def generate_sbom(self, project_name: str, version: str,
                     packages: List[Package]) -> SBOM:
        """Generate SBOM for a project"""
        sbom = self.scanner.generate_sbom(project_name, version, packages)
        self.sboms[sbom.sbom_id] = sbom
        return sbom
    
    def export_sbom(self, sbom_id: str, format_type: str = 'cyclonedx') -> str:
        """Export SBOM in specified format"""
        sbom = self.sboms.get(sbom_id)
        if not sbom:
            return json.dumps({'error': 'SBOM not found'})
        
        if format_type == 'cyclonedx':
            return json.dumps(sbom.to_cyclonedx(), indent=2)
        elif format_type == 'spdx':
            return json.dumps(sbom.to_spdx(), indent=2)
        
        return json.dumps(sbom.to_cyclonedx(), indent=2)
    
    def analyze_licenses(self, packages: List[Package],
                        project_license: str = 'MIT') -> Dict:
        """Analyze license compliance"""
        return self.license_analyzer.analyze_dependencies_licenses(
            packages, project_license
        )
    
    def _severity_to_risk(self, severity: str) -> RiskLevel:
        """Convert severity string to RiskLevel"""
        mapping = {
            'critical': RiskLevel.CRITICAL,
            'high': RiskLevel.HIGH,
            'medium': RiskLevel.MEDIUM,
            'low': RiskLevel.LOW
        }
        return mapping.get(severity.lower(), RiskLevel.MEDIUM)
    
    def _calculate_risk_summary(self, results: Dict) -> Dict:
        """Calculate overall risk summary"""
        vuln_count = len(results.get('vulnerabilities', []))
        typosquat_count = len(results.get('typosquatting', []))
        malicious_count = len(results.get('malicious_indicators', []))
        
        critical_vulns = sum(
            1 for v in results.get('vulnerabilities', [])
            if v.get('risk_level') == 'critical'
        )
        high_vulns = sum(
            1 for v in results.get('vulnerabilities', [])
            if v.get('risk_level') == 'high'
        )
        
        # Calculate overall score
        score = 100
        score -= critical_vulns * 20
        score -= high_vulns * 10
        score -= typosquat_count * 15
        score -= malicious_count * 25
        
        score = max(0, score)
        
        if score >= 80:
            level = 'low'
        elif score >= 60:
            level = 'medium'
        elif score >= 40:
            level = 'high'
        else:
            level = 'critical'
        
        return {
            'score': score,
            'level': level,
            'total_packages': len(results.get('packages', [])),
            'vulnerability_count': vuln_count,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'typosquatting_risks': typosquat_count,
            'malicious_indicators': malicious_count
        }
    
    def get_threats(self, risk_level: RiskLevel = None) -> List[SupplyChainThreat]:
        """Get detected threats"""
        if risk_level:
            return [t for t in self.threats if t.risk_level == risk_level]
        return self.threats
    
    def get_statistics(self) -> Dict:
        """Get supply chain security statistics"""
        return {
            'total_threats': len(self.threats),
            'by_type': {
                tt.value: sum(1 for t in self.threats if t.threat_type == tt)
                for tt in ThreatType
            },
            'by_risk': {
                rl.name_str: sum(1 for t in self.threats if t.risk_level == rl)
                for rl in RiskLevel
            },
            'sboms_generated': len(self.sboms),
            'monitored_packages': len(self.monitored_packages)
        }
