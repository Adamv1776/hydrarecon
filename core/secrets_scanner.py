#!/usr/bin/env python3
"""
HydraRecon Secrets Scanner
Detects leaked credentials, API keys, tokens, and sensitive data in code and configs.
"""

import asyncio
import re
import json
import base64
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from pathlib import Path
import hashlib
import aiohttp


class SecretType(Enum):
    """Types of secrets that can be detected."""
    # Cloud Provider Keys
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Key"
    AWS_SESSION_TOKEN = "AWS Session Token"
    AZURE_CLIENT_SECRET = "Azure Client Secret"
    AZURE_STORAGE_KEY = "Azure Storage Key"
    GCP_API_KEY = "GCP API Key"
    GCP_SERVICE_ACCOUNT = "GCP Service Account"
    DIGITALOCEAN_TOKEN = "DigitalOcean Token"
    HEROKU_API_KEY = "Heroku API Key"
    
    # API Keys
    GITHUB_TOKEN = "GitHub Token"
    GITLAB_TOKEN = "GitLab Token"
    BITBUCKET_TOKEN = "Bitbucket Token"
    SLACK_TOKEN = "Slack Token"
    SLACK_WEBHOOK = "Slack Webhook"
    DISCORD_TOKEN = "Discord Token"
    DISCORD_WEBHOOK = "Discord Webhook"
    TELEGRAM_BOT_TOKEN = "Telegram Bot Token"
    TWILIO_API_KEY = "Twilio API Key"
    SENDGRID_API_KEY = "SendGrid API Key"
    MAILGUN_API_KEY = "Mailgun API Key"
    STRIPE_API_KEY = "Stripe API Key"
    PAYPAL_CLIENT_SECRET = "PayPal Client Secret"
    SQUARE_ACCESS_TOKEN = "Square Access Token"
    SHOPIFY_API_KEY = "Shopify API Key"
    
    # Database Credentials
    DATABASE_URL = "Database URL"
    MONGODB_URI = "MongoDB URI"
    REDIS_URL = "Redis URL"
    MYSQL_PASSWORD = "MySQL Password"
    POSTGRES_PASSWORD = "PostgreSQL Password"
    
    # Security Keys
    JWT_SECRET = "JWT Secret"
    SSH_PRIVATE_KEY = "SSH Private Key"
    PGP_PRIVATE_KEY = "PGP Private Key"
    SSL_PRIVATE_KEY = "SSL Private Key"
    ENCRYPTION_KEY = "Encryption Key"
    
    # Authentication
    OAUTH_CLIENT_SECRET = "OAuth Client Secret"
    API_KEY_GENERIC = "Generic API Key"
    PASSWORD = "Password"
    BEARER_TOKEN = "Bearer Token"
    BASIC_AUTH = "Basic Auth Credentials"
    
    # Other
    PRIVATE_KEY_GENERIC = "Private Key"
    SECRET_GENERIC = "Generic Secret"
    CRYPTO_WALLET = "Crypto Wallet Key"
    NPM_TOKEN = "NPM Token"
    PYPI_TOKEN = "PyPI Token"
    NUGET_API_KEY = "NuGet API Key"


class Severity(Enum):
    """Severity levels for secret findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class SecretPattern:
    """Pattern definition for secret detection."""
    secret_type: SecretType
    pattern: str
    severity: Severity
    description: str
    entropy_threshold: float = 3.0
    validate_func: Optional[str] = None
    false_positive_patterns: List[str] = field(default_factory=list)


@dataclass
class SecretFinding:
    """Represents a detected secret."""
    id: str
    secret_type: SecretType
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    secret_value: str  # Partially masked
    full_match: str
    entropy: float
    description: str
    remediation: str
    verified: bool = False
    false_positive: bool = False
    commit_hash: Optional[str] = None
    author: Optional[str] = None
    commit_date: Optional[datetime] = None
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)


class SecretsScanner:
    """Advanced secrets and credential scanner."""
    
    # Comprehensive secret patterns
    PATTERNS: List[SecretPattern] = [
        # AWS
        SecretPattern(
            secret_type=SecretType.AWS_ACCESS_KEY,
            pattern=r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            severity=Severity.CRITICAL,
            description="AWS Access Key ID detected",
            entropy_threshold=3.5
        ),
        SecretPattern(
            secret_type=SecretType.AWS_SECRET_KEY,
            pattern=r'(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            severity=Severity.CRITICAL,
            description="AWS Secret Access Key detected"
        ),
        
        # Azure
        SecretPattern(
            secret_type=SecretType.AZURE_CLIENT_SECRET,
            pattern=r'(?i)(?:azure|az)[-_]?(?:client)?[-_]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9~._-]{34,})["\']?',
            severity=Severity.CRITICAL,
            description="Azure Client Secret detected"
        ),
        SecretPattern(
            secret_type=SecretType.AZURE_STORAGE_KEY,
            pattern=r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});',
            severity=Severity.CRITICAL,
            description="Azure Storage Account Key detected"
        ),
        
        # GCP
        SecretPattern(
            secret_type=SecretType.GCP_API_KEY,
            pattern=r'AIza[0-9A-Za-z_-]{35}',
            severity=Severity.HIGH,
            description="Google Cloud API Key detected"
        ),
        SecretPattern(
            secret_type=SecretType.GCP_SERVICE_ACCOUNT,
            pattern=r'(?i)"type"\s*:\s*"service_account"[^}]*"private_key"\s*:\s*"-----BEGIN',
            severity=Severity.CRITICAL,
            description="GCP Service Account Key detected"
        ),
        
        # GitHub/GitLab
        SecretPattern(
            secret_type=SecretType.GITHUB_TOKEN,
            pattern=r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
            severity=Severity.CRITICAL,
            description="GitHub Personal Access Token detected"
        ),
        SecretPattern(
            secret_type=SecretType.GITLAB_TOKEN,
            pattern=r'glpat-[A-Za-z0-9_-]{20,}',
            severity=Severity.CRITICAL,
            description="GitLab Personal Access Token detected"
        ),
        
        # Slack
        SecretPattern(
            secret_type=SecretType.SLACK_TOKEN,
            pattern=r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            severity=Severity.HIGH,
            description="Slack Token detected"
        ),
        SecretPattern(
            secret_type=SecretType.SLACK_WEBHOOK,
            pattern=r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
            severity=Severity.MEDIUM,
            description="Slack Webhook URL detected"
        ),
        
        # Discord
        SecretPattern(
            secret_type=SecretType.DISCORD_TOKEN,
            pattern=r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
            severity=Severity.HIGH,
            description="Discord Bot Token detected"
        ),
        SecretPattern(
            secret_type=SecretType.DISCORD_WEBHOOK,
            pattern=r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
            severity=Severity.MEDIUM,
            description="Discord Webhook URL detected"
        ),
        
        # Telegram
        SecretPattern(
            secret_type=SecretType.TELEGRAM_BOT_TOKEN,
            pattern=r'\d{9,10}:[A-Za-z0-9_-]{35}',
            severity=Severity.HIGH,
            description="Telegram Bot Token detected"
        ),
        
        # Payment Processors
        SecretPattern(
            secret_type=SecretType.STRIPE_API_KEY,
            pattern=r'sk_(?:live|test)_[A-Za-z0-9]{24,}',
            severity=Severity.CRITICAL,
            description="Stripe Secret Key detected"
        ),
        SecretPattern(
            secret_type=SecretType.PAYPAL_CLIENT_SECRET,
            pattern=r'(?i)paypal[-_]?(?:client)?[-_]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{40,})["\']?',
            severity=Severity.CRITICAL,
            description="PayPal Client Secret detected"
        ),
        SecretPattern(
            secret_type=SecretType.SQUARE_ACCESS_TOKEN,
            pattern=r'sq0[a-z]{3}-[A-Za-z0-9_-]{22,}',
            severity=Severity.CRITICAL,
            description="Square Access Token detected"
        ),
        
        # Email Services
        SecretPattern(
            secret_type=SecretType.SENDGRID_API_KEY,
            pattern=r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            severity=Severity.HIGH,
            description="SendGrid API Key detected"
        ),
        SecretPattern(
            secret_type=SecretType.MAILGUN_API_KEY,
            pattern=r'key-[A-Za-z0-9]{32}',
            severity=Severity.HIGH,
            description="Mailgun API Key detected"
        ),
        SecretPattern(
            secret_type=SecretType.TWILIO_API_KEY,
            pattern=r'SK[A-Za-z0-9]{32}',
            severity=Severity.HIGH,
            description="Twilio API Key detected"
        ),
        
        # Database URLs
        SecretPattern(
            secret_type=SecretType.DATABASE_URL,
            pattern=r'(?i)(?:mysql|postgres|postgresql|mongodb|redis|mariadb):\/\/[^\s"\']+:[^\s"\']+@[^\s"\']+',
            severity=Severity.CRITICAL,
            description="Database connection string with credentials detected"
        ),
        SecretPattern(
            secret_type=SecretType.MONGODB_URI,
            pattern=r'mongodb(?:\+srv)?:\/\/[^\s"\']+:[^\s"\']+@[^\s"\']+',
            severity=Severity.CRITICAL,
            description="MongoDB connection string with credentials detected"
        ),
        
        # Private Keys
        SecretPattern(
            secret_type=SecretType.SSH_PRIVATE_KEY,
            pattern=r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            severity=Severity.CRITICAL,
            description="SSH Private Key detected"
        ),
        SecretPattern(
            secret_type=SecretType.PGP_PRIVATE_KEY,
            pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            severity=Severity.CRITICAL,
            description="PGP Private Key detected"
        ),
        
        # JWT
        SecretPattern(
            secret_type=SecretType.JWT_SECRET,
            pattern=r'(?i)(?:jwt|jws|jwe)[-_]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{16,})["\']?',
            severity=Severity.HIGH,
            description="JWT Secret detected"
        ),
        
        # Bearer Tokens
        SecretPattern(
            secret_type=SecretType.BEARER_TOKEN,
            pattern=r'(?i)bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            severity=Severity.HIGH,
            description="Bearer Token (JWT) detected"
        ),
        
        # Basic Auth
        SecretPattern(
            secret_type=SecretType.BASIC_AUTH,
            pattern=r'(?i)basic\s+[A-Za-z0-9+/=]{10,}',
            severity=Severity.HIGH,
            description="Basic Authentication credentials detected"
        ),
        
        # Generic Patterns
        SecretPattern(
            secret_type=SecretType.API_KEY_GENERIC,
            pattern=r'(?i)(?:api[-_]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
            severity=Severity.MEDIUM,
            description="Generic API Key detected",
            entropy_threshold=3.5
        ),
        SecretPattern(
            secret_type=SecretType.PASSWORD,
            pattern=r'(?i)(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
            severity=Severity.HIGH,
            description="Password detected",
            false_positive_patterns=[r'password\s*[:=]\s*["\']?\$?\{', r'password\s*[:=]\s*["\']?<', r'password\s*[:=]\s*["\']?process\.env']
        ),
        SecretPattern(
            secret_type=SecretType.SECRET_GENERIC,
            pattern=r'(?i)(?:secret|private)[-_]?(?:key)?["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{16,})["\']?',
            severity=Severity.MEDIUM,
            description="Generic secret/private key detected",
            entropy_threshold=3.5
        ),
        
        # NPM/PyPI Tokens
        SecretPattern(
            secret_type=SecretType.NPM_TOKEN,
            pattern=r'npm_[A-Za-z0-9]{36}',
            severity=Severity.HIGH,
            description="NPM Access Token detected"
        ),
        SecretPattern(
            secret_type=SecretType.PYPI_TOKEN,
            pattern=r'pypi-[A-Za-z0-9_-]{50,}',
            severity=Severity.HIGH,
            description="PyPI API Token detected"
        ),
        
        # Crypto Wallets
        SecretPattern(
            secret_type=SecretType.CRYPTO_WALLET,
            pattern=r'(?i)(?:private[-_]?key|mnemonic|seed[-_]?phrase)["\']?\s*[:=]\s*["\']?([A-Za-z0-9\s]{20,})["\']?',
            severity=Severity.CRITICAL,
            description="Cryptocurrency wallet key/seed detected"
        ),
        
        # Heroku
        SecretPattern(
            secret_type=SecretType.HEROKU_API_KEY,
            pattern=r'(?i)heroku[-_]?api[-_]?key["\']?\s*[:=]\s*["\']?([A-Fa-f0-9-]{36})["\']?',
            severity=Severity.HIGH,
            description="Heroku API Key detected"
        ),
        
        # DigitalOcean
        SecretPattern(
            secret_type=SecretType.DIGITALOCEAN_TOKEN,
            pattern=r'dop_v1_[A-Fa-f0-9]{64}',
            severity=Severity.HIGH,
            description="DigitalOcean Personal Access Token detected"
        ),
    ]
    
    # Files to always skip
    SKIP_FILES = {
        '.git', 'node_modules', '__pycache__', '.venv', 'venv',
        '.env.example', '.env.sample', '.env.template',
        'package-lock.json', 'yarn.lock', 'poetry.lock',
        '.min.js', '.min.css', '.map'
    }
    
    # File extensions to scan
    SCAN_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.cs', '.cpp', '.c', '.h', '.rs', '.swift', '.kt', '.scala',
        '.yaml', '.yml', '.json', '.xml', '.toml', '.ini', '.cfg', '.conf',
        '.env', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
        '.tf', '.tfvars', '.hcl', '.dockerfile', 'dockerfile',
        '.md', '.txt', '.sql', '.graphql', '.gql'
    }
    
    def __init__(self):
        self.findings: List[SecretFinding] = []
        self.scanned_files: int = 0
        self.total_lines: int = 0
        self.compiled_patterns: List[Tuple[SecretPattern, re.Pattern]] = []
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        for pattern in self.PATTERNS:
            try:
                compiled = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
                self.compiled_patterns.append((pattern, compiled))
            except re.error as e:
                print(f"Warning: Invalid pattern for {pattern.secret_type}: {e}")
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        entropy = 0.0
        for char in set(text):
            p = text.count(char) / len(text)
            if p > 0:
                entropy -= p * (p.bit_length() - 1 if p == 1 else -1 * p.__class__(p).as_integer_ratio()[0].bit_length())
        
        # Simplified entropy calculation
        import math
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        for count in char_counts.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask a secret value, showing only first and last few characters."""
        if len(secret) <= visible_chars * 2:
            return '*' * len(secret)
        return secret[:visible_chars] + '*' * (len(secret) - visible_chars * 2) + secret[-visible_chars:]
    
    def is_false_positive(self, match: str, pattern: SecretPattern, line: str) -> bool:
        """Check if a match is likely a false positive."""
        # Check false positive patterns
        for fp_pattern in pattern.false_positive_patterns:
            if re.search(fp_pattern, line, re.IGNORECASE):
                return True
        
        # Check for placeholder values
        placeholders = [
            'example', 'sample', 'test', 'demo', 'placeholder',
            'your_', 'xxx', 'yyy', 'zzz', 'TODO', 'FIXME',
            '${', '{{', '<%', '<#', 'process.env', 'os.environ'
        ]
        match_lower = match.lower()
        for ph in placeholders:
            if ph.lower() in match_lower:
                return True
        
        # Check entropy for high-entropy patterns
        if pattern.entropy_threshold > 0:
            entropy = self.calculate_entropy(match)
            if entropy < pattern.entropy_threshold:
                return True
        
        return False
    
    def generate_finding_id(self, file_path: str, line_number: int, secret_type: SecretType) -> str:
        """Generate unique finding ID."""
        hash_input = f"{file_path}:{line_number}:{secret_type.value}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12].upper()
    
    def get_remediation(self, secret_type: SecretType) -> str:
        """Get remediation advice for a secret type."""
        remediations = {
            SecretType.AWS_ACCESS_KEY: "1. Immediately rotate the AWS credentials\n2. Check CloudTrail for unauthorized access\n3. Use IAM roles instead of access keys\n4. Store secrets in AWS Secrets Manager",
            SecretType.AWS_SECRET_KEY: "1. Rotate the AWS secret key immediately\n2. Review IAM policies for least privilege\n3. Enable MFA for the IAM user\n4. Use temporary credentials with STS",
            SecretType.GITHUB_TOKEN: "1. Revoke the token at github.com/settings/tokens\n2. Create a new token with minimal scopes\n3. Use GitHub Apps for better security\n4. Enable token expiration",
            SecretType.SLACK_TOKEN: "1. Revoke the token in Slack workspace settings\n2. Regenerate with minimal permissions\n3. Use environment variables for storage",
            SecretType.STRIPE_API_KEY: "1. Roll the API key in Stripe dashboard\n2. Enable restricted keys\n3. Use environment variables\n4. Review payment logs for fraud",
            SecretType.DATABASE_URL: "1. Change database password immediately\n2. Restrict database network access\n3. Use connection pooling with rotation\n4. Enable database audit logging",
            SecretType.SSH_PRIVATE_KEY: "1. Remove the key from authorized_keys\n2. Generate new key pair\n3. Never commit private keys to repos\n4. Use SSH certificates instead",
            SecretType.JWT_SECRET: "1. Rotate the JWT secret\n2. Invalidate all existing tokens\n3. Use asymmetric keys (RS256)\n4. Implement token refresh mechanism",
            SecretType.PASSWORD: "1. Change the password immediately\n2. Use a password manager\n3. Never hardcode passwords\n4. Use environment variables or secret managers"
        }
        
        default = """1. Rotate/regenerate the exposed credential immediately
2. Remove from source code and git history
3. Use environment variables or secret management
4. Audit access logs for unauthorized usage
5. Implement pre-commit hooks to prevent future leaks"""
        
        return remediations.get(secret_type, default)
    
    async def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file for secrets."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            self.total_lines += len(lines)
            
            for line_num, line in enumerate(lines, 1):
                for pattern, compiled_regex in self.compiled_patterns:
                    matches = compiled_regex.finditer(line)
                    
                    for match in matches:
                        # Get the actual secret value (first group or full match)
                        secret_value = match.group(1) if match.lastindex else match.group(0)
                        
                        # Check for false positives
                        if self.is_false_positive(secret_value, pattern, line):
                            continue
                        
                        # Get context
                        context_before = lines[max(0, line_num-3):line_num-1]
                        context_after = lines[line_num:min(len(lines), line_num+2)]
                        
                        finding = SecretFinding(
                            id=self.generate_finding_id(str(file_path), line_num, pattern.secret_type),
                            secret_type=pattern.secret_type,
                            severity=pattern.severity,
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.strip(),
                            secret_value=self.mask_secret(secret_value),
                            full_match=match.group(0)[:100],
                            entropy=self.calculate_entropy(secret_value),
                            description=pattern.description,
                            remediation=self.get_remediation(pattern.secret_type),
                            context_before=context_before,
                            context_after=context_after
                        )
                        
                        findings.append(finding)
            
            self.scanned_files += 1
            
        except Exception as e:
            pass  # Skip files that can't be read
        
        return findings
    
    async def scan_directory(self, directory: Path, recursive: bool = True) -> List[SecretFinding]:
        """Scan a directory for secrets."""
        all_findings = []
        
        if not directory.exists():
            return all_findings
        
        pattern = '**/*' if recursive else '*'
        
        for file_path in directory.glob(pattern):
            # Skip directories and non-scannable files
            if file_path.is_dir():
                continue
            
            # Check if in skip list
            skip = False
            for skip_pattern in self.SKIP_FILES:
                if skip_pattern in str(file_path):
                    skip = True
                    break
            
            if skip:
                continue
            
            # Check extension
            suffix = file_path.suffix.lower()
            if suffix not in self.SCAN_EXTENSIONS and file_path.name.lower() not in ['dockerfile', '.env']:
                continue
            
            findings = await self.scan_file(file_path)
            all_findings.extend(findings)
        
        self.findings = all_findings
        return all_findings
    
    async def scan_git_history(self, repo_path: Path, max_commits: int = 100) -> List[SecretFinding]:
        """Scan git history for secrets."""
        findings = []
        
        try:
            import subprocess
            
            # Get commit history
            result = subprocess.run(
                ['git', 'log', '--pretty=format:%H|%an|%aI', f'-{max_commits}'],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return findings
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) != 3:
                    continue
                
                commit_hash, author, date = parts
                
                # Get diff for this commit
                diff_result = subprocess.run(
                    ['git', 'show', '--format=', commit_hash],
                    cwd=repo_path,
                    capture_output=True,
                    text=True
                )
                
                if diff_result.returncode == 0:
                    diff_content = diff_result.stdout
                    
                    for pattern, compiled_regex in self.compiled_patterns:
                        matches = compiled_regex.finditer(diff_content)
                        
                        for match in matches:
                            secret_value = match.group(1) if match.lastindex else match.group(0)
                            
                            if self.is_false_positive(secret_value, pattern, match.group(0)):
                                continue
                            
                            finding = SecretFinding(
                                id=self.generate_finding_id(commit_hash, 0, pattern.secret_type),
                                secret_type=pattern.secret_type,
                                severity=pattern.severity,
                                file_path=f"git:{commit_hash[:8]}",
                                line_number=0,
                                line_content=match.group(0)[:100],
                                secret_value=self.mask_secret(secret_value),
                                full_match=match.group(0)[:100],
                                entropy=self.calculate_entropy(secret_value),
                                description=f"{pattern.description} (in git history)",
                                remediation=self.get_remediation(pattern.secret_type),
                                commit_hash=commit_hash,
                                author=author,
                                commit_date=datetime.fromisoformat(date.replace('Z', '+00:00')) if date else None
                            )
                            
                            findings.append(finding)
        
        except Exception as e:
            pass
        
        return findings
    
    async def scan_url(self, url: str) -> List[SecretFinding]:
        """Scan a URL's content for secrets."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    content = await response.text()
                    
                    lines = content.split('\n')
                    
                    for line_num, line in enumerate(lines, 1):
                        for pattern, compiled_regex in self.compiled_patterns:
                            matches = compiled_regex.finditer(line)
                            
                            for match in matches:
                                secret_value = match.group(1) if match.lastindex else match.group(0)
                                
                                if self.is_false_positive(secret_value, pattern, line):
                                    continue
                                
                                finding = SecretFinding(
                                    id=self.generate_finding_id(url, line_num, pattern.secret_type),
                                    secret_type=pattern.secret_type,
                                    severity=pattern.severity,
                                    file_path=url,
                                    line_number=line_num,
                                    line_content=line.strip()[:200],
                                    secret_value=self.mask_secret(secret_value),
                                    full_match=match.group(0)[:100],
                                    entropy=self.calculate_entropy(secret_value),
                                    description=f"{pattern.description} (from URL)",
                                    remediation=self.get_remediation(pattern.secret_type)
                                )
                                
                                findings.append(finding)
        
        except Exception as e:
            pass
        
        return findings
    
    async def verify_secret(self, finding: SecretFinding) -> bool:
        """Attempt to verify if a secret is valid/active."""
        # This would contain API-specific validation
        # For security, we don't actually test credentials
        # but could check format validity
        
        return False  # Return False for safety
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics."""
        severity_counts = {}
        type_counts = {}
        
        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            stype = finding.secret_type.value
            type_counts[stype] = type_counts.get(stype, 0) + 1
        
        return {
            "total_findings": len(self.findings),
            "files_scanned": self.scanned_files,
            "lines_scanned": self.total_lines,
            "by_severity": severity_counts,
            "by_type": type_counts,
            "critical_count": severity_counts.get("Critical", 0),
            "high_count": severity_counts.get("High", 0)
        }
    
    def export_findings(self, format: str = "json") -> str:
        """Export findings in specified format."""
        if format == "json":
            return json.dumps([{
                "id": f.id,
                "type": f.secret_type.value,
                "severity": f.severity.value,
                "file": f.file_path,
                "line": f.line_number,
                "secret": f.secret_value,
                "description": f.description,
                "remediation": f.remediation
            } for f in self.findings], indent=2)
        
        elif format == "csv":
            lines = ["ID,Type,Severity,File,Line,Secret,Description"]
            for f in self.findings:
                lines.append(f'"{f.id}","{f.secret_type.value}","{f.severity.value}","{f.file_path}",{f.line_number},"{f.secret_value}","{f.description}"')
            return '\n'.join(lines)
        
        elif format == "sarif":
            return json.dumps({
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "HydraRecon Secrets Scanner",
                            "version": "1.0.0"
                        }
                    },
                    "results": [{
                        "ruleId": f.secret_type.value.replace(" ", "-").lower(),
                        "level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "warning",
                        "message": {"text": f.description},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file_path},
                                "region": {"startLine": f.line_number}
                            }
                        }]
                    } for f in self.findings]
                }]
            }, indent=2)
        
        return ""
