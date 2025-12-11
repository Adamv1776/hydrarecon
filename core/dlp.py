#!/usr/bin/env python3
"""
HydraRecon Data Loss Prevention Module
Enterprise DLP for detecting and preventing data exfiltration.
"""

import asyncio
import re
import hashlib
import mimetypes
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Set, Pattern
from pathlib import Path
import logging


class DataClassification(Enum):
    """Data sensitivity levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class ContentType(Enum):
    """Types of sensitive content"""
    PII = "pii"  # Personal Identifiable Information
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Industry
    CREDENTIALS = "credentials"
    SOURCE_CODE = "source_code"
    FINANCIAL = "financial"
    LEGAL = "legal"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    CUSTOM = "custom"


class ViolationSeverity(Enum):
    """Severity levels for DLP violations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(Enum):
    """Actions to take on DLP violations"""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ENCRYPT = "encrypt"
    NOTIFY = "notify"
    LOG = "log"


class ChannelType(Enum):
    """Data exfiltration channels"""
    EMAIL = "email"
    WEB_UPLOAD = "web_upload"
    USB = "usb"
    CLOUD_STORAGE = "cloud_storage"
    PRINT = "print"
    CLIPBOARD = "clipboard"
    NETWORK = "network"
    IM = "instant_messaging"


@dataclass
class DLPPattern:
    """Pattern for detecting sensitive data"""
    id: str
    name: str
    description: str
    content_type: ContentType
    pattern: str  # Regex pattern
    compiled: Optional[Pattern] = None
    keywords: List[str] = field(default_factory=list)
    threshold: int = 1  # Minimum matches to trigger
    classification: DataClassification = DataClassification.CONFIDENTIAL
    enabled: bool = True
    custom_validator: Optional[str] = None  # Python function name
    
    def __post_init__(self):
        if self.pattern:
            try:
                self.compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                self.compiled = None


@dataclass
class DLPPolicy:
    """DLP policy definition"""
    id: str
    name: str
    description: str
    patterns: List[str] = field(default_factory=list)  # Pattern IDs
    channels: List[ChannelType] = field(default_factory=list)
    actions: List[ActionType] = field(default_factory=list)
    severity: ViolationSeverity = ViolationSeverity.HIGH
    enabled: bool = True
    exceptions: List[str] = field(default_factory=list)  # User/group exceptions
    schedule: Optional[Dict[str, Any]] = None  # Time-based policy
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class DLPViolation:
    """Recorded DLP violation"""
    id: str
    timestamp: datetime
    policy_id: str
    policy_name: str
    user: str
    source: str
    destination: str
    channel: ChannelType
    content_type: ContentType
    classification: DataClassification
    severity: ViolationSeverity
    matches: List[Dict[str, Any]] = field(default_factory=list)
    action_taken: ActionType = ActionType.LOG
    file_hash: Optional[str] = None
    file_name: Optional[str] = None
    file_size: int = 0
    blocked: bool = False
    acknowledged: bool = False
    remediated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataInventoryItem:
    """Tracked sensitive data item"""
    id: str
    path: str
    file_name: str
    content_type: ContentType
    classification: DataClassification
    owner: str
    size: int
    hash: str
    discovered_at: datetime
    last_accessed: Optional[datetime] = None
    access_count: int = 0
    patterns_matched: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DLPEndpoint:
    """Monitored DLP endpoint"""
    id: str
    hostname: str
    ip_address: str
    os: str
    agent_version: str
    last_seen: datetime
    status: str = "active"
    policies: List[str] = field(default_factory=list)
    violations_count: int = 0


class DLPEngine:
    """Enterprise Data Loss Prevention Engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("DLPEngine")
        self.patterns: Dict[str, DLPPattern] = {}
        self.policies: Dict[str, DLPPolicy] = {}
        self.violations: List[DLPViolation] = []
        self.inventory: Dict[str, DataInventoryItem] = {}
        self.endpoints: Dict[str, DLPEndpoint] = {}
        self._init_builtin_patterns()
    
    def _init_builtin_patterns(self):
        """Initialize built-in DLP patterns"""
        builtin = [
            # PII Patterns
            DLPPattern(
                id="ssn_us",
                name="US Social Security Number",
                description="Matches US SSN format XXX-XX-XXXX",
                content_type=ContentType.PII,
                pattern=r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
                classification=DataClassification.RESTRICTED
            ),
            DLPPattern(
                id="email",
                name="Email Address",
                description="Matches email addresses",
                content_type=ContentType.PII,
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                classification=DataClassification.INTERNAL,
                threshold=5
            ),
            DLPPattern(
                id="phone_us",
                name="US Phone Number",
                description="Matches US phone number formats",
                content_type=ContentType.PII,
                pattern=r'\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b',
                classification=DataClassification.INTERNAL
            ),
            DLPPattern(
                id="passport_us",
                name="US Passport Number",
                description="Matches US passport numbers",
                content_type=ContentType.PII,
                pattern=r'\b[A-Z]\d{8}\b',
                classification=DataClassification.RESTRICTED
            ),
            DLPPattern(
                id="drivers_license",
                name="Driver's License",
                description="Common US driver's license formats",
                content_type=ContentType.PII,
                pattern=r'\b[A-Z]{1,2}\d{6,8}\b',
                classification=DataClassification.RESTRICTED
            ),
            
            # PCI Patterns
            DLPPattern(
                id="credit_card_visa",
                name="Visa Credit Card",
                description="Matches Visa card numbers",
                content_type=ContentType.PCI,
                pattern=r'\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                classification=DataClassification.TOP_SECRET
            ),
            DLPPattern(
                id="credit_card_mc",
                name="MasterCard Credit Card",
                description="Matches MasterCard numbers",
                content_type=ContentType.PCI,
                pattern=r'\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                classification=DataClassification.TOP_SECRET
            ),
            DLPPattern(
                id="credit_card_amex",
                name="American Express Card",
                description="Matches Amex card numbers",
                content_type=ContentType.PCI,
                pattern=r'\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b',
                classification=DataClassification.TOP_SECRET
            ),
            DLPPattern(
                id="cvv",
                name="CVV/CVC Code",
                description="3-4 digit security code",
                content_type=ContentType.PCI,
                pattern=r'\bCVV[:\s]?\d{3,4}\b',
                keywords=["cvv", "cvc", "security code"],
                classification=DataClassification.TOP_SECRET
            ),
            
            # PHI Patterns
            DLPPattern(
                id="medical_record",
                name="Medical Record Number",
                description="Common MRN formats",
                content_type=ContentType.PHI,
                pattern=r'\bMRN[:\s#]?\d{6,10}\b',
                keywords=["patient", "diagnosis", "medical"],
                classification=DataClassification.RESTRICTED
            ),
            DLPPattern(
                id="npi",
                name="National Provider Identifier",
                description="10-digit NPI number",
                content_type=ContentType.PHI,
                pattern=r'\bNPI[:\s]?\d{10}\b',
                classification=DataClassification.CONFIDENTIAL
            ),
            
            # Credential Patterns
            DLPPattern(
                id="aws_access_key",
                name="AWS Access Key",
                description="AWS Access Key ID",
                content_type=ContentType.CREDENTIALS,
                pattern=r'\bAKIA[0-9A-Z]{16}\b',
                classification=DataClassification.TOP_SECRET
            ),
            DLPPattern(
                id="aws_secret_key",
                name="AWS Secret Key",
                description="AWS Secret Access Key",
                content_type=ContentType.CREDENTIALS,
                pattern=r'\b[A-Za-z0-9/+=]{40}\b',
                keywords=["aws_secret", "secret_access_key"],
                classification=DataClassification.TOP_SECRET
            ),
            DLPPattern(
                id="private_key",
                name="Private Key",
                description="RSA/SSH private key header",
                content_type=ContentType.CREDENTIALS,
                pattern=r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
                classification=DataClassification.TOP_SECRET
            ),
            DLPPattern(
                id="api_key_generic",
                name="Generic API Key",
                description="Common API key patterns",
                content_type=ContentType.CREDENTIALS,
                pattern=r'\b(?:api[_-]?key|apikey|api_secret)[:\s=]+[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?',
                classification=DataClassification.RESTRICTED
            ),
            DLPPattern(
                id="password_field",
                name="Password in Config",
                description="Password fields in configuration",
                content_type=ContentType.CREDENTIALS,
                pattern=r'(?:password|passwd|pwd|secret)[:\s=]+[\'"]?([^\s\'"]{8,})[\'"]?',
                keywords=["password", "secret", "credential"],
                classification=DataClassification.TOP_SECRET
            ),
            
            # Financial Patterns
            DLPPattern(
                id="iban",
                name="International Bank Account Number",
                description="IBAN format",
                content_type=ContentType.FINANCIAL,
                pattern=r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
                classification=DataClassification.RESTRICTED
            ),
            DLPPattern(
                id="routing_number",
                name="Bank Routing Number",
                description="US bank routing number",
                content_type=ContentType.FINANCIAL,
                pattern=r'\b\d{9}\b',
                keywords=["routing", "aba", "transit"],
                classification=DataClassification.CONFIDENTIAL
            ),
            
            # Source Code Patterns
            DLPPattern(
                id="source_code_header",
                name="Source Code Header",
                description="Proprietary code markers",
                content_type=ContentType.SOURCE_CODE,
                pattern=r'(?:Copyright|Proprietary|Confidential)[^\n]*(?:Inc\.|Corp\.|Ltd\.)',
                keywords=["proprietary", "trade secret", "confidential"],
                classification=DataClassification.RESTRICTED
            ),
        ]
        
        for pattern in builtin:
            self.patterns[pattern.id] = pattern
    
    async def scan_content(
        self,
        content: str,
        source: str = "",
        metadata: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        """Scan content for sensitive data patterns"""
        matches = []
        
        for pattern in self.patterns.values():
            if not pattern.enabled or not pattern.compiled:
                continue
            
            found = pattern.compiled.findall(content)
            
            # Check keywords
            keyword_matches = []
            for keyword in pattern.keywords:
                if keyword.lower() in content.lower():
                    keyword_matches.append(keyword)
            
            if len(found) >= pattern.threshold or keyword_matches:
                matches.append({
                    "pattern_id": pattern.id,
                    "pattern_name": pattern.name,
                    "content_type": pattern.content_type.value,
                    "classification": pattern.classification.value,
                    "match_count": len(found),
                    "keyword_matches": keyword_matches,
                    "samples": found[:5] if found else [],  # Limit samples for safety
                    "source": source
                })
        
        return matches
    
    async def scan_file(
        self,
        file_path: str,
        user: str = "system"
    ) -> List[Dict[str, Any]]:
        """Scan a file for sensitive data"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Get file info
        file_size = path.stat().st_size
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        
        # Determine file type
        mime_type, _ = mimetypes.guess_type(file_path)
        
        # Read content based on type
        try:
            if mime_type and mime_type.startswith("text"):
                content = path.read_text(errors='ignore')
            else:
                # For binary files, convert to hex representation for pattern matching
                content = path.read_bytes().decode('utf-8', errors='ignore')
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return []
        
        # Scan content
        matches = await self.scan_content(content, source=file_path)
        
        # Add file metadata
        for match in matches:
            match["file_path"] = file_path
            match["file_size"] = file_size
            match["file_hash"] = file_hash
            match["mime_type"] = mime_type
            match["scanned_by"] = user
        
        # Add to inventory if sensitive data found
        if matches:
            await self._add_to_inventory(file_path, matches, file_hash, file_size, user)
        
        return matches
    
    async def _add_to_inventory(
        self,
        file_path: str,
        matches: List[Dict],
        file_hash: str,
        file_size: int,
        owner: str
    ):
        """Add discovered sensitive data to inventory"""
        # Determine highest classification
        classifications = [
            DataClassification(m["classification"]) for m in matches
        ]
        highest = max(classifications, key=lambda c: list(DataClassification).index(c))
        
        # Determine content types
        content_types = set(m["content_type"] for m in matches)
        primary_type = ContentType(matches[0]["content_type"])
        
        item_id = hashlib.sha256(file_path.encode()).hexdigest()[:16]
        
        item = DataInventoryItem(
            id=item_id,
            path=file_path,
            file_name=Path(file_path).name,
            content_type=primary_type,
            classification=highest,
            owner=owner,
            size=file_size,
            hash=file_hash,
            discovered_at=datetime.now(),
            patterns_matched=[m["pattern_id"] for m in matches]
        )
        
        self.inventory[item_id] = item
    
    async def create_policy(
        self,
        name: str,
        description: str,
        pattern_ids: List[str],
        channels: List[ChannelType],
        actions: List[ActionType],
        severity: ViolationSeverity = ViolationSeverity.HIGH,
        exceptions: Optional[List[str]] = None
    ) -> DLPPolicy:
        """Create a DLP policy"""
        policy_id = hashlib.sha256(
            f"{name}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        policy = DLPPolicy(
            id=policy_id,
            name=name,
            description=description,
            patterns=pattern_ids,
            channels=channels,
            actions=actions,
            severity=severity,
            exceptions=exceptions or []
        )
        
        self.policies[policy_id] = policy
        return policy
    
    async def evaluate_transfer(
        self,
        content: str,
        user: str,
        source: str,
        destination: str,
        channel: ChannelType,
        file_name: Optional[str] = None,
        file_size: int = 0
    ) -> Dict[str, Any]:
        """Evaluate a data transfer against DLP policies"""
        result = {
            "allowed": True,
            "violations": [],
            "actions": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Scan content for sensitive data
        matches = await self.scan_content(content, source)
        
        if not matches:
            return result
        
        # Check against policies
        for policy in self.policies.values():
            if not policy.enabled:
                continue
            
            # Check channel
            if channel not in policy.channels:
                continue
            
            # Check exceptions
            if user in policy.exceptions:
                continue
            
            # Check patterns
            policy_matches = [
                m for m in matches if m["pattern_id"] in policy.patterns
            ]
            
            if policy_matches:
                # Create violation
                violation_id = hashlib.sha256(
                    f"{policy.id}{user}{datetime.now().isoformat()}".encode()
                ).hexdigest()[:16]
                
                violation = DLPViolation(
                    id=violation_id,
                    timestamp=datetime.now(),
                    policy_id=policy.id,
                    policy_name=policy.name,
                    user=user,
                    source=source,
                    destination=destination,
                    channel=channel,
                    content_type=ContentType(policy_matches[0]["content_type"]),
                    classification=DataClassification(policy_matches[0]["classification"]),
                    severity=policy.severity,
                    matches=policy_matches,
                    file_name=file_name,
                    file_size=file_size
                )
                
                # Determine actions
                for action in policy.actions:
                    if action == ActionType.BLOCK:
                        result["allowed"] = False
                        violation.blocked = True
                    violation.action_taken = action
                
                self.violations.append(violation)
                result["violations"].append({
                    "violation_id": violation_id,
                    "policy": policy.name,
                    "severity": policy.severity.value,
                    "matches": len(policy_matches)
                })
                result["actions"].extend([a.value for a in policy.actions])
        
        return result
    
    async def add_custom_pattern(
        self,
        name: str,
        description: str,
        content_type: ContentType,
        pattern: str,
        classification: DataClassification = DataClassification.CONFIDENTIAL,
        keywords: Optional[List[str]] = None,
        threshold: int = 1
    ) -> DLPPattern:
        """Add a custom DLP pattern"""
        pattern_id = f"custom_{hashlib.sha256(name.encode()).hexdigest()[:12]}"
        
        dlp_pattern = DLPPattern(
            id=pattern_id,
            name=name,
            description=description,
            content_type=content_type,
            pattern=pattern,
            keywords=keywords or [],
            threshold=threshold,
            classification=classification
        )
        
        self.patterns[pattern_id] = dlp_pattern
        return dlp_pattern
    
    def get_violations(
        self,
        time_range: Optional[timedelta] = None,
        severity: Optional[ViolationSeverity] = None,
        user: Optional[str] = None,
        policy_id: Optional[str] = None
    ) -> List[DLPViolation]:
        """Get DLP violations with optional filters"""
        violations = self.violations.copy()
        
        if time_range:
            cutoff = datetime.now() - time_range
            violations = [v for v in violations if v.timestamp >= cutoff]
        
        if severity:
            violations = [v for v in violations if v.severity == severity]
        
        if user:
            violations = [v for v in violations if v.user == user]
        
        if policy_id:
            violations = [v for v in violations if v.policy_id == policy_id]
        
        return violations
    
    async def generate_report(
        self,
        time_range: Optional[timedelta] = None
    ) -> Dict[str, Any]:
        """Generate DLP report"""
        violations = self.get_violations(time_range=time_range)
        
        # Aggregate by severity
        by_severity = {}
        for v in violations:
            sev = v.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # Aggregate by channel
        by_channel = {}
        for v in violations:
            ch = v.channel.value
            by_channel[ch] = by_channel.get(ch, 0) + 1
        
        # Aggregate by user
        by_user = {}
        for v in violations:
            by_user[v.user] = by_user.get(v.user, 0) + 1
        
        # Aggregate by content type
        by_type = {}
        for v in violations:
            ct = v.content_type.value
            by_type[ct] = by_type.get(ct, 0) + 1
        
        # Top violators
        top_users = sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Blocked transfers
        blocked = sum(1 for v in violations if v.blocked)
        
        return {
            "generated_at": datetime.now().isoformat(),
            "period": str(time_range) if time_range else "all_time",
            "summary": {
                "total_violations": len(violations),
                "blocked_transfers": blocked,
                "unique_users": len(by_user),
                "total_policies": len(self.policies),
                "total_patterns": len(self.patterns),
                "inventory_items": len(self.inventory)
            },
            "by_severity": by_severity,
            "by_channel": by_channel,
            "by_content_type": by_type,
            "top_violators": top_users,
            "critical_violations": [
                {
                    "id": v.id,
                    "timestamp": v.timestamp.isoformat(),
                    "user": v.user,
                    "policy": v.policy_name,
                    "blocked": v.blocked
                }
                for v in violations if v.severity == ViolationSeverity.CRITICAL
            ][:20]
        }
    
    async def discover_sensitive_data(
        self,
        scan_paths: List[str],
        recursive: bool = True,
        file_extensions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Discover sensitive data across file systems"""
        results = {
            "scanned_files": 0,
            "sensitive_files": 0,
            "findings": [],
            "errors": []
        }
        
        default_extensions = [
            '.txt', '.csv', '.json', '.xml', '.yml', '.yaml',
            '.conf', '.cfg', '.ini', '.env', '.log',
            '.doc', '.docx', '.xls', '.xlsx', '.pdf',
            '.sql', '.db', '.sqlite'
        ]
        extensions = file_extensions or default_extensions
        
        for scan_path in scan_paths:
            path = Path(scan_path)
            if not path.exists():
                results["errors"].append(f"Path not found: {scan_path}")
                continue
            
            # Get files to scan
            if path.is_file():
                files = [path]
            elif recursive:
                files = [f for f in path.rglob("*") if f.is_file()]
            else:
                files = [f for f in path.iterdir() if f.is_file()]
            
            # Filter by extension
            files = [f for f in files if f.suffix.lower() in extensions]
            
            for file_path in files:
                try:
                    results["scanned_files"] += 1
                    matches = await self.scan_file(str(file_path))
                    
                    if matches:
                        results["sensitive_files"] += 1
                        results["findings"].append({
                            "file": str(file_path),
                            "matches": matches
                        })
                except Exception as e:
                    results["errors"].append(f"Error scanning {file_path}: {str(e)}")
        
        return results
    
    def get_inventory_by_classification(
        self,
        classification: Optional[DataClassification] = None
    ) -> List[DataInventoryItem]:
        """Get inventory items by classification"""
        if classification:
            return [
                item for item in self.inventory.values()
                if item.classification == classification
            ]
        return list(self.inventory.values())
    
    async def export_inventory(self) -> List[Dict[str, Any]]:
        """Export data inventory"""
        return [
            {
                "id": item.id,
                "path": item.path,
                "file_name": item.file_name,
                "content_type": item.content_type.value,
                "classification": item.classification.value,
                "owner": item.owner,
                "size": item.size,
                "hash": item.hash,
                "discovered_at": item.discovered_at.isoformat(),
                "patterns_matched": item.patterns_matched
            }
            for item in self.inventory.values()
        ]
