"""
HydraRecon Configuration Management Database (CMDB) Module
Enterprise asset configuration tracking, relationships, and change management
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
import logging


class CIType(Enum):
    """Configuration Item types"""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    DATABASE = "database"
    APPLICATION = "application"
    SERVICE = "service"
    CONTAINER = "container"
    VIRTUAL_MACHINE = "virtual_machine"
    CLOUD_RESOURCE = "cloud_resource"
    STORAGE = "storage"
    CERTIFICATE = "certificate"
    LICENSE = "license"
    DOMAIN = "domain"
    DNS_RECORD = "dns_record"
    SUBNET = "subnet"
    VLAN = "vlan"
    USER_ACCOUNT = "user_account"
    GROUP = "group"
    POLICY = "policy"


class CIStatus(Enum):
    """Configuration Item status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PLANNED = "planned"
    IN_DEVELOPMENT = "in_development"
    IN_TESTING = "in_testing"
    DEPLOYED = "deployed"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"
    RETIRED = "retired"
    UNKNOWN = "unknown"


class RelationshipType(Enum):
    """CI relationship types"""
    DEPENDS_ON = "depends_on"
    USED_BY = "used_by"
    CONTAINS = "contains"
    PART_OF = "part_of"
    RUNS_ON = "runs_on"
    HOSTS = "hosts"
    CONNECTS_TO = "connects_to"
    MANAGES = "manages"
    MANAGED_BY = "managed_by"
    BACKS_UP = "backs_up"
    BACKED_UP_BY = "backed_up_by"
    REPLICATES_TO = "replicates_to"
    LOAD_BALANCES = "load_balances"
    PROTECTS = "protects"
    PROTECTED_BY = "protected_by"
    AUTHENTICATES = "authenticates"


class ChangeType(Enum):
    """Change request types"""
    STANDARD = "standard"
    NORMAL = "normal"
    EMERGENCY = "emergency"
    MAJOR = "major"
    MINOR = "minor"


class ChangeStatus(Enum):
    """Change request status"""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class CriticalityLevel(Enum):
    """Asset criticality levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class ConfigurationItem:
    """Configuration Item (CI) representation"""
    ci_id: str
    name: str
    ci_type: CIType
    status: CIStatus
    description: str = ""
    owner: str = ""
    department: str = ""
    location: str = ""
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    
    # Technical details
    ip_address: str = ""
    hostname: str = ""
    fqdn: str = ""
    mac_address: str = ""
    os_type: str = ""
    os_version: str = ""
    software_version: str = ""
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    
    # Cloud/virtual details
    cloud_provider: str = ""
    cloud_region: str = ""
    instance_type: str = ""
    resource_id: str = ""
    
    # Compliance & security
    compliance_frameworks: List[str] = field(default_factory=list)
    security_classification: str = ""
    last_vulnerability_scan: Optional[datetime] = None
    vulnerability_count: int = 0
    risk_score: float = 0.0
    
    # Lifecycle
    purchase_date: Optional[datetime] = None
    warranty_expiry: Optional[datetime] = None
    end_of_life: Optional[datetime] = None
    end_of_support: Optional[datetime] = None
    
    # Metadata
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    updated_by: str = ""
    version: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ci_id": self.ci_id,
            "name": self.name,
            "ci_type": self.ci_type.value,
            "status": self.status.value,
            "description": self.description,
            "owner": self.owner,
            "department": self.department,
            "location": self.location,
            "criticality": self.criticality.value,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "software_version": self.software_version,
            "compliance_frameworks": self.compliance_frameworks,
            "vulnerability_count": self.vulnerability_count,
            "risk_score": self.risk_score,
            "tags": self.tags,
            "version": self.version
        }


@dataclass
class CIRelationship:
    """Relationship between Configuration Items"""
    relationship_id: str
    source_ci_id: str
    target_ci_id: str
    relationship_type: RelationshipType
    description: str = ""
    is_bidirectional: bool = False
    strength: float = 1.0  # 0-1 representing relationship strength
    attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "source_ci_id": self.source_ci_id,
            "target_ci_id": self.target_ci_id,
            "relationship_type": self.relationship_type.value,
            "description": self.description,
            "is_bidirectional": self.is_bidirectional,
            "strength": self.strength
        }


@dataclass
class ChangeRequest:
    """Change Request for CMDB"""
    change_id: str
    title: str
    description: str
    change_type: ChangeType
    status: ChangeStatus = ChangeStatus.DRAFT
    priority: CriticalityLevel = CriticalityLevel.MEDIUM
    
    # Affected CIs
    affected_cis: List[str] = field(default_factory=list)
    
    # Planning
    requested_by: str = ""
    assigned_to: str = ""
    approvers: List[str] = field(default_factory=list)
    approved_by: List[str] = field(default_factory=list)
    
    # Scheduling
    planned_start: Optional[datetime] = None
    planned_end: Optional[datetime] = None
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    
    # Risk assessment
    risk_level: str = "medium"
    impact_analysis: str = ""
    rollback_plan: str = ""
    test_plan: str = ""
    
    # Implementation
    implementation_notes: str = ""
    post_implementation_review: str = ""
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_id": self.change_id,
            "title": self.title,
            "description": self.description,
            "change_type": self.change_type.value,
            "status": self.status.value,
            "priority": self.priority.value,
            "affected_cis": self.affected_cis,
            "requested_by": self.requested_by,
            "assigned_to": self.assigned_to,
            "risk_level": self.risk_level,
            "planned_start": self.planned_start.isoformat() if self.planned_start else None,
            "planned_end": self.planned_end.isoformat() if self.planned_end else None
        }


@dataclass
class CMDBSnapshot:
    """Point-in-time snapshot of CMDB state"""
    snapshot_id: str
    name: str
    description: str
    ci_count: int = 0
    relationship_count: int = 0
    data_hash: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    
    # Snapshot data
    ci_data: Dict[str, Any] = field(default_factory=dict)
    relationship_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CMDBReport:
    """CMDB reporting structure"""
    report_id: str
    report_type: str
    title: str
    generated_at: datetime = field(default_factory=datetime.now)
    generated_by: str = ""
    
    # Statistics
    total_cis: int = 0
    cis_by_type: Dict[str, int] = field(default_factory=dict)
    cis_by_status: Dict[str, int] = field(default_factory=dict)
    cis_by_criticality: Dict[str, int] = field(default_factory=dict)
    total_relationships: int = 0
    
    # Health metrics
    compliance_score: float = 0.0
    data_quality_score: float = 0.0
    stale_cis_count: int = 0
    orphaned_cis_count: int = 0
    
    # Findings
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class CMDBEngine:
    """Configuration Management Database Engine"""
    
    def __init__(self, db_path: str = "cmdb.db"):
        self.db_path = db_path
        self.logger = logging.getLogger("CMDBEngine")
        self.configuration_items: Dict[str, ConfigurationItem] = {}
        self.relationships: Dict[str, CIRelationship] = {}
        self.change_requests: Dict[str, ChangeRequest] = {}
        self.snapshots: Dict[str, CMDBSnapshot] = {}
        
        # Discovery configuration
        self.discovery_enabled = True
        self.auto_relationship_detection = True
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for CMDB"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Configuration Items table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS configuration_items (
                ci_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ci_type TEXT NOT NULL,
                status TEXT NOT NULL,
                description TEXT,
                owner TEXT,
                department TEXT,
                location TEXT,
                criticality TEXT,
                ip_address TEXT,
                hostname TEXT,
                fqdn TEXT,
                mac_address TEXT,
                os_type TEXT,
                os_version TEXT,
                software_version TEXT,
                manufacturer TEXT,
                model TEXT,
                serial_number TEXT,
                cloud_provider TEXT,
                cloud_region TEXT,
                instance_type TEXT,
                resource_id TEXT,
                compliance_frameworks TEXT,
                security_classification TEXT,
                vulnerability_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0,
                attributes TEXT,
                tags TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                created_by TEXT,
                updated_by TEXT,
                version INTEGER DEFAULT 1
            )
        """)
        
        # Relationships table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ci_relationships (
                relationship_id TEXT PRIMARY KEY,
                source_ci_id TEXT NOT NULL,
                target_ci_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                description TEXT,
                is_bidirectional INTEGER DEFAULT 0,
                strength REAL DEFAULT 1.0,
                attributes TEXT,
                created_at TIMESTAMP,
                created_by TEXT,
                FOREIGN KEY (source_ci_id) REFERENCES configuration_items(ci_id),
                FOREIGN KEY (target_ci_id) REFERENCES configuration_items(ci_id)
            )
        """)
        
        # Change requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS change_requests (
                change_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                change_type TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT,
                affected_cis TEXT,
                requested_by TEXT,
                assigned_to TEXT,
                approvers TEXT,
                approved_by TEXT,
                planned_start TIMESTAMP,
                planned_end TIMESTAMP,
                actual_start TIMESTAMP,
                actual_end TIMESTAMP,
                risk_level TEXT,
                impact_analysis TEXT,
                rollback_plan TEXT,
                test_plan TEXT,
                implementation_notes TEXT,
                post_implementation_review TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """)
        
        # CI history table for version tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ci_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ci_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                change_type TEXT NOT NULL,
                changed_fields TEXT,
                old_values TEXT,
                new_values TEXT,
                changed_at TIMESTAMP,
                changed_by TEXT,
                change_reason TEXT,
                FOREIGN KEY (ci_id) REFERENCES configuration_items(ci_id)
            )
        """)
        
        # Snapshots table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cmdb_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                ci_count INTEGER,
                relationship_count INTEGER,
                data_hash TEXT,
                ci_data TEXT,
                relationship_data TEXT,
                created_at TIMESTAMP,
                created_by TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ci_type ON configuration_items(ci_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ci_status ON configuration_items(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ci_owner ON configuration_items(owner)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON ci_relationships(source_ci_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON ci_relationships(target_ci_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_change_status ON change_requests(status)")
        
        conn.commit()
        conn.close()
    
    async def create_ci(self, ci: ConfigurationItem, created_by: str = "system") -> ConfigurationItem:
        """Create a new Configuration Item"""
        ci.created_by = created_by
        ci.created_at = datetime.now()
        ci.updated_at = datetime.now()
        ci.version = 1
        
        self.configuration_items[ci.ci_id] = ci
        
        # Save to database
        await self._save_ci_to_db(ci)
        
        # Record history
        await self._record_ci_history(ci.ci_id, "create", {}, ci.to_dict(), created_by)
        
        self.logger.info(f"Created CI: {ci.name} ({ci.ci_id})")
        return ci
    
    async def _save_ci_to_db(self, ci: ConfigurationItem):
        """Save CI to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO configuration_items (
                ci_id, name, ci_type, status, description, owner, department,
                location, criticality, ip_address, hostname, fqdn, mac_address,
                os_type, os_version, software_version, manufacturer, model,
                serial_number, cloud_provider, cloud_region, instance_type,
                resource_id, compliance_frameworks, security_classification,
                vulnerability_count, risk_score, attributes, tags,
                created_at, updated_at, created_by, updated_by, version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ci.ci_id, ci.name, ci.ci_type.value, ci.status.value, ci.description,
            ci.owner, ci.department, ci.location, ci.criticality.value,
            ci.ip_address, ci.hostname, ci.fqdn, ci.mac_address,
            ci.os_type, ci.os_version, ci.software_version, ci.manufacturer,
            ci.model, ci.serial_number, ci.cloud_provider, ci.cloud_region,
            ci.instance_type, ci.resource_id,
            json.dumps(ci.compliance_frameworks), ci.security_classification,
            ci.vulnerability_count, ci.risk_score,
            json.dumps(ci.attributes), json.dumps(ci.tags),
            ci.created_at.isoformat(), ci.updated_at.isoformat(),
            ci.created_by, ci.updated_by, ci.version
        ))
        
        conn.commit()
        conn.close()
    
    async def update_ci(self, ci_id: str, updates: Dict[str, Any], updated_by: str = "system") -> Optional[ConfigurationItem]:
        """Update an existing Configuration Item"""
        if ci_id not in self.configuration_items:
            return None
        
        ci = self.configuration_items[ci_id]
        old_values = ci.to_dict()
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(ci, key):
                setattr(ci, key, value)
        
        ci.updated_at = datetime.now()
        ci.updated_by = updated_by
        ci.version += 1
        
        # Save to database
        await self._save_ci_to_db(ci)
        
        # Record history
        await self._record_ci_history(ci_id, "update", old_values, ci.to_dict(), updated_by)
        
        self.logger.info(f"Updated CI: {ci.name} (v{ci.version})")
        return ci
    
    async def delete_ci(self, ci_id: str, deleted_by: str = "system") -> bool:
        """Delete a Configuration Item (soft delete - mark as decommissioned)"""
        if ci_id not in self.configuration_items:
            return False
        
        ci = self.configuration_items[ci_id]
        old_values = ci.to_dict()
        
        ci.status = CIStatus.DECOMMISSIONED
        ci.updated_at = datetime.now()
        ci.updated_by = deleted_by
        ci.version += 1
        
        await self._save_ci_to_db(ci)
        await self._record_ci_history(ci_id, "delete", old_values, ci.to_dict(), deleted_by)
        
        return True
    
    async def _record_ci_history(self, ci_id: str, change_type: str, old_values: Dict, new_values: Dict, changed_by: str):
        """Record CI change history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Find changed fields
        changed_fields = []
        for key in new_values:
            if old_values.get(key) != new_values.get(key):
                changed_fields.append(key)
        
        cursor.execute("""
            INSERT INTO ci_history (
                ci_id, version, change_type, changed_fields,
                old_values, new_values, changed_at, changed_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ci_id, new_values.get("version", 1), change_type,
            json.dumps(changed_fields), json.dumps(old_values),
            json.dumps(new_values), datetime.now().isoformat(), changed_by
        ))
        
        conn.commit()
        conn.close()
    
    async def create_relationship(self, relationship: CIRelationship) -> CIRelationship:
        """Create a relationship between CIs"""
        self.relationships[relationship.relationship_id] = relationship
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO ci_relationships (
                relationship_id, source_ci_id, target_ci_id, relationship_type,
                description, is_bidirectional, strength, attributes, created_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            relationship.relationship_id, relationship.source_ci_id,
            relationship.target_ci_id, relationship.relationship_type.value,
            relationship.description, int(relationship.is_bidirectional),
            relationship.strength, json.dumps(relationship.attributes),
            relationship.created_at.isoformat(), relationship.created_by
        ))
        
        conn.commit()
        conn.close()
        
        return relationship
    
    async def get_ci_relationships(self, ci_id: str) -> List[CIRelationship]:
        """Get all relationships for a CI"""
        relationships = []
        
        for rel in self.relationships.values():
            if rel.source_ci_id == ci_id or rel.target_ci_id == ci_id:
                relationships.append(rel)
        
        return relationships
    
    async def get_dependency_tree(self, ci_id: str, depth: int = 5) -> Dict[str, Any]:
        """Get dependency tree for a CI"""
        visited = set()
        
        def build_tree(current_id: str, current_depth: int) -> Dict[str, Any]:
            if current_depth <= 0 or current_id in visited:
                return None
            
            visited.add(current_id)
            ci = self.configuration_items.get(current_id)
            
            if not ci:
                return None
            
            tree = {
                "ci_id": ci.ci_id,
                "name": ci.name,
                "type": ci.ci_type.value,
                "status": ci.status.value,
                "dependencies": [],
                "dependents": []
            }
            
            for rel in self.relationships.values():
                if rel.relationship_type == RelationshipType.DEPENDS_ON:
                    if rel.source_ci_id == current_id:
                        dep_tree = build_tree(rel.target_ci_id, current_depth - 1)
                        if dep_tree:
                            tree["dependencies"].append(dep_tree)
                    elif rel.target_ci_id == current_id:
                        dep_tree = build_tree(rel.source_ci_id, current_depth - 1)
                        if dep_tree:
                            tree["dependents"].append(dep_tree)
            
            return tree
        
        return build_tree(ci_id, depth)
    
    async def impact_analysis(self, ci_id: str) -> Dict[str, Any]:
        """Analyze impact of changes to a CI"""
        affected_cis = set()
        impact_chain = []
        
        def find_dependents(current_id: str, level: int = 0):
            for rel in self.relationships.values():
                if rel.target_ci_id == current_id and rel.relationship_type in [
                    RelationshipType.DEPENDS_ON, RelationshipType.USED_BY
                ]:
                    if rel.source_ci_id not in affected_cis:
                        affected_cis.add(rel.source_ci_id)
                        ci = self.configuration_items.get(rel.source_ci_id)
                        if ci:
                            impact_chain.append({
                                "ci_id": ci.ci_id,
                                "name": ci.name,
                                "type": ci.ci_type.value,
                                "criticality": ci.criticality.value,
                                "level": level
                            })
                            find_dependents(rel.source_ci_id, level + 1)
        
        find_dependents(ci_id)
        
        # Calculate impact score
        impact_score = 0.0
        for ci_id in affected_cis:
            ci = self.configuration_items.get(ci_id)
            if ci:
                criticality_weights = {
                    CriticalityLevel.CRITICAL: 1.0,
                    CriticalityLevel.HIGH: 0.8,
                    CriticalityLevel.MEDIUM: 0.5,
                    CriticalityLevel.LOW: 0.3,
                    CriticalityLevel.MINIMAL: 0.1
                }
                impact_score += criticality_weights.get(ci.criticality, 0.5)
        
        return {
            "source_ci": ci_id,
            "affected_count": len(affected_cis),
            "affected_cis": list(affected_cis),
            "impact_chain": impact_chain,
            "impact_score": min(impact_score, 10.0),
            "risk_level": "critical" if impact_score > 5 else "high" if impact_score > 3 else "medium" if impact_score > 1 else "low"
        }
    
    async def create_change_request(self, change: ChangeRequest) -> ChangeRequest:
        """Create a new change request"""
        change.created_at = datetime.now()
        change.updated_at = datetime.now()
        
        self.change_requests[change.change_id] = change
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO change_requests (
                change_id, title, description, change_type, status, priority,
                affected_cis, requested_by, assigned_to, approvers, approved_by,
                planned_start, planned_end, risk_level, impact_analysis,
                rollback_plan, test_plan, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            change.change_id, change.title, change.description,
            change.change_type.value, change.status.value, change.priority.value,
            json.dumps(change.affected_cis), change.requested_by,
            change.assigned_to, json.dumps(change.approvers),
            json.dumps(change.approved_by),
            change.planned_start.isoformat() if change.planned_start else None,
            change.planned_end.isoformat() if change.planned_end else None,
            change.risk_level, change.impact_analysis, change.rollback_plan,
            change.test_plan, change.created_at.isoformat(),
            change.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return change
    
    async def approve_change(self, change_id: str, approver: str) -> bool:
        """Approve a change request"""
        if change_id not in self.change_requests:
            return False
        
        change = self.change_requests[change_id]
        
        if approver not in change.approved_by:
            change.approved_by.append(approver)
        
        # Check if all approvers have approved
        if all(a in change.approved_by for a in change.approvers):
            change.status = ChangeStatus.APPROVED
        
        change.updated_at = datetime.now()
        
        return True
    
    async def create_snapshot(self, name: str, description: str = "", created_by: str = "system") -> CMDBSnapshot:
        """Create a point-in-time snapshot of the CMDB"""
        snapshot_id = hashlib.sha256(f"{name}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        
        # Collect CI data
        ci_data = {ci_id: ci.to_dict() for ci_id, ci in self.configuration_items.items()}
        rel_data = {rel_id: rel.to_dict() for rel_id, rel in self.relationships.items()}
        
        # Calculate hash
        data_str = json.dumps({"cis": ci_data, "relationships": rel_data}, sort_keys=True)
        data_hash = hashlib.sha256(data_str.encode()).hexdigest()
        
        snapshot = CMDBSnapshot(
            snapshot_id=snapshot_id,
            name=name,
            description=description,
            ci_count=len(ci_data),
            relationship_count=len(rel_data),
            data_hash=data_hash,
            ci_data=ci_data,
            relationship_data=rel_data,
            created_by=created_by
        )
        
        self.snapshots[snapshot_id] = snapshot
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO cmdb_snapshots (
                snapshot_id, name, description, ci_count, relationship_count,
                data_hash, ci_data, relationship_data, created_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot.snapshot_id, snapshot.name, snapshot.description,
            snapshot.ci_count, snapshot.relationship_count, snapshot.data_hash,
            json.dumps(snapshot.ci_data), json.dumps(snapshot.relationship_data),
            snapshot.created_at.isoformat(), snapshot.created_by
        ))
        
        conn.commit()
        conn.close()
        
        return snapshot
    
    async def compare_snapshots(self, snapshot1_id: str, snapshot2_id: str) -> Dict[str, Any]:
        """Compare two CMDB snapshots"""
        if snapshot1_id not in self.snapshots or snapshot2_id not in self.snapshots:
            return {"error": "Snapshot not found"}
        
        snap1 = self.snapshots[snapshot1_id]
        snap2 = self.snapshots[snapshot2_id]
        
        added_cis = set(snap2.ci_data.keys()) - set(snap1.ci_data.keys())
        removed_cis = set(snap1.ci_data.keys()) - set(snap2.ci_data.keys())
        common_cis = set(snap1.ci_data.keys()) & set(snap2.ci_data.keys())
        
        modified_cis = []
        for ci_id in common_cis:
            if snap1.ci_data[ci_id] != snap2.ci_data[ci_id]:
                modified_cis.append({
                    "ci_id": ci_id,
                    "old": snap1.ci_data[ci_id],
                    "new": snap2.ci_data[ci_id]
                })
        
        return {
            "snapshot1": snapshot1_id,
            "snapshot2": snapshot2_id,
            "added_cis": list(added_cis),
            "removed_cis": list(removed_cis),
            "modified_cis": modified_cis,
            "total_changes": len(added_cis) + len(removed_cis) + len(modified_cis)
        }
    
    async def search_cis(self, query: str = "", ci_type: Optional[CIType] = None,
                         status: Optional[CIStatus] = None, owner: str = "",
                         department: str = "", tags: List[str] = None) -> List[ConfigurationItem]:
        """Search Configuration Items"""
        results = []
        
        for ci in self.configuration_items.values():
            if ci_type and ci.ci_type != ci_type:
                continue
            if status and ci.status != status:
                continue
            if owner and owner.lower() not in ci.owner.lower():
                continue
            if department and department.lower() not in ci.department.lower():
                continue
            if tags and not any(tag in ci.tags for tag in tags):
                continue
            if query:
                query_lower = query.lower()
                if not any([
                    query_lower in ci.name.lower(),
                    query_lower in ci.description.lower(),
                    query_lower in ci.hostname.lower(),
                    query_lower in ci.ip_address
                ]):
                    continue
            
            results.append(ci)
        
        return results
    
    async def generate_report(self, report_type: str = "summary") -> CMDBReport:
        """Generate CMDB report"""
        report_id = hashlib.sha256(f"{report_type}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        
        report = CMDBReport(
            report_id=report_id,
            report_type=report_type,
            title=f"CMDB {report_type.title()} Report",
            total_cis=len(self.configuration_items),
            total_relationships=len(self.relationships)
        )
        
        # Calculate statistics
        for ci in self.configuration_items.values():
            ci_type = ci.ci_type.value
            report.cis_by_type[ci_type] = report.cis_by_type.get(ci_type, 0) + 1
            
            status = ci.status.value
            report.cis_by_status[status] = report.cis_by_status.get(status, 0) + 1
            
            criticality = ci.criticality.value
            report.cis_by_criticality[criticality] = report.cis_by_criticality.get(criticality, 0) + 1
        
        # Find stale CIs (not updated in 30 days)
        stale_threshold = datetime.now() - timedelta(days=30)
        for ci in self.configuration_items.values():
            if ci.updated_at < stale_threshold:
                report.stale_cis_count += 1
        
        # Find orphaned CIs (no relationships)
        cis_with_relationships = set()
        for rel in self.relationships.values():
            cis_with_relationships.add(rel.source_ci_id)
            cis_with_relationships.add(rel.target_ci_id)
        
        for ci_id in self.configuration_items.keys():
            if ci_id not in cis_with_relationships:
                report.orphaned_cis_count += 1
        
        # Calculate data quality score
        total_fields = 0
        filled_fields = 0
        required_fields = ["name", "owner", "department", "description"]
        
        for ci in self.configuration_items.values():
            for field in required_fields:
                total_fields += 1
                if getattr(ci, field, ""):
                    filled_fields += 1
        
        report.data_quality_score = (filled_fields / total_fields * 100) if total_fields > 0 else 0
        
        # Calculate compliance score
        compliant_cis = sum(1 for ci in self.configuration_items.values() if ci.compliance_frameworks)
        report.compliance_score = (compliant_cis / len(self.configuration_items) * 100) if self.configuration_items else 0
        
        # Add findings
        if report.stale_cis_count > 0:
            report.findings.append({
                "type": "warning",
                "message": f"{report.stale_cis_count} CIs have not been updated in 30+ days"
            })
        
        if report.orphaned_cis_count > 0:
            report.findings.append({
                "type": "info",
                "message": f"{report.orphaned_cis_count} CIs have no relationships defined"
            })
        
        if report.data_quality_score < 80:
            report.recommendations.append("Improve data quality by filling in required fields")
        
        if report.compliance_score < 50:
            report.recommendations.append("Assign compliance frameworks to more CIs")
        
        return report
    
    async def auto_discover_cis(self, targets: List[str]) -> List[ConfigurationItem]:
        """Auto-discover CIs from network scan results"""
        discovered = []
        
        for target in targets:
            ci_id = hashlib.sha256(target.encode()).hexdigest()[:16]
            
            if ci_id not in self.configuration_items:
                ci = ConfigurationItem(
                    ci_id=ci_id,
                    name=f"Discovered-{target}",
                    ci_type=CIType.SERVER,
                    status=CIStatus.ACTIVE,
                    ip_address=target,
                    description="Auto-discovered from network scan"
                )
                
                await self.create_ci(ci, created_by="auto_discovery")
                discovered.append(ci)
        
        return discovered
    
    async def export_cmdb(self, format: str = "json") -> str:
        """Export CMDB data"""
        data = {
            "export_date": datetime.now().isoformat(),
            "configuration_items": [ci.to_dict() for ci in self.configuration_items.values()],
            "relationships": [rel.to_dict() for rel in self.relationships.values()],
            "change_requests": [cr.to_dict() for cr in self.change_requests.values()]
        }
        
        if format == "json":
            return json.dumps(data, indent=2)
        else:
            return json.dumps(data)
    
    async def import_cmdb(self, data: str, merge: bool = True) -> Dict[str, int]:
        """Import CMDB data"""
        try:
            imported = json.loads(data)
            stats = {"cis_imported": 0, "relationships_imported": 0, "changes_imported": 0}
            
            # Import CIs
            for ci_data in imported.get("configuration_items", []):
                ci = ConfigurationItem(
                    ci_id=ci_data["ci_id"],
                    name=ci_data["name"],
                    ci_type=CIType(ci_data["ci_type"]),
                    status=CIStatus(ci_data["status"]),
                    description=ci_data.get("description", ""),
                    owner=ci_data.get("owner", ""),
                    ip_address=ci_data.get("ip_address", "")
                )
                
                if merge or ci.ci_id not in self.configuration_items:
                    await self.create_ci(ci, created_by="import")
                    stats["cis_imported"] += 1
            
            return stats
        except Exception as e:
            self.logger.error(f"Import failed: {e}")
            return {"error": str(e)}


# Create singleton instance
cmdb_engine = CMDBEngine()
