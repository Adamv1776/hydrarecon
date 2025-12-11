#!/usr/bin/env python3
"""
Access Control Matrix Engine
Comprehensive role-based access control, permission management, and entitlement review.
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
import logging
from pathlib import Path


class PermissionType(Enum):
    """Types of permissions"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"
    CREATE = "create"
    MODIFY = "modify"
    APPROVE = "approve"
    AUDIT = "audit"
    EXPORT = "export"


class AccessDecision(Enum):
    """Access decision outcomes"""
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"
    PENDING = "pending"
    EXPIRED = "expired"


class RoleType(Enum):
    """Types of roles"""
    SYSTEM = "system"
    APPLICATION = "application"
    BUSINESS = "business"
    ADMINISTRATIVE = "administrative"
    TECHNICAL = "technical"
    PRIVILEGED = "privileged"
    SERVICE = "service"


class ReviewStatus(Enum):
    """Access review status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REVOKED = "revoked"
    EXPIRED = "expired"
    ESCALATED = "escalated"


class SoDViolationType(Enum):
    """Separation of Duties violation types"""
    TOXIC_COMBINATION = "toxic_combination"
    EXCESSIVE_ACCESS = "excessive_access"
    CROSS_DOMAIN = "cross_domain"
    PRIVILEGED_CONFLICT = "privileged_conflict"
    APPROVAL_CHAIN = "approval_chain"


@dataclass
class Permission:
    """Individual permission definition"""
    id: str
    name: str
    description: str
    type: PermissionType
    resource: str
    action: str
    scope: str = "global"
    conditions: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"
    requires_mfa: bool = False
    time_bound: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Role:
    """Role definition with permissions"""
    id: str
    name: str
    description: str
    type: RoleType
    permissions: List[str] = field(default_factory=list)
    parent_roles: List[str] = field(default_factory=list)
    excluded_roles: List[str] = field(default_factory=list)
    max_users: int = 0  # 0 = unlimited
    require_approval: bool = False
    approvers: List[str] = field(default_factory=list)
    auto_revoke_days: int = 0  # 0 = never
    risk_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class User:
    """User with role assignments"""
    id: str
    username: str
    email: str
    department: str
    manager: str = ""
    roles: List[str] = field(default_factory=list)
    direct_permissions: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    status: str = "active"
    last_access: Optional[datetime] = None
    risk_score: float = 0.0
    mfa_enabled: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoleAssignment:
    """Role assignment to user"""
    id: str
    user_id: str
    role_id: str
    granted_by: str
    granted_at: datetime
    expires_at: Optional[datetime] = None
    justification: str = ""
    status: str = "active"
    review_status: ReviewStatus = ReviewStatus.PENDING
    last_review: Optional[datetime] = None
    next_review: Optional[datetime] = None
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessRequest:
    """Access request for approval workflow"""
    id: str
    user_id: str
    requested_roles: List[str]
    requested_permissions: List[str]
    justification: str
    requested_at: datetime
    requested_by: str
    status: str = "pending"
    approvers: List[str] = field(default_factory=list)
    approved_by: List[str] = field(default_factory=list)
    denied_by: Optional[str] = None
    denial_reason: str = ""
    expires_at: Optional[datetime] = None
    risk_assessment: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SoDRule:
    """Separation of Duties rule"""
    id: str
    name: str
    description: str
    type: SoDViolationType
    conflicting_roles: List[Tuple[str, str]] = field(default_factory=list)
    conflicting_permissions: List[Tuple[str, str]] = field(default_factory=list)
    severity: str = "high"
    remediation: str = ""
    exceptions: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class SoDViolation:
    """Detected SoD violation"""
    id: str
    rule_id: str
    user_id: str
    violation_type: SoDViolationType
    conflicting_items: List[str]
    detected_at: datetime
    severity: str
    status: str = "open"
    exception_granted: bool = False
    exception_reason: str = ""
    remediation_action: str = ""


@dataclass
class AccessReview:
    """Periodic access review campaign"""
    id: str
    name: str
    description: str
    scope: Dict[str, Any]  # roles, departments, etc.
    reviewer_id: str
    start_date: datetime
    end_date: datetime
    status: str = "pending"
    total_items: int = 0
    reviewed_items: int = 0
    approved_items: int = 0
    revoked_items: int = 0
    escalated_items: int = 0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class AccessMatrix:
    """Complete access control matrix"""
    id: str
    name: str
    permissions: Dict[str, Permission] = field(default_factory=dict)
    roles: Dict[str, Role] = field(default_factory=dict)
    users: Dict[str, User] = field(default_factory=dict)
    assignments: Dict[str, RoleAssignment] = field(default_factory=dict)
    sod_rules: Dict[str, SoDRule] = field(default_factory=dict)
    resources: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)


class AccessControlEngine:
    """
    Enterprise Access Control Matrix Engine
    Provides comprehensive RBAC, ABAC, and entitlement management.
    """
    
    def __init__(self, db_path: str = "access_control.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.matrices: Dict[str, AccessMatrix] = {}
        self.pending_requests: Dict[str, AccessRequest] = {}
        self.violations: Dict[str, SoDViolation] = {}
        self.reviews: Dict[str, AccessReview] = {}
        self._permission_cache: Dict[str, Set[str]] = {}
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for persistence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS permissions (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                name TEXT,
                description TEXT,
                type TEXT,
                resource TEXT,
                action TEXT,
                scope TEXT,
                risk_level TEXT,
                requires_mfa INTEGER,
                conditions TEXT,
                metadata TEXT,
                created_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                name TEXT,
                description TEXT,
                type TEXT,
                permissions TEXT,
                parent_roles TEXT,
                excluded_roles TEXT,
                max_users INTEGER,
                require_approval INTEGER,
                approvers TEXT,
                auto_revoke_days INTEGER,
                risk_score REAL,
                metadata TEXT,
                created_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                username TEXT,
                email TEXT,
                department TEXT,
                manager TEXT,
                roles TEXT,
                direct_permissions TEXT,
                groups TEXT,
                status TEXT,
                last_access TIMESTAMP,
                risk_score REAL,
                mfa_enabled INTEGER,
                metadata TEXT,
                created_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS role_assignments (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                user_id TEXT,
                role_id TEXT,
                granted_by TEXT,
                granted_at TIMESTAMP,
                expires_at TIMESTAMP,
                justification TEXT,
                status TEXT,
                review_status TEXT,
                last_review TIMESTAMP,
                next_review TIMESTAMP,
                conditions TEXT
            );
            
            CREATE TABLE IF NOT EXISTS access_requests (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                user_id TEXT,
                requested_roles TEXT,
                requested_permissions TEXT,
                justification TEXT,
                requested_at TIMESTAMP,
                requested_by TEXT,
                status TEXT,
                approvers TEXT,
                approved_by TEXT,
                denied_by TEXT,
                denial_reason TEXT,
                expires_at TIMESTAMP,
                risk_assessment TEXT
            );
            
            CREATE TABLE IF NOT EXISTS sod_rules (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                name TEXT,
                description TEXT,
                type TEXT,
                conflicting_roles TEXT,
                conflicting_permissions TEXT,
                severity TEXT,
                remediation TEXT,
                exceptions TEXT,
                enabled INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS sod_violations (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                rule_id TEXT,
                user_id TEXT,
                violation_type TEXT,
                conflicting_items TEXT,
                detected_at TIMESTAMP,
                severity TEXT,
                status TEXT,
                exception_granted INTEGER,
                exception_reason TEXT,
                remediation_action TEXT
            );
            
            CREATE TABLE IF NOT EXISTS access_reviews (
                id TEXT PRIMARY KEY,
                matrix_id TEXT,
                name TEXT,
                description TEXT,
                scope TEXT,
                reviewer_id TEXT,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                status TEXT,
                total_items INTEGER,
                reviewed_items INTEGER,
                approved_items INTEGER,
                revoked_items INTEGER,
                escalated_items INTEGER,
                created_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                matrix_id TEXT,
                action TEXT,
                entity_type TEXT,
                entity_id TEXT,
                user_id TEXT,
                details TEXT,
                timestamp TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_assignments_user ON role_assignments(user_id);
            CREATE INDEX IF NOT EXISTS idx_assignments_role ON role_assignments(role_id);
            CREATE INDEX IF NOT EXISTS idx_violations_user ON sod_violations(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_trail(entity_type, entity_id);
        """)
        
        conn.commit()
        conn.close()
    
    async def create_matrix(self, name: str) -> AccessMatrix:
        """Create new access control matrix"""
        matrix_id = hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        matrix = AccessMatrix(
            id=matrix_id,
            name=name
        )
        
        self.matrices[matrix_id] = matrix
        self._log_audit(matrix_id, "create_matrix", "matrix", matrix_id, "system", {"name": name})
        
        return matrix
    
    async def create_permission(
        self,
        matrix_id: str,
        name: str,
        description: str,
        perm_type: PermissionType,
        resource: str,
        action: str,
        **kwargs
    ) -> Permission:
        """Create new permission"""
        perm_id = hashlib.md5(f"{matrix_id}_{name}_{resource}".encode()).hexdigest()[:12]
        
        permission = Permission(
            id=perm_id,
            name=name,
            description=description,
            type=perm_type,
            resource=resource,
            action=action,
            scope=kwargs.get("scope", "global"),
            conditions=kwargs.get("conditions", {}),
            risk_level=kwargs.get("risk_level", "low"),
            requires_mfa=kwargs.get("requires_mfa", False),
            time_bound=kwargs.get("time_bound", False),
            metadata=kwargs.get("metadata", {})
        )
        
        if matrix_id in self.matrices:
            self.matrices[matrix_id].permissions[perm_id] = permission
            self._invalidate_cache(matrix_id)
        
        self._log_audit(matrix_id, "create_permission", "permission", perm_id, "system", 
                       {"name": name, "resource": resource, "action": action})
        
        return permission
    
    async def create_role(
        self,
        matrix_id: str,
        name: str,
        description: str,
        role_type: RoleType,
        permissions: List[str] = None,
        **kwargs
    ) -> Role:
        """Create new role"""
        role_id = hashlib.md5(f"{matrix_id}_{name}".encode()).hexdigest()[:12]
        
        role = Role(
            id=role_id,
            name=name,
            description=description,
            type=role_type,
            permissions=permissions or [],
            parent_roles=kwargs.get("parent_roles", []),
            excluded_roles=kwargs.get("excluded_roles", []),
            max_users=kwargs.get("max_users", 0),
            require_approval=kwargs.get("require_approval", False),
            approvers=kwargs.get("approvers", []),
            auto_revoke_days=kwargs.get("auto_revoke_days", 0),
            risk_score=kwargs.get("risk_score", 0.0),
            metadata=kwargs.get("metadata", {})
        )
        
        if matrix_id in self.matrices:
            self.matrices[matrix_id].roles[role_id] = role
            self._invalidate_cache(matrix_id)
        
        self._log_audit(matrix_id, "create_role", "role", role_id, "system",
                       {"name": name, "type": role_type.value})
        
        return role
    
    async def create_user(
        self,
        matrix_id: str,
        username: str,
        email: str,
        department: str,
        **kwargs
    ) -> User:
        """Create new user"""
        user_id = hashlib.md5(f"{matrix_id}_{username}".encode()).hexdigest()[:12]
        
        user = User(
            id=user_id,
            username=username,
            email=email,
            department=department,
            manager=kwargs.get("manager", ""),
            roles=kwargs.get("roles", []),
            direct_permissions=kwargs.get("direct_permissions", []),
            groups=kwargs.get("groups", []),
            status=kwargs.get("status", "active"),
            mfa_enabled=kwargs.get("mfa_enabled", False),
            metadata=kwargs.get("metadata", {})
        )
        
        if matrix_id in self.matrices:
            self.matrices[matrix_id].users[user_id] = user
        
        self._log_audit(matrix_id, "create_user", "user", user_id, "system",
                       {"username": username, "department": department})
        
        return user
    
    async def assign_role(
        self,
        matrix_id: str,
        user_id: str,
        role_id: str,
        granted_by: str,
        justification: str = "",
        expires_at: Optional[datetime] = None
    ) -> Tuple[bool, str, Optional[RoleAssignment]]:
        """Assign role to user with validation"""
        matrix = self.matrices.get(matrix_id)
        if not matrix:
            return False, "Matrix not found", None
        
        user = matrix.users.get(user_id)
        role = matrix.roles.get(role_id)
        
        if not user:
            return False, "User not found", None
        if not role:
            return False, "Role not found", None
        
        # Check for SoD violations
        violations = await self.check_sod_violations(matrix_id, user_id, [role_id])
        if violations:
            violation_details = ", ".join([v.violation_type.value for v in violations])
            return False, f"SoD violations detected: {violation_details}", None
        
        # Check role exclusions
        for assigned_role_id in user.roles:
            assigned_role = matrix.roles.get(assigned_role_id)
            if assigned_role:
                if role_id in assigned_role.excluded_roles or assigned_role_id in role.excluded_roles:
                    return False, f"Role {role.name} conflicts with existing role", None
        
        # Check max users limit
        if role.max_users > 0:
            current_count = sum(1 for u in matrix.users.values() if role_id in u.roles)
            if current_count >= role.max_users:
                return False, f"Role {role.name} has reached maximum user limit", None
        
        # Create assignment
        assignment_id = hashlib.md5(
            f"{user_id}_{role_id}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        # Determine review date
        next_review = None
        if role.auto_revoke_days > 0:
            next_review = datetime.now() + timedelta(days=role.auto_revoke_days // 2)
        
        assignment = RoleAssignment(
            id=assignment_id,
            user_id=user_id,
            role_id=role_id,
            granted_by=granted_by,
            granted_at=datetime.now(),
            expires_at=expires_at,
            justification=justification,
            status="active" if not role.require_approval else "pending_approval",
            review_status=ReviewStatus.PENDING if role.require_approval else ReviewStatus.APPROVED,
            next_review=next_review
        )
        
        matrix.assignments[assignment_id] = assignment
        
        if not role.require_approval:
            user.roles.append(role_id)
        
        self._invalidate_cache(matrix_id)
        self._log_audit(matrix_id, "assign_role", "assignment", assignment_id, granted_by,
                       {"user_id": user_id, "role_id": role_id})
        
        return True, "Role assigned successfully", assignment
    
    async def revoke_role(
        self,
        matrix_id: str,
        user_id: str,
        role_id: str,
        revoked_by: str,
        reason: str = ""
    ) -> Tuple[bool, str]:
        """Revoke role from user"""
        matrix = self.matrices.get(matrix_id)
        if not matrix:
            return False, "Matrix not found"
        
        user = matrix.users.get(user_id)
        if not user:
            return False, "User not found"
        
        if role_id not in user.roles:
            return False, "User does not have this role"
        
        user.roles.remove(role_id)
        
        # Update assignments
        for assignment in matrix.assignments.values():
            if assignment.user_id == user_id and assignment.role_id == role_id:
                assignment.status = "revoked"
                assignment.review_status = ReviewStatus.REVOKED
        
        self._invalidate_cache(matrix_id)
        self._log_audit(matrix_id, "revoke_role", "role", role_id, revoked_by,
                       {"user_id": user_id, "reason": reason})
        
        return True, "Role revoked successfully"
    
    async def check_access(
        self,
        matrix_id: str,
        user_id: str,
        resource: str,
        action: str,
        context: Dict[str, Any] = None
    ) -> Tuple[AccessDecision, str]:
        """Check if user has access to resource/action"""
        matrix = self.matrices.get(matrix_id)
        if not matrix:
            return AccessDecision.DENY, "Matrix not found"
        
        user = matrix.users.get(user_id)
        if not user:
            return AccessDecision.DENY, "User not found"
        
        if user.status != "active":
            return AccessDecision.DENY, f"User status: {user.status}"
        
        # Get effective permissions
        effective_perms = await self.get_effective_permissions(matrix_id, user_id)
        
        # Check permissions
        for perm_id in effective_perms:
            perm = matrix.permissions.get(perm_id)
            if perm:
                if (perm.resource == resource or perm.resource == "*") and \
                   (perm.action == action or perm.action == "*"):
                    
                    # Check conditions
                    if perm.conditions:
                        if not self._evaluate_conditions(perm.conditions, context or {}):
                            continue
                    
                    # Check MFA requirement
                    if perm.requires_mfa and not user.mfa_enabled:
                        return AccessDecision.CONDITIONAL, "MFA required"
                    
                    return AccessDecision.ALLOW, f"Access granted via {perm.name}"
        
        return AccessDecision.DENY, "No matching permission found"
    
    async def get_effective_permissions(
        self,
        matrix_id: str,
        user_id: str
    ) -> Set[str]:
        """Get all effective permissions for user including inherited"""
        cache_key = f"{matrix_id}_{user_id}"
        
        if cache_key in self._permission_cache:
            return self._permission_cache[cache_key]
        
        matrix = self.matrices.get(matrix_id)
        if not matrix:
            return set()
        
        user = matrix.users.get(user_id)
        if not user:
            return set()
        
        permissions = set(user.direct_permissions)
        
        # Collect permissions from all roles
        processed_roles = set()
        roles_to_process = list(user.roles)
        
        while roles_to_process:
            role_id = roles_to_process.pop()
            if role_id in processed_roles:
                continue
            
            processed_roles.add(role_id)
            role = matrix.roles.get(role_id)
            
            if role:
                permissions.update(role.permissions)
                roles_to_process.extend(role.parent_roles)
        
        self._permission_cache[cache_key] = permissions
        return permissions
    
    async def create_sod_rule(
        self,
        matrix_id: str,
        name: str,
        description: str,
        violation_type: SoDViolationType,
        conflicting_roles: List[Tuple[str, str]] = None,
        conflicting_permissions: List[Tuple[str, str]] = None,
        **kwargs
    ) -> SoDRule:
        """Create Separation of Duties rule"""
        rule_id = hashlib.md5(f"{matrix_id}_{name}".encode()).hexdigest()[:12]
        
        rule = SoDRule(
            id=rule_id,
            name=name,
            description=description,
            type=violation_type,
            conflicting_roles=conflicting_roles or [],
            conflicting_permissions=conflicting_permissions or [],
            severity=kwargs.get("severity", "high"),
            remediation=kwargs.get("remediation", ""),
            exceptions=kwargs.get("exceptions", []),
            enabled=kwargs.get("enabled", True)
        )
        
        if matrix_id in self.matrices:
            self.matrices[matrix_id].sod_rules[rule_id] = rule
        
        self._log_audit(matrix_id, "create_sod_rule", "sod_rule", rule_id, "system",
                       {"name": name, "type": violation_type.value})
        
        return rule
    
    async def check_sod_violations(
        self,
        matrix_id: str,
        user_id: str,
        proposed_roles: List[str] = None
    ) -> List[SoDViolation]:
        """Check for SoD violations for user"""
        matrix = self.matrices.get(matrix_id)
        if not matrix:
            return []
        
        user = matrix.users.get(user_id)
        if not user:
            return []
        
        violations = []
        all_roles = set(user.roles)
        if proposed_roles:
            all_roles.update(proposed_roles)
        
        # Get all permissions
        all_permissions = set(user.direct_permissions)
        for role_id in all_roles:
            role = matrix.roles.get(role_id)
            if role:
                all_permissions.update(role.permissions)
        
        for rule in matrix.sod_rules.values():
            if not rule.enabled:
                continue
            
            # Check role conflicts
            for role1, role2 in rule.conflicting_roles:
                if role1 in all_roles and role2 in all_roles:
                    if user_id not in rule.exceptions:
                        violation = SoDViolation(
                            id=hashlib.md5(
                                f"{user_id}_{rule.id}_{datetime.now().isoformat()}".encode()
                            ).hexdigest()[:12],
                            rule_id=rule.id,
                            user_id=user_id,
                            violation_type=rule.type,
                            conflicting_items=[role1, role2],
                            detected_at=datetime.now(),
                            severity=rule.severity
                        )
                        violations.append(violation)
            
            # Check permission conflicts
            for perm1, perm2 in rule.conflicting_permissions:
                if perm1 in all_permissions and perm2 in all_permissions:
                    if user_id not in rule.exceptions:
                        violation = SoDViolation(
                            id=hashlib.md5(
                                f"{user_id}_{rule.id}_{datetime.now().isoformat()}".encode()
                            ).hexdigest()[:12],
                            rule_id=rule.id,
                            user_id=user_id,
                            violation_type=rule.type,
                            conflicting_items=[perm1, perm2],
                            detected_at=datetime.now(),
                            severity=rule.severity
                        )
                        violations.append(violation)
        
        return violations
    
    async def create_access_review(
        self,
        matrix_id: str,
        name: str,
        description: str,
        scope: Dict[str, Any],
        reviewer_id: str,
        duration_days: int = 30
    ) -> AccessReview:
        """Create access review campaign"""
        review_id = hashlib.md5(f"{matrix_id}_{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        matrix = self.matrices.get(matrix_id)
        total_items = 0
        
        if matrix:
            # Count items to review
            if "roles" in scope:
                for role_id in scope["roles"]:
                    total_items += sum(
                        1 for u in matrix.users.values() if role_id in u.roles
                    )
            elif "departments" in scope:
                total_items = sum(
                    len(u.roles) for u in matrix.users.values()
                    if u.department in scope["departments"]
                )
            else:
                total_items = sum(len(u.roles) for u in matrix.users.values())
        
        review = AccessReview(
            id=review_id,
            name=name,
            description=description,
            scope=scope,
            reviewer_id=reviewer_id,
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(days=duration_days),
            total_items=total_items
        )
        
        self.reviews[review_id] = review
        self._log_audit(matrix_id, "create_access_review", "review", review_id, "system",
                       {"name": name, "total_items": total_items})
        
        return review
    
    async def submit_access_request(
        self,
        matrix_id: str,
        user_id: str,
        requested_roles: List[str],
        requested_permissions: List[str],
        justification: str,
        requested_by: str
    ) -> AccessRequest:
        """Submit access request for approval"""
        request_id = hashlib.md5(
            f"{user_id}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        matrix = self.matrices.get(matrix_id)
        approvers = []
        risk_assessment = {"risk_score": 0.0, "factors": []}
        
        if matrix:
            # Determine approvers based on roles
            for role_id in requested_roles:
                role = matrix.roles.get(role_id)
                if role:
                    approvers.extend(role.approvers)
                    risk_assessment["risk_score"] = max(
                        risk_assessment["risk_score"],
                        role.risk_score
                    )
            
            # Get user's manager as approver
            user = matrix.users.get(user_id)
            if user and user.manager:
                approvers.append(user.manager)
        
        request = AccessRequest(
            id=request_id,
            user_id=user_id,
            requested_roles=requested_roles,
            requested_permissions=requested_permissions,
            justification=justification,
            requested_at=datetime.now(),
            requested_by=requested_by,
            approvers=list(set(approvers)),
            risk_assessment=risk_assessment
        )
        
        self.pending_requests[request_id] = request
        self._log_audit(matrix_id, "submit_access_request", "request", request_id, requested_by,
                       {"user_id": user_id, "roles": requested_roles})
        
        return request
    
    async def approve_access_request(
        self,
        matrix_id: str,
        request_id: str,
        approver_id: str
    ) -> Tuple[bool, str]:
        """Approve access request"""
        request = self.pending_requests.get(request_id)
        if not request:
            return False, "Request not found"
        
        if approver_id not in request.approvers:
            return False, "Not authorized to approve this request"
        
        request.approved_by.append(approver_id)
        
        # Check if all approvers have approved
        if set(request.approvers).issubset(set(request.approved_by)):
            request.status = "approved"
            
            # Grant roles
            for role_id in request.requested_roles:
                await self.assign_role(
                    matrix_id,
                    request.user_id,
                    role_id,
                    approver_id,
                    request.justification
                )
            
            # Grant direct permissions
            matrix = self.matrices.get(matrix_id)
            if matrix:
                user = matrix.users.get(request.user_id)
                if user:
                    user.direct_permissions.extend(request.requested_permissions)
        
        self._log_audit(matrix_id, "approve_request", "request", request_id, approver_id, {})
        
        return True, "Request approved"
    
    async def deny_access_request(
        self,
        matrix_id: str,
        request_id: str,
        denied_by: str,
        reason: str
    ) -> Tuple[bool, str]:
        """Deny access request"""
        request = self.pending_requests.get(request_id)
        if not request:
            return False, "Request not found"
        
        request.status = "denied"
        request.denied_by = denied_by
        request.denial_reason = reason
        
        self._log_audit(matrix_id, "deny_request", "request", request_id, denied_by,
                       {"reason": reason})
        
        return True, "Request denied"
    
    async def generate_access_report(
        self,
        matrix_id: str,
        report_type: str = "full"
    ) -> Dict[str, Any]:
        """Generate access control report"""
        matrix = self.matrices.get(matrix_id)
        if not matrix:
            return {"error": "Matrix not found"}
        
        report = {
            "matrix_id": matrix_id,
            "matrix_name": matrix.name,
            "generated_at": datetime.now().isoformat(),
            "report_type": report_type,
            "summary": {
                "total_users": len(matrix.users),
                "total_roles": len(matrix.roles),
                "total_permissions": len(matrix.permissions),
                "total_assignments": len(matrix.assignments),
                "active_users": sum(1 for u in matrix.users.values() if u.status == "active"),
                "privileged_users": 0,
                "pending_reviews": 0,
                "sod_violations": len(self.violations)
            },
            "risk_analysis": {
                "high_risk_users": [],
                "unused_permissions": [],
                "expired_assignments": [],
                "orphan_roles": []
            },
            "compliance": {
                "last_review_date": None,
                "review_coverage": 0.0,
                "sod_rules_count": len(matrix.sod_rules),
                "active_violations": 0
            }
        }
        
        # Analyze users
        for user in matrix.users.values():
            if user.risk_score >= 7.0:
                report["risk_analysis"]["high_risk_users"].append({
                    "user_id": user.id,
                    "username": user.username,
                    "risk_score": user.risk_score
                })
            
            # Check for privileged roles
            for role_id in user.roles:
                role = matrix.roles.get(role_id)
                if role and role.type == RoleType.PRIVILEGED:
                    report["summary"]["privileged_users"] += 1
                    break
        
        # Check for expired assignments
        for assignment in matrix.assignments.values():
            if assignment.expires_at and assignment.expires_at < datetime.now():
                report["risk_analysis"]["expired_assignments"].append({
                    "assignment_id": assignment.id,
                    "user_id": assignment.user_id,
                    "role_id": assignment.role_id,
                    "expired_at": assignment.expires_at.isoformat()
                })
        
        # Check for orphan roles (roles with no users)
        for role in matrix.roles.values():
            has_users = any(role.id in u.roles for u in matrix.users.values())
            if not has_users:
                report["risk_analysis"]["orphan_roles"].append({
                    "role_id": role.id,
                    "role_name": role.name
                })
        
        return report
    
    async def export_matrix(
        self,
        matrix_id: str,
        format: str = "json"
    ) -> str:
        """Export access control matrix"""
        matrix = self.matrices.get(matrix_id)
        if not matrix:
            return ""
        
        if format == "json":
            export_data = {
                "id": matrix.id,
                "name": matrix.name,
                "created_at": matrix.created_at.isoformat(),
                "last_updated": matrix.last_updated.isoformat(),
                "permissions": [
                    {
                        "id": p.id,
                        "name": p.name,
                        "description": p.description,
                        "type": p.type.value,
                        "resource": p.resource,
                        "action": p.action,
                        "risk_level": p.risk_level
                    }
                    for p in matrix.permissions.values()
                ],
                "roles": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "description": r.description,
                        "type": r.type.value,
                        "permissions": r.permissions,
                        "risk_score": r.risk_score
                    }
                    for r in matrix.roles.values()
                ],
                "users": [
                    {
                        "id": u.id,
                        "username": u.username,
                        "email": u.email,
                        "department": u.department,
                        "roles": u.roles,
                        "status": u.status
                    }
                    for u in matrix.users.values()
                ]
            }
            return json.dumps(export_data, indent=2)
        
        return ""
    
    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate permission conditions against context"""
        for key, expected in conditions.items():
            actual = context.get(key)
            
            if isinstance(expected, dict):
                if "eq" in expected and actual != expected["eq"]:
                    return False
                if "in" in expected and actual not in expected["in"]:
                    return False
                if "gt" in expected and not (actual > expected["gt"]):
                    return False
                if "lt" in expected and not (actual < expected["lt"]):
                    return False
            elif actual != expected:
                return False
        
        return True
    
    def _invalidate_cache(self, matrix_id: str):
        """Invalidate permission cache for matrix"""
        keys_to_remove = [k for k in self._permission_cache if k.startswith(matrix_id)]
        for key in keys_to_remove:
            del self._permission_cache[key]
    
    def _log_audit(
        self,
        matrix_id: str,
        action: str,
        entity_type: str,
        entity_id: str,
        user_id: str,
        details: Dict[str, Any]
    ):
        """Log audit trail entry"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO audit_trail (matrix_id, action, entity_type, entity_id, user_id, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (matrix_id, action, entity_type, entity_id, user_id, json.dumps(details), datetime.now()))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to log audit: {e}")
    
    async def get_audit_trail(
        self,
        matrix_id: str,
        entity_type: str = None,
        entity_id: str = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit trail entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM audit_trail WHERE matrix_id = ?"
        params = [matrix_id]
        
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "id": row[0],
                "matrix_id": row[1],
                "action": row[2],
                "entity_type": row[3],
                "entity_id": row[4],
                "user_id": row[5],
                "details": json.loads(row[6]) if row[6] else {},
                "timestamp": row[7]
            }
            for row in rows
        ]
