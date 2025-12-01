#!/usr/bin/env python3
"""
HydraRecon Session & Project Management
████████████████████████████████████████████████████████████████████████████████
█  PERSISTENT ENGAGEMENT TRACKING - Sessions, Credentials, Pivoting Support    █
████████████████████████████████████████████████████████████████████████████████
"""

import os
import json
import sqlite3
import hashlib
import base64
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import uuid


class SessionType(Enum):
    SHELL = "shell"
    METERPRETER = "meterpreter"
    SSH = "ssh"
    RDP = "rdp"
    VNC = "vnc"
    WMI = "wmi"
    WINRM = "winrm"
    WEB = "web"


class SessionStatus(Enum):
    ACTIVE = "active"
    DORMANT = "dormant"
    DEAD = "dead"
    UPGRADING = "upgrading"


class CredentialType(Enum):
    PASSWORD = "password"
    HASH_NTLM = "hash_ntlm"
    HASH_LM = "hash_lm"
    SSH_KEY = "ssh_key"
    TOKEN = "token"
    KERBEROS_TICKET = "kerberos_ticket"
    CERTIFICATE = "certificate"
    API_KEY = "api_key"


@dataclass
class Session:
    """Active session with compromised host"""
    id: str
    session_type: SessionType
    target_host: str
    target_port: int
    local_host: str
    local_port: int
    status: SessionStatus
    username: str = ""
    hostname: str = ""
    os_info: str = ""
    architecture: str = ""
    privileges: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    notes: str = ""
    routes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['session_type'] = self.session_type.value
        d['status'] = self.status.value
        d['created_at'] = self.created_at.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        return d
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'Session':
        d['session_type'] = SessionType(d['session_type'])
        d['status'] = SessionStatus(d['status'])
        d['created_at'] = datetime.fromisoformat(d['created_at'])
        d['last_seen'] = datetime.fromisoformat(d['last_seen'])
        return cls(**d)


@dataclass
class Credential:
    """Captured credential"""
    id: str
    credential_type: CredentialType
    username: str
    secret: str  # Encrypted in storage
    domain: str = ""
    source_host: str = ""
    source_service: str = ""
    target_host: str = ""
    captured_at: datetime = field(default_factory=datetime.now)
    validated: bool = False
    notes: str = ""
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['credential_type'] = self.credential_type.value
        d['captured_at'] = self.captured_at.isoformat()
        return d
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'Credential':
        d['credential_type'] = CredentialType(d['credential_type'])
        d['captured_at'] = datetime.fromisoformat(d['captured_at'])
        return cls(**d)


@dataclass 
class Loot:
    """Collected loot/data from target"""
    id: str
    loot_type: str  # file, screenshot, keylog, etc.
    name: str
    data: bytes
    source_host: str
    source_path: str = ""
    captured_at: datetime = field(default_factory=datetime.now)
    session_id: str = ""
    notes: str = ""


@dataclass
class Host:
    """Discovered host with enumeration data"""
    id: str
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    os_name: str = ""
    os_version: str = ""
    architecture: str = ""
    services: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    compromised: bool = False
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['first_seen'] = self.first_seen.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        return d


@dataclass
class Route:
    """Network route through pivot"""
    subnet: str
    netmask: str
    gateway_session_id: str
    metric: int = 1


@dataclass
class Project:
    """Engagement/Project container"""
    id: str
    name: str
    description: str = ""
    client_name: str = ""
    scope: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ""


class SessionManager:
    """
    Central session and project management
    Tracks all compromised hosts, credentials, loot, and pivots
    """
    
    def __init__(self, db_path: str = None, encryption_key: bytes = None):
        self.db_path = db_path or os.path.expanduser("~/.hydrarecon/sessions.db")
        self._ensure_db_dir()
        
        # Encryption for credentials
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            self.cipher = None
        
        self._init_database()
        
        # In-memory caches
        self.active_sessions: Dict[str, Session] = {}
        self.routes: List[Route] = []
    
    def _ensure_db_dir(self):
        """Ensure database directory exists"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Projects table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                client_name TEXT,
                scope TEXT,
                exclusions TEXT,
                created_at TEXT,
                updated_at TEXT,
                start_date TEXT,
                end_date TEXT,
                tags TEXT,
                notes TEXT
            )
        ''')
        
        # Hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                os_name TEXT,
                os_version TEXT,
                architecture TEXT,
                services TEXT,
                vulnerabilities TEXT,
                notes TEXT,
                tags TEXT,
                first_seen TEXT,
                last_seen TEXT,
                compromised INTEGER,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                host_id TEXT,
                session_type TEXT,
                target_host TEXT,
                target_port INTEGER,
                local_host TEXT,
                local_port INTEGER,
                status TEXT,
                username TEXT,
                hostname TEXT,
                os_info TEXT,
                architecture TEXT,
                privileges TEXT,
                created_at TEXT,
                last_seen TEXT,
                notes TEXT,
                routes TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        ''')
        
        # Credentials table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                credential_type TEXT,
                username TEXT,
                secret TEXT,
                domain TEXT,
                source_host TEXT,
                source_service TEXT,
                target_host TEXT,
                captured_at TEXT,
                validated INTEGER,
                notes TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )
        ''')
        
        # Loot table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS loot (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                session_id TEXT,
                loot_type TEXT,
                name TEXT,
                data BLOB,
                source_host TEXT,
                source_path TEXT,
                captured_at TEXT,
                notes TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        ''')
        
        # Events/Activity log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT,
                timestamp TEXT,
                event_type TEXT,
                source TEXT,
                description TEXT,
                details TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_creds_user ON credentials(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target_host)')
        
        conn.commit()
        conn.close()
    
    def _encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if self.cipher:
            return self.cipher.encrypt(data.encode()).decode()
        return data
    
    def _decrypt(self, data: str) -> str:
        """Decrypt sensitive data"""
        if self.cipher:
            return self.cipher.decrypt(data.encode()).decode()
        return data
    
    # === Project Management ===
    
    def create_project(self, name: str, **kwargs) -> Project:
        """Create a new project/engagement"""
        project = Project(
            id=str(uuid.uuid4()),
            name=name,
            **kwargs
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO projects (id, name, description, client_name, scope, 
                                 exclusions, created_at, updated_at, start_date, 
                                 end_date, tags, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            project.id, project.name, project.description, project.client_name,
            json.dumps(project.scope), json.dumps(project.exclusions),
            project.created_at.isoformat(), project.updated_at.isoformat(),
            project.start_date.isoformat() if project.start_date else None,
            project.end_date.isoformat() if project.end_date else None,
            json.dumps(project.tags), project.notes
        ))
        conn.commit()
        conn.close()
        
        self._log_activity(project.id, "project", "create", f"Created project: {name}")
        return project
    
    def get_projects(self) -> List[Project]:
        """Get all projects"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM projects ORDER BY created_at DESC')
        rows = cursor.fetchall()
        conn.close()
        
        projects = []
        for row in rows:
            projects.append(Project(
                id=row[0],
                name=row[1],
                description=row[2] or "",
                client_name=row[3] or "",
                scope=json.loads(row[4]) if row[4] else [],
                exclusions=json.loads(row[5]) if row[5] else [],
                created_at=datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                updated_at=datetime.fromisoformat(row[7]) if row[7] else datetime.now(),
                start_date=datetime.fromisoformat(row[8]) if row[8] else None,
                end_date=datetime.fromisoformat(row[9]) if row[9] else None,
                tags=json.loads(row[10]) if row[10] else [],
                notes=row[11] or ""
            ))
        
        return projects
    
    # === Host Management ===
    
    def add_host(self, project_id: str, ip_address: str, **kwargs) -> Host:
        """Add or update a host"""
        host = Host(
            id=str(uuid.uuid4()),
            ip_address=ip_address,
            **kwargs
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if host already exists
        cursor.execute('''
            SELECT id FROM hosts WHERE project_id = ? AND ip_address = ?
        ''', (project_id, ip_address))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing host
            cursor.execute('''
                UPDATE hosts SET hostname = ?, os_name = ?, os_version = ?,
                    services = ?, vulnerabilities = ?, last_seen = ?, 
                    compromised = ?, notes = ?
                WHERE id = ?
            ''', (
                host.hostname, host.os_name, host.os_version,
                json.dumps(host.services), json.dumps(host.vulnerabilities),
                datetime.now().isoformat(), host.compromised, host.notes,
                existing[0]
            ))
            host.id = existing[0]
        else:
            # Insert new host
            cursor.execute('''
                INSERT INTO hosts (id, project_id, ip_address, hostname, mac_address,
                                  os_name, os_version, architecture, services,
                                  vulnerabilities, notes, tags, first_seen,
                                  last_seen, compromised)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                host.id, project_id, host.ip_address, host.hostname, host.mac_address,
                host.os_name, host.os_version, host.architecture,
                json.dumps(host.services), json.dumps(host.vulnerabilities),
                host.notes, json.dumps(host.tags),
                host.first_seen.isoformat(), host.last_seen.isoformat(),
                1 if host.compromised else 0
            ))
        
        conn.commit()
        conn.close()
        
        self._log_activity(project_id, "host", "add", f"Added/updated host: {ip_address}")
        return host
    
    def get_hosts(self, project_id: str = None) -> List[Host]:
        """Get all hosts, optionally filtered by project"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if project_id:
            cursor.execute('SELECT * FROM hosts WHERE project_id = ?', (project_id,))
        else:
            cursor.execute('SELECT * FROM hosts')
        
        rows = cursor.fetchall()
        conn.close()
        
        hosts = []
        for row in rows:
            hosts.append(Host(
                id=row[0],
                ip_address=row[2],
                hostname=row[3] or "",
                mac_address=row[4] or "",
                os_name=row[5] or "",
                os_version=row[6] or "",
                architecture=row[7] or "",
                services=json.loads(row[8]) if row[8] else [],
                vulnerabilities=json.loads(row[9]) if row[9] else [],
                notes=row[10] or "",
                tags=json.loads(row[11]) if row[11] else [],
                first_seen=datetime.fromisoformat(row[12]) if row[12] else datetime.now(),
                last_seen=datetime.fromisoformat(row[13]) if row[13] else datetime.now(),
                compromised=bool(row[14])
            ))
        
        return hosts
    
    # === Session Management ===
    
    def create_session(self, project_id: str, session_type: SessionType,
                      target_host: str, target_port: int,
                      local_host: str, local_port: int, **kwargs) -> Session:
        """Create a new session"""
        session = Session(
            id=str(uuid.uuid4()),
            session_type=session_type,
            target_host=target_host,
            target_port=target_port,
            local_host=local_host,
            local_port=local_port,
            status=SessionStatus.ACTIVE,
            **kwargs
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sessions (id, project_id, session_type, target_host,
                                 target_port, local_host, local_port, status,
                                 username, hostname, os_info, architecture,
                                 privileges, created_at, last_seen, notes, routes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.id, project_id, session.session_type.value,
            session.target_host, session.target_port,
            session.local_host, session.local_port,
            session.status.value, session.username, session.hostname,
            session.os_info, session.architecture, session.privileges,
            session.created_at.isoformat(), session.last_seen.isoformat(),
            session.notes, json.dumps(session.routes)
        ))
        conn.commit()
        conn.close()
        
        # Add to active sessions cache
        self.active_sessions[session.id] = session
        
        # Mark host as compromised
        self.add_host(project_id, target_host, compromised=True)
        
        self._log_activity(project_id, "session", "create", 
                          f"New {session_type.value} session on {target_host}:{target_port}")
        return session
    
    def get_sessions(self, project_id: str = None, 
                    status: SessionStatus = None) -> List[Session]:
        """Get sessions with optional filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = 'SELECT * FROM sessions WHERE 1=1'
        params = []
        
        if project_id:
            query += ' AND project_id = ?'
            params.append(project_id)
        
        if status:
            query += ' AND status = ?'
            params.append(status.value)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            sessions.append(Session(
                id=row[0],
                session_type=SessionType(row[2]),
                target_host=row[3],
                target_port=row[4],
                local_host=row[5],
                local_port=row[6],
                status=SessionStatus(row[7]),
                username=row[8] or "",
                hostname=row[9] or "",
                os_info=row[10] or "",
                architecture=row[11] or "",
                privileges=row[12] or "",
                created_at=datetime.fromisoformat(row[13]) if row[13] else datetime.now(),
                last_seen=datetime.fromisoformat(row[14]) if row[14] else datetime.now(),
                notes=row[15] or "",
                routes=json.loads(row[16]) if row[16] else []
            ))
        
        return sessions
    
    def update_session_status(self, session_id: str, status: SessionStatus):
        """Update session status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sessions SET status = ?, last_seen = ? WHERE id = ?
        ''', (status.value, datetime.now().isoformat(), session_id))
        conn.commit()
        conn.close()
        
        if session_id in self.active_sessions:
            self.active_sessions[session_id].status = status
    
    # === Credential Management ===
    
    def add_credential(self, project_id: str, credential_type: CredentialType,
                      username: str, secret: str, **kwargs) -> Credential:
        """Add a captured credential"""
        credential = Credential(
            id=str(uuid.uuid4()),
            credential_type=credential_type,
            username=username,
            secret=self._encrypt(secret),  # Encrypt the secret
            **kwargs
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO credentials (id, project_id, credential_type, username,
                                    secret, domain, source_host, source_service,
                                    target_host, captured_at, validated, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            credential.id, project_id, credential.credential_type.value,
            credential.username, credential.secret, credential.domain,
            credential.source_host, credential.source_service,
            credential.target_host, credential.captured_at.isoformat(),
            1 if credential.validated else 0, credential.notes
        ))
        conn.commit()
        conn.close()
        
        self._log_activity(project_id, "credential", "capture",
                          f"Captured {credential_type.value} for {username}")
        return credential
    
    def get_credentials(self, project_id: str = None, 
                       decrypt: bool = False) -> List[Credential]:
        """Get credentials with optional decryption"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if project_id:
            cursor.execute('SELECT * FROM credentials WHERE project_id = ?', (project_id,))
        else:
            cursor.execute('SELECT * FROM credentials')
        
        rows = cursor.fetchall()
        conn.close()
        
        credentials = []
        for row in rows:
            secret = row[4]
            if decrypt:
                secret = self._decrypt(secret)
            
            credentials.append(Credential(
                id=row[0],
                credential_type=CredentialType(row[2]),
                username=row[3],
                secret=secret,
                domain=row[5] or "",
                source_host=row[6] or "",
                source_service=row[7] or "",
                target_host=row[8] or "",
                captured_at=datetime.fromisoformat(row[9]) if row[9] else datetime.now(),
                validated=bool(row[10]),
                notes=row[11] or ""
            ))
        
        return credentials
    
    # === Loot Management ===
    
    def add_loot(self, project_id: str, loot_type: str, name: str,
                data: bytes, source_host: str, **kwargs) -> Loot:
        """Add captured loot"""
        loot = Loot(
            id=str(uuid.uuid4()),
            loot_type=loot_type,
            name=name,
            data=data,
            source_host=source_host,
            **kwargs
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO loot (id, project_id, session_id, loot_type, name,
                             data, source_host, source_path, captured_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            loot.id, project_id, loot.session_id, loot.loot_type, loot.name,
            loot.data, loot.source_host, loot.source_path,
            loot.captured_at.isoformat(), loot.notes
        ))
        conn.commit()
        conn.close()
        
        self._log_activity(project_id, "loot", "capture",
                          f"Captured {loot_type}: {name} from {source_host}")
        return loot
    
    # === Route/Pivot Management ===
    
    def add_route(self, subnet: str, netmask: str, session_id: str) -> Route:
        """Add a route through a pivot session"""
        route = Route(
            subnet=subnet,
            netmask=netmask,
            gateway_session_id=session_id
        )
        self.routes.append(route)
        return route
    
    def get_routes(self) -> List[Route]:
        """Get all active routes"""
        return self.routes
    
    # === Activity Logging ===
    
    def _log_activity(self, project_id: str, event_type: str,
                     source: str, description: str, details: str = ""):
        """Log an activity event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO activity_log (project_id, timestamp, event_type,
                                     source, description, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            project_id, datetime.now().isoformat(),
            event_type, source, description, details
        ))
        conn.commit()
        conn.close()
    
    def get_activity_log(self, project_id: str = None,
                        limit: int = 100) -> List[Dict]:
        """Get activity log"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if project_id:
            cursor.execute('''
                SELECT * FROM activity_log WHERE project_id = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (project_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "id": row[0],
                "project_id": row[1],
                "timestamp": row[2],
                "event_type": row[3],
                "source": row[4],
                "description": row[5],
                "details": row[6]
            }
            for row in rows
        ]
    
    # === Statistics ===
    
    def get_project_stats(self, project_id: str) -> Dict:
        """Get statistics for a project"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Host count
        cursor.execute('SELECT COUNT(*) FROM hosts WHERE project_id = ?', (project_id,))
        host_count = cursor.fetchone()[0]
        
        # Compromised hosts
        cursor.execute('SELECT COUNT(*) FROM hosts WHERE project_id = ? AND compromised = 1', (project_id,))
        compromised_count = cursor.fetchone()[0]
        
        # Active sessions
        cursor.execute('SELECT COUNT(*) FROM sessions WHERE project_id = ? AND status = ?',
                      (project_id, SessionStatus.ACTIVE.value))
        active_sessions = cursor.fetchone()[0]
        
        # Credentials
        cursor.execute('SELECT COUNT(*) FROM credentials WHERE project_id = ?', (project_id,))
        credential_count = cursor.fetchone()[0]
        
        # Loot
        cursor.execute('SELECT COUNT(*) FROM loot WHERE project_id = ?', (project_id,))
        loot_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "hosts_total": host_count,
            "hosts_compromised": compromised_count,
            "sessions_active": active_sessions,
            "credentials_captured": credential_count,
            "loot_items": loot_count,
            "compromise_rate": f"{(compromised_count / host_count * 100):.1f}%" if host_count > 0 else "N/A"
        }


# Generate encryption key from password
def generate_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Generate Fernet key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt
