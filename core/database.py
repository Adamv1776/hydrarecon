#!/usr/bin/env python3
"""
HydraRecon Database Manager
SQLite database for storing scan results, projects, and findings.
"""

import sqlite3
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager
import threading


class DatabaseManager:
    """Manages all database operations for HydraRecon"""
    
    def __init__(self, db_path: Path):
        """Initialize database manager"""
        self.db_path = db_path
        self._local = threading.local()
    
    @property
    def connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    @contextmanager
    def cursor(self):
        """Context manager for database cursor"""
        cursor = self.connection.cursor()
        try:
            yield cursor
            self.connection.commit()
        except Exception as e:
            self.connection.rollback()
            raise e
        finally:
            cursor.close()
    
    def initialize(self):
        """Initialize database schema"""
        with self.cursor() as cur:
            # Projects table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    scope TEXT,
                    client TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    metadata TEXT
                )
            ''')
            
            # Targets table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    hostname TEXT,
                    ip_address TEXT,
                    domain TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                )
            ''')
            
            # Scans table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    target_id INTEGER,
                    scan_type TEXT NOT NULL,
                    scan_profile TEXT,
                    status TEXT DEFAULT 'pending',
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    progress INTEGER DEFAULT 0,
                    command TEXT,
                    raw_output TEXT,
                    parsed_results TEXT,
                    error_message TEXT,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
                )
            ''')
            
            # Hosts table (discovered hosts)
            cur.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    scan_id INTEGER,
                    ip_address TEXT NOT NULL,
                    hostname TEXT,
                    mac_address TEXT,
                    vendor TEXT,
                    os_name TEXT,
                    os_accuracy INTEGER,
                    os_family TEXT,
                    state TEXT DEFAULT 'unknown',
                    state_reason TEXT,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    geolocation TEXT,
                    asn TEXT,
                    organization TEXT,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
                )
            ''')
            
            # Ports table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port_number INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    state TEXT,
                    state_reason TEXT,
                    service_name TEXT,
                    service_product TEXT,
                    service_version TEXT,
                    service_extrainfo TEXT,
                    service_conf INTEGER,
                    cpe TEXT,
                    banner TEXT,
                    scripts_output TEXT,
                    metadata TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
                )
            ''')
            
            # Credentials table (for Hydra results)
            cur.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    host_id INTEGER,
                    port_id INTEGER,
                    username TEXT,
                    password TEXT,
                    hash_value TEXT,
                    hash_type TEXT,
                    service TEXT,
                    source TEXT,
                    verified BOOLEAN DEFAULT FALSE,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL,
                    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE SET NULL
                )
            ''')
            
            # OSINT findings table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS osint_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    target_id INTEGER,
                    finding_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    title TEXT,
                    description TEXT,
                    data TEXT,
                    confidence INTEGER DEFAULT 50,
                    severity TEXT DEFAULT 'info',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
                )
            ''')
            
            # Vulnerabilities table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    host_id INTEGER,
                    port_id INTEGER,
                    vuln_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cve_ids TEXT,
                    cwe_ids TEXT,
                    references_list TEXT,
                    solution TEXT,
                    proof TEXT,
                    status TEXT DEFAULT 'open',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verified_at TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL,
                    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE SET NULL
                )
            ''')
            
            # DNS records table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    target_id INTEGER,
                    domain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_value TEXT NOT NULL,
                    ttl INTEGER,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
                )
            ''')
            
            # Subdomains table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    target_id INTEGER,
                    parent_domain TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    ip_addresses TEXT,
                    source TEXT,
                    alive BOOLEAN,
                    status_code INTEGER,
                    title TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
                )
            ''')
            
            # Emails table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    email TEXT NOT NULL,
                    domain TEXT,
                    full_name TEXT,
                    position TEXT,
                    department TEXT,
                    phone TEXT,
                    social_profiles TEXT,
                    source TEXT,
                    verified BOOLEAN DEFAULT FALSE,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                )
            ''')
            
            # Reports table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    report_type TEXT,
                    format TEXT,
                    file_path TEXT,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                )
            ''')
            
            # Notes/Comments table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    related_type TEXT,
                    related_id INTEGER,
                    title TEXT,
                    content TEXT NOT NULL,
                    tags TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                )
            ''')
            
            # Create indexes for performance
            cur.execute('CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_hosts_project ON hosts(project_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_credentials_project ON credentials(project_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_vulns_project ON vulnerabilities(project_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_osint_project ON osint_findings(project_id)')
    
    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
    
    # ==================== Project Operations ====================
    
    def create_project(self, name: str, description: str = "", scope: str = "",
                      client: str = "", metadata: Dict = None) -> int:
        """Create a new project"""
        with self.cursor() as cur:
            cur.execute('''
                INSERT INTO projects (name, description, scope, client, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, description, scope, client, json.dumps(metadata or {})))
            return cur.lastrowid
    
    def get_project(self, project_id: int) -> Optional[Dict]:
        """Get project by ID"""
        with self.cursor() as cur:
            cur.execute('SELECT * FROM projects WHERE id = ?', (project_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    
    def get_all_projects(self) -> List[Dict]:
        """Get all projects"""
        with self.cursor() as cur:
            cur.execute('SELECT * FROM projects ORDER BY updated_at DESC')
            return [dict(row) for row in cur.fetchall()]
    
    def update_project(self, project_id: int, **kwargs):
        """Update project attributes"""
        allowed = ['name', 'description', 'scope', 'client', 'status', 'metadata']
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        
        updates['updated_at'] = datetime.now()
        set_clause = ', '.join(f'{k} = ?' for k in updates.keys())
        values = list(updates.values()) + [project_id]
        
        with self.cursor() as cur:
            cur.execute(f'UPDATE projects SET {set_clause} WHERE id = ?', values)
    
    def delete_project(self, project_id: int):
        """Delete a project and all related data"""
        with self.cursor() as cur:
            cur.execute('DELETE FROM projects WHERE id = ?', (project_id,))
    
    # ==================== Target Operations ====================
    
    def add_target(self, project_id: int, target: str, target_type: str,
                   hostname: str = None, ip_address: str = None,
                   domain: str = None, metadata: Dict = None) -> int:
        """Add a target to a project"""
        with self.cursor() as cur:
            cur.execute('''
                INSERT INTO targets (project_id, target, target_type, hostname, 
                                   ip_address, domain, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (project_id, target, target_type, hostname, ip_address, 
                  domain, json.dumps(metadata or {})))
            return cur.lastrowid
    
    def get_targets(self, project_id: int) -> List[Dict]:
        """Get all targets for a project"""
        with self.cursor() as cur:
            cur.execute('SELECT * FROM targets WHERE project_id = ?', (project_id,))
            return [dict(row) for row in cur.fetchall()]
    
    # ==================== Host Operations ====================
    
    def add_host(self, project_id: int, ip_address: str, scan_id: int = None,
                 hostname: str = None, **kwargs) -> int:
        """Add a discovered host"""
        with self.cursor() as cur:
            # Check if host already exists
            cur.execute('''
                SELECT id FROM hosts WHERE project_id = ? AND ip_address = ?
            ''', (project_id, ip_address))
            existing = cur.fetchone()
            
            if existing:
                # Update existing host
                self.update_host(existing['id'], **kwargs)
                return existing['id']
            
            columns = ['project_id', 'ip_address', 'scan_id', 'hostname']
            values = [project_id, ip_address, scan_id, hostname]
            
            for key in ['mac_address', 'vendor', 'os_name', 'os_accuracy', 
                       'os_family', 'state', 'state_reason', 'geolocation',
                       'asn', 'organization', 'metadata']:
                if key in kwargs:
                    columns.append(key)
                    values.append(kwargs[key] if key != 'metadata' 
                                 else json.dumps(kwargs[key]))
            
            placeholders = ', '.join(['?' for _ in values])
            col_str = ', '.join(columns)
            
            cur.execute(f'''
                INSERT INTO hosts ({col_str}) VALUES ({placeholders})
            ''', values)
            return cur.lastrowid
    
    def update_host(self, host_id: int, **kwargs):
        """Update host attributes"""
        if not kwargs:
            return
        
        kwargs['last_seen'] = datetime.now()
        set_clause = ', '.join(f'{k} = ?' for k in kwargs.keys())
        values = list(kwargs.values()) + [host_id]
        
        with self.cursor() as cur:
            cur.execute(f'UPDATE hosts SET {set_clause} WHERE id = ?', values)
    
    def get_hosts(self, project_id: int) -> List[Dict]:
        """Get all hosts for a project"""
        with self.cursor() as cur:
            cur.execute('SELECT * FROM hosts WHERE project_id = ?', (project_id,))
            return [dict(row) for row in cur.fetchall()]
    
    def get_host_by_ip(self, project_id: int, ip_address: str) -> Optional[Dict]:
        """Get host by IP address"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT * FROM hosts WHERE project_id = ? AND ip_address = ?
            ''', (project_id, ip_address))
            row = cur.fetchone()
            return dict(row) if row else None
    
    # ==================== Port Operations ====================
    
    def add_port(self, host_id: int, port_number: int, protocol: str = 'tcp',
                 **kwargs) -> int:
        """Add a discovered port"""
        with self.cursor() as cur:
            # Check if port already exists
            cur.execute('''
                SELECT id FROM ports WHERE host_id = ? AND port_number = ? AND protocol = ?
            ''', (host_id, port_number, protocol))
            existing = cur.fetchone()
            
            if existing:
                self.update_port(existing['id'], **kwargs)
                return existing['id']
            
            columns = ['host_id', 'port_number', 'protocol']
            values = [host_id, port_number, protocol]
            
            for key in ['state', 'state_reason', 'service_name', 'service_product',
                       'service_version', 'service_extrainfo', 'service_conf',
                       'cpe', 'banner', 'scripts_output', 'metadata']:
                if key in kwargs:
                    columns.append(key)
                    values.append(kwargs[key] if key not in ['scripts_output', 'metadata']
                                 else json.dumps(kwargs[key]))
            
            placeholders = ', '.join(['?' for _ in values])
            col_str = ', '.join(columns)
            
            cur.execute(f'''
                INSERT INTO ports ({col_str}) VALUES ({placeholders})
            ''', values)
            return cur.lastrowid
    
    def update_port(self, port_id: int, **kwargs):
        """Update port attributes"""
        if not kwargs:
            return
        
        set_clause = ', '.join(f'{k} = ?' for k in kwargs.keys())
        values = list(kwargs.values()) + [port_id]
        
        with self.cursor() as cur:
            cur.execute(f'UPDATE ports SET {set_clause} WHERE id = ?', values)
    
    def get_ports(self, host_id: int) -> List[Dict]:
        """Get all ports for a host"""
        with self.cursor() as cur:
            cur.execute('SELECT * FROM ports WHERE host_id = ? ORDER BY port_number', 
                       (host_id,))
            return [dict(row) for row in cur.fetchall()]
    
    # ==================== Credential Operations ====================
    
    def add_credential(self, project_id: int, username: str = None,
                       password: str = None, **kwargs) -> int:
        """Add discovered credential"""
        with self.cursor() as cur:
            columns = ['project_id']
            values = [project_id]
            
            if username:
                columns.append('username')
                values.append(username)
            if password:
                columns.append('password')
                values.append(password)
            
            for key in ['host_id', 'port_id', 'hash_value', 'hash_type',
                       'service', 'source', 'verified', 'metadata']:
                if key in kwargs:
                    columns.append(key)
                    values.append(kwargs[key] if key != 'metadata'
                                 else json.dumps(kwargs[key]))
            
            placeholders = ', '.join(['?' for _ in values])
            col_str = ', '.join(columns)
            
            cur.execute(f'''
                INSERT INTO credentials ({col_str}) VALUES ({placeholders})
            ''', values)
            return cur.lastrowid
    
    def get_credentials(self, project_id: int) -> List[Dict]:
        """Get all credentials for a project"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT c.*, h.ip_address, h.hostname, p.port_number
                FROM credentials c
                LEFT JOIN hosts h ON c.host_id = h.id
                LEFT JOIN ports p ON c.port_id = p.id
                WHERE c.project_id = ?
            ''', (project_id,))
            return [dict(row) for row in cur.fetchall()]
    
    # ==================== OSINT Operations ====================
    
    def add_osint_finding(self, project_id: int, finding_type: str,
                          source: str, **kwargs) -> int:
        """Add OSINT finding"""
        with self.cursor() as cur:
            columns = ['project_id', 'finding_type', 'source']
            values = [project_id, finding_type, source]
            
            for key in ['target_id', 'title', 'description', 'data',
                       'confidence', 'severity', 'metadata']:
                if key in kwargs:
                    columns.append(key)
                    val = kwargs[key]
                    if key in ['data', 'metadata'] and isinstance(val, dict):
                        val = json.dumps(val)
                    values.append(val)
            
            placeholders = ', '.join(['?' for _ in values])
            col_str = ', '.join(columns)
            
            cur.execute(f'''
                INSERT INTO osint_findings ({col_str}) VALUES ({placeholders})
            ''', values)
            return cur.lastrowid
    
    def get_osint_findings(self, project_id: int, finding_type: str = None) -> List[Dict]:
        """Get OSINT findings for a project"""
        with self.cursor() as cur:
            if finding_type:
                cur.execute('''
                    SELECT * FROM osint_findings 
                    WHERE project_id = ? AND finding_type = ?
                ''', (project_id, finding_type))
            else:
                cur.execute('''
                    SELECT * FROM osint_findings WHERE project_id = ?
                ''', (project_id,))
            return [dict(row) for row in cur.fetchall()]
    
    # ==================== Vulnerability Operations ====================
    
    def add_vulnerability(self, project_id: int, title: str, **kwargs) -> int:
        """Add vulnerability"""
        with self.cursor() as cur:
            columns = ['project_id', 'title']
            values = [project_id, title]
            
            for key in ['host_id', 'port_id', 'vuln_id', 'description',
                       'severity', 'cvss_score', 'cvss_vector', 'cve_ids',
                       'cwe_ids', 'references_list', 'solution', 'proof',
                       'status', 'metadata']:
                if key in kwargs:
                    columns.append(key)
                    val = kwargs[key]
                    if key in ['cve_ids', 'cwe_ids', 'references_list', 'metadata']:
                        if isinstance(val, (list, dict)):
                            val = json.dumps(val)
                    values.append(val)
            
            placeholders = ', '.join(['?' for _ in values])
            col_str = ', '.join(columns)
            
            cur.execute(f'''
                INSERT INTO vulnerabilities ({col_str}) VALUES ({placeholders})
            ''', values)
            return cur.lastrowid
    
    def get_vulnerabilities(self, project_id: int, severity: str = None) -> List[Dict]:
        """Get vulnerabilities for a project"""
        with self.cursor() as cur:
            if severity:
                cur.execute('''
                    SELECT v.*, h.ip_address, h.hostname, p.port_number
                    FROM vulnerabilities v
                    LEFT JOIN hosts h ON v.host_id = h.id
                    LEFT JOIN ports p ON v.port_id = p.id
                    WHERE v.project_id = ? AND v.severity = ?
                ''', (project_id, severity))
            else:
                cur.execute('''
                    SELECT v.*, h.ip_address, h.hostname, p.port_number
                    FROM vulnerabilities v
                    LEFT JOIN hosts h ON v.host_id = h.id
                    LEFT JOIN ports p ON v.port_id = p.id
                    WHERE v.project_id = ?
                ''', (project_id,))
            return [dict(row) for row in cur.fetchall()]
    
    # ==================== Scan Operations ====================
    
    def create_scan(self, project_id: int, scan_type: str, target_id: int = None,
                    scan_profile: str = None, command: str = None) -> int:
        """Create a new scan record"""
        with self.cursor() as cur:
            cur.execute('''
                INSERT INTO scans (project_id, target_id, scan_type, scan_profile, command)
                VALUES (?, ?, ?, ?, ?)
            ''', (project_id, target_id, scan_type, scan_profile, command))
            return cur.lastrowid
    
    def update_scan(self, scan_id: int, **kwargs):
        """Update scan record"""
        if not kwargs:
            return
        
        # Handle JSON fields
        for key in ['parsed_results', 'metadata']:
            if key in kwargs and isinstance(kwargs[key], (dict, list)):
                kwargs[key] = json.dumps(kwargs[key])
        
        set_clause = ', '.join(f'{k} = ?' for k in kwargs.keys())
        values = list(kwargs.values()) + [scan_id]
        
        with self.cursor() as cur:
            cur.execute(f'UPDATE scans SET {set_clause} WHERE id = ?', values)
    
    def get_scans(self, project_id: int) -> List[Dict]:
        """Get all scans for a project"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT * FROM scans WHERE project_id = ? ORDER BY started_at DESC
            ''', (project_id,))
            return [dict(row) for row in cur.fetchall()]
    
    # ==================== Statistics ====================
    
    def get_project_stats(self, project_id: int) -> Dict:
        """Get statistics for a project"""
        with self.cursor() as cur:
            stats = {}
            
            # Target count
            cur.execute('SELECT COUNT(*) FROM targets WHERE project_id = ?', (project_id,))
            stats['targets'] = cur.fetchone()[0]
            
            # Host count
            cur.execute('SELECT COUNT(*) FROM hosts WHERE project_id = ?', (project_id,))
            stats['hosts'] = cur.fetchone()[0]
            
            # Open ports count
            cur.execute('''
                SELECT COUNT(*) FROM ports p
                JOIN hosts h ON p.host_id = h.id
                WHERE h.project_id = ? AND p.state = 'open'
            ''', (project_id,))
            stats['open_ports'] = cur.fetchone()[0]
            
            # Credentials count
            cur.execute('SELECT COUNT(*) FROM credentials WHERE project_id = ?', (project_id,))
            stats['credentials'] = cur.fetchone()[0]
            
            # Vulnerability counts by severity
            cur.execute('''
                SELECT severity, COUNT(*) FROM vulnerabilities 
                WHERE project_id = ? GROUP BY severity
            ''', (project_id,))
            stats['vulnerabilities'] = {row[0]: row[1] for row in cur.fetchall()}
            
            # Scan count
            cur.execute('SELECT COUNT(*) FROM scans WHERE project_id = ?', (project_id,))
            stats['scans'] = cur.fetchone()[0]
            
            return stats
