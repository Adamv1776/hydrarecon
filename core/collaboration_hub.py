"""
HydraRecon Real-Time Collaboration Hub
Live multi-user pentesting with cursor sharing, chat, and synchronized attacks
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Callable
from enum import Enum
import hashlib
import uuid


class UserRole(Enum):
    """User roles in collaboration"""
    LEADER = "leader"
    OPERATOR = "operator"
    OBSERVER = "observer"
    ANALYST = "analyst"


class UserStatus(Enum):
    """User online status"""
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    OFFLINE = "offline"


class MessageType(Enum):
    """Types of collaboration messages"""
    CHAT = "chat"
    COMMAND = "command"
    FINDING = "finding"
    ALERT = "alert"
    SYSTEM = "system"
    ANNOTATION = "annotation"
    QUESTION = "question"
    TASK_ASSIGN = "task_assign"


class TaskStatus(Enum):
    """Status of collaboration tasks"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


@dataclass
class CollaboratorUser:
    """A user in the collaboration session"""
    user_id: str
    username: str
    display_name: str
    avatar: str
    role: UserRole
    status: UserStatus
    color: str  # Cursor/highlight color
    current_page: str = ""
    cursor_position: Dict[str, int] = field(default_factory=dict)
    last_activity: datetime = field(default_factory=datetime.now)
    permissions: List[str] = field(default_factory=list)
    joined_at: datetime = field(default_factory=datetime.now)


@dataclass
class CollaborationMessage:
    """A message in the collaboration chat"""
    message_id: str
    session_id: str
    sender_id: str
    sender_name: str
    message_type: MessageType
    content: str
    timestamp: datetime
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    reactions: Dict[str, List[str]] = field(default_factory=dict)
    replies: List[str] = field(default_factory=list)
    mentions: List[str] = field(default_factory=list)
    read_by: List[str] = field(default_factory=list)


@dataclass
class CollaborationTask:
    """A task in the collaboration session"""
    task_id: str
    session_id: str
    title: str
    description: str
    assigned_to: List[str]
    created_by: str
    status: TaskStatus
    priority: int
    target: str = ""
    due_time: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    subtasks: List[Dict[str, Any]] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)


@dataclass
class SharedAnnotation:
    """A shared annotation on a finding or asset"""
    annotation_id: str
    session_id: str
    target_type: str  # "finding", "asset", "scan_result", etc.
    target_id: str
    author_id: str
    author_name: str
    content: str
    position: Dict[str, Any] = field(default_factory=dict)
    color: str = "#ffff00"
    timestamp: datetime = field(default_factory=datetime.now)
    resolved: bool = False


@dataclass
class CollaborationSession:
    """A collaboration session"""
    session_id: str
    name: str
    description: str
    created_by: str
    created_at: datetime
    target_scope: List[str]
    active: bool = True
    password_hash: Optional[str] = None
    max_users: int = 10
    settings: Dict[str, Any] = field(default_factory=dict)


class CollaborationHub:
    """
    Real-time collaboration hub for team pentesting
    
    Features:
    - Live user presence and cursor tracking
    - Real-time chat with mentions and reactions
    - Shared task management
    - Synchronized attack execution
    - Shared annotations on findings
    - Role-based permissions
    - Session recording integration
    """
    
    def __init__(self, db_path: str = "collaboration.db"):
        self.db_path = db_path
        self.sessions: Dict[str, CollaborationSession] = {}
        self.session_users: Dict[str, Dict[str, CollaboratorUser]] = {}
        self.message_queues: Dict[str, asyncio.Queue] = {}
        self.event_handlers: Dict[str, List[Callable]] = {}
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize the collaboration database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collaboration_sessions (
                session_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_by TEXT,
                created_at TIMESTAMP,
                target_scope TEXT,
                active INTEGER DEFAULT 1,
                password_hash TEXT,
                max_users INTEGER DEFAULT 10,
                settings TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collaboration_messages (
                message_id TEXT PRIMARY KEY,
                session_id TEXT,
                sender_id TEXT,
                sender_name TEXT,
                message_type TEXT,
                content TEXT,
                timestamp TIMESTAMP,
                attachments TEXT,
                reactions TEXT,
                replies TEXT,
                mentions TEXT,
                read_by TEXT,
                FOREIGN KEY (session_id) REFERENCES collaboration_sessions(session_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collaboration_tasks (
                task_id TEXT PRIMARY KEY,
                session_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                assigned_to TEXT,
                created_by TEXT,
                status TEXT,
                priority INTEGER DEFAULT 0,
                target TEXT,
                due_time TIMESTAMP,
                created_at TIMESTAMP,
                completed_at TIMESTAMP,
                subtasks TEXT,
                comments TEXT,
                FOREIGN KEY (session_id) REFERENCES collaboration_sessions(session_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shared_annotations (
                annotation_id TEXT PRIMARY KEY,
                session_id TEXT,
                target_type TEXT,
                target_id TEXT,
                author_id TEXT,
                author_name TEXT,
                content TEXT,
                position TEXT,
                color TEXT,
                timestamp TIMESTAMP,
                resolved INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES collaboration_sessions(session_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_session ON collaboration_messages(session_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_tasks_session ON collaboration_tasks(session_id)
        """)
        
        conn.commit()
        conn.close()
    
    async def create_session(self, name: str, created_by: str,
                            target_scope: List[str] = None,
                            description: str = "",
                            password: str = None,
                            max_users: int = 10) -> CollaborationSession:
        """Create a new collaboration session"""
        session = CollaborationSession(
            session_id=str(uuid.uuid4()),
            name=name,
            description=description,
            created_by=created_by,
            created_at=datetime.now(),
            target_scope=target_scope or [],
            max_users=max_users,
            password_hash=hashlib.sha256(password.encode()).hexdigest() if password else None
        )
        
        self.sessions[session.session_id] = session
        self.session_users[session.session_id] = {}
        self.message_queues[session.session_id] = asyncio.Queue()
        
        # Persist to database
        await self._persist_session(session)
        
        # Broadcast system message
        await self.send_message(
            session.session_id,
            "system",
            "System",
            MessageType.SYSTEM,
            f"Collaboration session '{name}' created by {created_by}"
        )
        
        return session
    
    async def _persist_session(self, session: CollaborationSession):
        """Persist session to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO collaboration_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.session_id,
            session.name,
            session.description,
            session.created_by,
            session.created_at.isoformat(),
            json.dumps(session.target_scope),
            1 if session.active else 0,
            session.password_hash,
            session.max_users,
            json.dumps(session.settings)
        ))
        
        conn.commit()
        conn.close()
    
    async def join_session(self, session_id: str, user_id: str,
                          username: str, display_name: str = None,
                          password: str = None,
                          role: UserRole = UserRole.OPERATOR) -> Optional[CollaboratorUser]:
        """Join a collaboration session"""
        if session_id not in self.sessions:
            # Try to load from database
            session = await self._load_session(session_id)
            if not session:
                return None
            self.sessions[session_id] = session
            self.session_users[session_id] = {}
            self.message_queues[session_id] = asyncio.Queue()
        
        session = self.sessions[session_id]
        
        # Check password
        if session.password_hash:
            if not password or hashlib.sha256(password.encode()).hexdigest() != session.password_hash:
                return None
        
        # Check max users
        if len(self.session_users[session_id]) >= session.max_users:
            return None
        
        # Generate user color
        colors = ["#ff0000", "#00ff00", "#0000ff", "#ffff00", "#ff00ff", "#00ffff",
                  "#ff8800", "#8800ff", "#00ff88", "#ff0088"]
        color = colors[len(self.session_users[session_id]) % len(colors)]
        
        user = CollaboratorUser(
            user_id=user_id,
            username=username,
            display_name=display_name or username,
            avatar="👤",
            role=role,
            status=UserStatus.ONLINE,
            color=color,
            permissions=self._get_default_permissions(role)
        )
        
        self.session_users[session_id][user_id] = user
        
        # Broadcast join message
        await self.send_message(
            session_id,
            "system",
            "System",
            MessageType.SYSTEM,
            f"{display_name or username} joined the session"
        )
        
        # Notify other users
        await self._broadcast_event(session_id, "user_joined", {
            "user_id": user_id,
            "username": username,
            "display_name": display_name or username,
            "color": color
        })
        
        return user
    
    def _get_default_permissions(self, role: UserRole) -> List[str]:
        """Get default permissions for a role"""
        permissions = {
            UserRole.LEADER: [
                "scan", "exploit", "chat", "annotate", "assign_tasks",
                "kick_users", "modify_scope", "end_session"
            ],
            UserRole.OPERATOR: [
                "scan", "exploit", "chat", "annotate", "create_tasks"
            ],
            UserRole.ANALYST: [
                "chat", "annotate", "create_tasks", "view_all"
            ],
            UserRole.OBSERVER: [
                "chat", "view_all"
            ]
        }
        return permissions.get(role, ["chat"])
    
    async def _load_session(self, session_id: str) -> Optional[CollaborationSession]:
        """Load session from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM collaboration_sessions WHERE session_id = ?",
            (session_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return CollaborationSession(
            session_id=row[0],
            name=row[1],
            description=row[2],
            created_by=row[3],
            created_at=datetime.fromisoformat(row[4]),
            target_scope=json.loads(row[5]) if row[5] else [],
            active=bool(row[6]),
            password_hash=row[7],
            max_users=row[8],
            settings=json.loads(row[9]) if row[9] else {}
        )
    
    async def leave_session(self, session_id: str, user_id: str):
        """Leave a collaboration session"""
        if session_id not in self.session_users:
            return
        
        if user_id in self.session_users[session_id]:
            user = self.session_users[session_id][user_id]
            del self.session_users[session_id][user_id]
            
            await self.send_message(
                session_id,
                "system",
                "System",
                MessageType.SYSTEM,
                f"{user.display_name} left the session"
            )
            
            await self._broadcast_event(session_id, "user_left", {
                "user_id": user_id,
                "username": user.username
            })
    
    async def update_cursor(self, session_id: str, user_id: str,
                           page: str, position: Dict[str, int]):
        """Update user's cursor position"""
        if session_id not in self.session_users:
            return
        
        if user_id in self.session_users[session_id]:
            user = self.session_users[session_id][user_id]
            user.current_page = page
            user.cursor_position = position
            user.last_activity = datetime.now()
            
            await self._broadcast_event(session_id, "cursor_update", {
                "user_id": user_id,
                "username": user.username,
                "color": user.color,
                "page": page,
                "position": position
            }, exclude=[user_id])
    
    async def update_status(self, session_id: str, user_id: str,
                           status: UserStatus):
        """Update user's status"""
        if session_id not in self.session_users:
            return
        
        if user_id in self.session_users[session_id]:
            self.session_users[session_id][user_id].status = status
            
            await self._broadcast_event(session_id, "status_update", {
                "user_id": user_id,
                "status": status.value
            })
    
    async def send_message(self, session_id: str, sender_id: str,
                          sender_name: str, message_type: MessageType,
                          content: str, attachments: List[Dict] = None,
                          mentions: List[str] = None) -> CollaborationMessage:
        """Send a message to the session"""
        message = CollaborationMessage(
            message_id=str(uuid.uuid4()),
            session_id=session_id,
            sender_id=sender_id,
            sender_name=sender_name,
            message_type=message_type,
            content=content,
            timestamp=datetime.now(),
            attachments=attachments or [],
            mentions=mentions or []
        )
        
        # Persist message
        await self._persist_message(message)
        
        # Add to queue
        if session_id in self.message_queues:
            await self.message_queues[session_id].put(message)
        
        # Broadcast to all users
        await self._broadcast_event(session_id, "new_message", {
            "message_id": message.message_id,
            "sender_id": sender_id,
            "sender_name": sender_name,
            "message_type": message_type.value,
            "content": content,
            "timestamp": message.timestamp.isoformat(),
            "mentions": mentions or []
        })
        
        return message
    
    async def _persist_message(self, message: CollaborationMessage):
        """Persist message to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO collaboration_messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            message.message_id,
            message.session_id,
            message.sender_id,
            message.sender_name,
            message.message_type.value,
            message.content,
            message.timestamp.isoformat(),
            json.dumps(message.attachments),
            json.dumps(message.reactions),
            json.dumps(message.replies),
            json.dumps(message.mentions),
            json.dumps(message.read_by)
        ))
        
        conn.commit()
        conn.close()
    
    async def add_reaction(self, session_id: str, message_id: str,
                          user_id: str, reaction: str):
        """Add a reaction to a message"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT reactions FROM collaboration_messages WHERE message_id = ?",
            (message_id,)
        )
        row = cursor.fetchone()
        
        if row:
            reactions = json.loads(row[0]) if row[0] else {}
            if reaction not in reactions:
                reactions[reaction] = []
            if user_id not in reactions[reaction]:
                reactions[reaction].append(user_id)
            
            cursor.execute(
                "UPDATE collaboration_messages SET reactions = ? WHERE message_id = ?",
                (json.dumps(reactions), message_id)
            )
            conn.commit()
            
            await self._broadcast_event(session_id, "message_reaction", {
                "message_id": message_id,
                "user_id": user_id,
                "reaction": reaction
            })
        
        conn.close()
    
    async def create_task(self, session_id: str, title: str,
                         created_by: str, description: str = "",
                         assigned_to: List[str] = None,
                         target: str = "", priority: int = 0,
                         due_time: datetime = None) -> CollaborationTask:
        """Create a collaboration task"""
        task = CollaborationTask(
            task_id=str(uuid.uuid4()),
            session_id=session_id,
            title=title,
            description=description,
            assigned_to=assigned_to or [],
            created_by=created_by,
            status=TaskStatus.PENDING,
            priority=priority,
            target=target,
            due_time=due_time
        )
        
        # Persist task
        await self._persist_task(task)
        
        # Notify assigned users
        await self._broadcast_event(session_id, "task_created", {
            "task_id": task.task_id,
            "title": title,
            "assigned_to": assigned_to or [],
            "created_by": created_by,
            "priority": priority
        })
        
        # Send chat notification
        if assigned_to:
            assignees = ", ".join(f"@{a}" for a in assigned_to)
            await self.send_message(
                session_id,
                created_by,
                "Task System",
                MessageType.TASK_ASSIGN,
                f"New task: {title}\nAssigned to: {assignees}",
                mentions=assigned_to
            )
        
        return task
    
    async def _persist_task(self, task: CollaborationTask):
        """Persist task to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO collaboration_tasks VALUES 
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            task.task_id,
            task.session_id,
            task.title,
            task.description,
            json.dumps(task.assigned_to),
            task.created_by,
            task.status.value,
            task.priority,
            task.target,
            task.due_time.isoformat() if task.due_time else None,
            task.created_at.isoformat(),
            task.completed_at.isoformat() if task.completed_at else None,
            json.dumps(task.subtasks),
            json.dumps(task.comments)
        ))
        
        conn.commit()
        conn.close()
    
    async def update_task_status(self, session_id: str, task_id: str,
                                status: TaskStatus, user_id: str):
        """Update task status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        completed_at = datetime.now().isoformat() if status == TaskStatus.COMPLETED else None
        
        cursor.execute("""
            UPDATE collaboration_tasks SET status = ?, completed_at = ?
            WHERE task_id = ?
        """, (status.value, completed_at, task_id))
        
        conn.commit()
        conn.close()
        
        await self._broadcast_event(session_id, "task_updated", {
            "task_id": task_id,
            "status": status.value,
            "updated_by": user_id
        })
    
    async def add_annotation(self, session_id: str, target_type: str,
                            target_id: str, author_id: str, author_name: str,
                            content: str, position: Dict = None,
                            color: str = "#ffff00") -> SharedAnnotation:
        """Add a shared annotation"""
        annotation = SharedAnnotation(
            annotation_id=str(uuid.uuid4()),
            session_id=session_id,
            target_type=target_type,
            target_id=target_id,
            author_id=author_id,
            author_name=author_name,
            content=content,
            position=position or {},
            color=color
        )
        
        # Persist annotation
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO shared_annotations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            annotation.annotation_id,
            annotation.session_id,
            annotation.target_type,
            annotation.target_id,
            annotation.author_id,
            annotation.author_name,
            annotation.content,
            json.dumps(annotation.position),
            annotation.color,
            annotation.timestamp.isoformat(),
            0
        ))
        
        conn.commit()
        conn.close()
        
        # Broadcast
        await self._broadcast_event(session_id, "annotation_added", {
            "annotation_id": annotation.annotation_id,
            "target_type": target_type,
            "target_id": target_id,
            "author_id": author_id,
            "author_name": author_name,
            "content": content,
            "color": color
        })
        
        return annotation
    
    async def share_finding(self, session_id: str, user_id: str,
                           user_name: str, finding: Dict[str, Any]):
        """Share a finding with the team"""
        severity = finding.get("severity", "medium")
        title = finding.get("title", "Unknown finding")
        
        # Create styled message
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        
        emoji = severity_emoji.get(severity, "⚪")
        content = f"{emoji} **{severity.upper()}**: {title}"
        if finding.get("description"):
            content += f"\n{finding['description'][:200]}..."
        
        await self.send_message(
            session_id,
            user_id,
            user_name,
            MessageType.FINDING,
            content,
            attachments=[finding]
        )
    
    async def request_assistance(self, session_id: str, user_id: str,
                                user_name: str, question: str,
                                context: Dict = None):
        """Request assistance from team members"""
        content = f"❓ **Assistance Requested**\n{question}"
        
        await self.send_message(
            session_id,
            user_id,
            user_name,
            MessageType.QUESTION,
            content,
            attachments=[context] if context else None
        )
    
    async def get_session_users(self, session_id: str) -> List[CollaboratorUser]:
        """Get all users in a session"""
        if session_id not in self.session_users:
            return []
        return list(self.session_users[session_id].values())
    
    async def get_messages(self, session_id: str, limit: int = 100,
                          before: datetime = None) -> List[CollaborationMessage]:
        """Get messages from a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if before:
            cursor.execute("""
                SELECT * FROM collaboration_messages
                WHERE session_id = ? AND timestamp < ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (session_id, before.isoformat(), limit))
        else:
            cursor.execute("""
                SELECT * FROM collaboration_messages
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (session_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        messages = []
        for row in rows:
            messages.append(CollaborationMessage(
                message_id=row[0],
                session_id=row[1],
                sender_id=row[2],
                sender_name=row[3],
                message_type=MessageType(row[4]),
                content=row[5],
                timestamp=datetime.fromisoformat(row[6]),
                attachments=json.loads(row[7]) if row[7] else [],
                reactions=json.loads(row[8]) if row[8] else {},
                replies=json.loads(row[9]) if row[9] else [],
                mentions=json.loads(row[10]) if row[10] else [],
                read_by=json.loads(row[11]) if row[11] else []
            ))
        
        return list(reversed(messages))
    
    async def get_tasks(self, session_id: str, 
                       status: TaskStatus = None) -> List[CollaborationTask]:
        """Get tasks for a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute("""
                SELECT * FROM collaboration_tasks
                WHERE session_id = ? AND status = ?
                ORDER BY priority DESC, created_at
            """, (session_id, status.value))
        else:
            cursor.execute("""
                SELECT * FROM collaboration_tasks
                WHERE session_id = ?
                ORDER BY priority DESC, created_at
            """, (session_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        tasks = []
        for row in rows:
            tasks.append(CollaborationTask(
                task_id=row[0],
                session_id=row[1],
                title=row[2],
                description=row[3],
                assigned_to=json.loads(row[4]) if row[4] else [],
                created_by=row[5],
                status=TaskStatus(row[6]),
                priority=row[7],
                target=row[8],
                due_time=datetime.fromisoformat(row[9]) if row[9] else None,
                created_at=datetime.fromisoformat(row[10]),
                completed_at=datetime.fromisoformat(row[11]) if row[11] else None,
                subtasks=json.loads(row[12]) if row[12] else [],
                comments=json.loads(row[13]) if row[13] else []
            ))
        
        return tasks
    
    async def get_annotations(self, session_id: str, 
                             target_type: str = None,
                             target_id: str = None) -> List[SharedAnnotation]:
        """Get annotations for a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM shared_annotations WHERE session_id = ?"
        params = [session_id]
        
        if target_type:
            query += " AND target_type = ?"
            params.append(target_type)
        
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        annotations = []
        for row in rows:
            annotations.append(SharedAnnotation(
                annotation_id=row[0],
                session_id=row[1],
                target_type=row[2],
                target_id=row[3],
                author_id=row[4],
                author_name=row[5],
                content=row[6],
                position=json.loads(row[7]) if row[7] else {},
                color=row[8],
                timestamp=datetime.fromisoformat(row[9]),
                resolved=bool(row[10])
            ))
        
        return annotations
    
    async def _broadcast_event(self, session_id: str, event_type: str,
                              data: Dict[str, Any], exclude: List[str] = None):
        """Broadcast an event to all session users"""
        if session_id not in self.event_handlers:
            return
        
        for handler in self.event_handlers.get(session_id, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event_type, data, exclude or [])
                else:
                    handler(event_type, data, exclude or [])
            except Exception as e:
                print(f"Event broadcast error: {e}")
    
    def add_event_handler(self, session_id: str, handler: Callable):
        """Add an event handler for a session"""
        if session_id not in self.event_handlers:
            self.event_handlers[session_id] = []
        self.event_handlers[session_id].append(handler)
    
    def remove_event_handler(self, session_id: str, handler: Callable):
        """Remove an event handler"""
        if session_id in self.event_handlers:
            if handler in self.event_handlers[session_id]:
                self.event_handlers[session_id].remove(handler)
    
    async def end_session(self, session_id: str, ended_by: str):
        """End a collaboration session"""
        if session_id in self.sessions:
            self.sessions[session_id].active = False
            await self._persist_session(self.sessions[session_id])
            
            await self.send_message(
                session_id,
                "system",
                "System",
                MessageType.SYSTEM,
                f"Session ended by {ended_by}"
            )
            
            # Kick all users
            for user_id in list(self.session_users.get(session_id, {}).keys()):
                await self.leave_session(session_id, user_id)
            
            # Cleanup
            if session_id in self.session_users:
                del self.session_users[session_id]
            if session_id in self.message_queues:
                del self.message_queues[session_id]
            if session_id in self.event_handlers:
                del self.event_handlers[session_id]
    
    async def list_sessions(self, active_only: bool = True) -> List[CollaborationSession]:
        """List all collaboration sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if active_only:
            cursor.execute("""
                SELECT * FROM collaboration_sessions
                WHERE active = 1
                ORDER BY created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT * FROM collaboration_sessions
                ORDER BY created_at DESC
            """)
        
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            sessions.append(CollaborationSession(
                session_id=row[0],
                name=row[1],
                description=row[2],
                created_by=row[3],
                created_at=datetime.fromisoformat(row[4]),
                target_scope=json.loads(row[5]) if row[5] else [],
                active=bool(row[6]),
                password_hash=row[7],
                max_users=row[8],
                settings=json.loads(row[9]) if row[9] else {}
            ))
        
        return sessions
