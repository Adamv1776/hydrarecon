"""
Real-Time Collaboration System
Multi-user collaboration for security assessments
"""

import asyncio
import json
import hashlib
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Set
from enum import Enum
import websockets
import logging
import threading
import queue

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of collaboration messages"""
    # Connection
    JOIN = "join"
    LEAVE = "leave"
    HEARTBEAT = "heartbeat"
    
    # Data sync
    SYNC_REQUEST = "sync_request"
    SYNC_RESPONSE = "sync_response"
    DATA_UPDATE = "data_update"
    
    # Operations
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    FINDING = "finding"
    TARGET_ADD = "target_add"
    COMMENT = "comment"
    
    # Chat
    CHAT = "chat"
    
    # Permissions
    PERMISSION_REQUEST = "permission_request"
    PERMISSION_GRANT = "permission_grant"
    PERMISSION_DENY = "permission_deny"


class UserRole(Enum):
    """User roles in collaboration"""
    OWNER = "owner"
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


@dataclass
class CollaborationUser:
    """Represents a user in the collaboration session"""
    id: str
    username: str
    email: str = ""
    role: UserRole = UserRole.VIEWER
    avatar: str = ""
    status: str = "online"
    current_page: str = "dashboard"
    last_seen: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'avatar': self.avatar,
            'status': self.status,
            'current_page': self.current_page,
            'last_seen': self.last_seen.isoformat()
        }


@dataclass
class CollaborationMessage:
    """Message for collaboration"""
    type: MessageType
    sender_id: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_json(self) -> str:
        return json.dumps({
            'id': self.id,
            'type': self.type.value,
            'sender_id': self.sender_id,
            'data': self.data,
            'timestamp': self.timestamp.isoformat()
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CollaborationMessage':
        data = json.loads(json_str)
        return cls(
            id=data['id'],
            type=MessageType(data['type']),
            sender_id=data['sender_id'],
            data=data.get('data', {}),
            timestamp=datetime.fromisoformat(data['timestamp'])
        )


@dataclass
class CollaborationSession:
    """Represents a collaboration session"""
    id: str
    name: str
    owner_id: str
    created_at: datetime = field(default_factory=datetime.now)
    users: Dict[str, CollaborationUser] = field(default_factory=dict)
    shared_data: Dict[str, Any] = field(default_factory=dict)
    chat_history: List[Dict] = field(default_factory=list)
    is_private: bool = False
    password_hash: Optional[str] = None


class CollaborationClient:
    """
    Client for real-time collaboration.
    Connects to collaboration server and handles messaging.
    """
    
    def __init__(self, user: CollaborationUser):
        self.user = user
        self.session: Optional[CollaborationSession] = None
        self.websocket = None
        self._connected = False
        self._message_handlers: Dict[MessageType, List[Callable]] = {}
        self._outgoing_queue: queue.Queue = queue.Queue()
        self._receive_task = None
        self._send_task = None
    
    async def connect(self, server_url: str, 
                      session_id: str, 
                      password: Optional[str] = None) -> bool:
        """Connect to a collaboration session"""
        try:
            self.websocket = await websockets.connect(server_url)
            self._connected = True
            
            # Send join message
            join_msg = CollaborationMessage(
                type=MessageType.JOIN,
                sender_id=self.user.id,
                data={
                    'user': self.user.to_dict(),
                    'session_id': session_id,
                    'password': hashlib.sha256(password.encode()).hexdigest() if password else None
                }
            )
            await self.websocket.send(join_msg.to_json())
            
            # Wait for response
            response = await self.websocket.recv()
            response_msg = CollaborationMessage.from_json(response)
            
            if response_msg.type == MessageType.SYNC_RESPONSE:
                self.session = CollaborationSession(
                    id=session_id,
                    name=response_msg.data.get('session_name', 'Unknown'),
                    owner_id=response_msg.data.get('owner_id', ''),
                    shared_data=response_msg.data.get('shared_data', {}),
                    chat_history=response_msg.data.get('chat_history', [])
                )
                
                # Start background tasks
                self._receive_task = asyncio.create_task(self._receive_loop())
                self._send_task = asyncio.create_task(self._send_loop())
                
                logger.info(f"Connected to session {session_id}")
                return True
            else:
                logger.error("Failed to join session")
                return False
                
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from the session"""
        if self._connected and self.websocket:
            # Send leave message
            leave_msg = CollaborationMessage(
                type=MessageType.LEAVE,
                sender_id=self.user.id
            )
            await self.websocket.send(leave_msg.to_json())
            
            # Cancel tasks
            if self._receive_task:
                self._receive_task.cancel()
            if self._send_task:
                self._send_task.cancel()
            
            await self.websocket.close()
            self._connected = False
            self.session = None
            
            logger.info("Disconnected from session")
    
    async def _receive_loop(self) -> None:
        """Background loop to receive messages"""
        while self._connected:
            try:
                message = await self.websocket.recv()
                msg = CollaborationMessage.from_json(message)
                await self._handle_message(msg)
            except websockets.ConnectionClosed:
                self._connected = False
                break
            except Exception as e:
                logger.error(f"Error receiving message: {e}")
    
    async def _send_loop(self) -> None:
        """Background loop to send queued messages"""
        while self._connected:
            try:
                if not self._outgoing_queue.empty():
                    msg = self._outgoing_queue.get_nowait()
                    await self.websocket.send(msg.to_json())
                await asyncio.sleep(0.01)
            except Exception as e:
                logger.error(f"Error sending message: {e}")
    
    async def _handle_message(self, msg: CollaborationMessage) -> None:
        """Handle incoming messages"""
        handlers = self._message_handlers.get(msg.type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(msg)
                else:
                    handler(msg)
            except Exception as e:
                logger.error(f"Error in message handler: {e}")
        
        # Built-in handlers
        if msg.type == MessageType.JOIN:
            user_data = msg.data.get('user', {})
            user = CollaborationUser(
                id=user_data['id'],
                username=user_data['username'],
                role=UserRole(user_data.get('role', 'viewer'))
            )
            if self.session:
                self.session.users[user.id] = user
                
        elif msg.type == MessageType.LEAVE:
            if self.session and msg.sender_id in self.session.users:
                del self.session.users[msg.sender_id]
                
        elif msg.type == MessageType.DATA_UPDATE:
            if self.session:
                key = msg.data.get('key')
                value = msg.data.get('value')
                if key:
                    self.session.shared_data[key] = value
                    
        elif msg.type == MessageType.CHAT:
            if self.session:
                self.session.chat_history.append({
                    'sender_id': msg.sender_id,
                    'message': msg.data.get('message', ''),
                    'timestamp': msg.timestamp.isoformat()
                })
    
    def on_message(self, message_type: MessageType, 
                   handler: Callable) -> None:
        """Register a message handler"""
        if message_type not in self._message_handlers:
            self._message_handlers[message_type] = []
        self._message_handlers[message_type].append(handler)
    
    def send_message(self, message_type: MessageType, 
                     data: Dict[str, Any] = None) -> None:
        """Queue a message to be sent"""
        msg = CollaborationMessage(
            type=message_type,
            sender_id=self.user.id,
            data=data or {}
        )
        self._outgoing_queue.put(msg)
    
    def send_chat(self, message: str) -> None:
        """Send a chat message"""
        self.send_message(MessageType.CHAT, {'message': message})
    
    def share_finding(self, finding: Dict[str, Any]) -> None:
        """Share a finding with the team"""
        self.send_message(MessageType.FINDING, finding)
    
    def share_scan_start(self, target: str, scan_type: str) -> None:
        """Notify team of scan start"""
        self.send_message(MessageType.SCAN_START, {
            'target': target,
            'scan_type': scan_type
        })
    
    def share_scan_complete(self, target: str, 
                            results_summary: Dict[str, Any]) -> None:
        """Share scan completion"""
        self.send_message(MessageType.SCAN_COMPLETE, {
            'target': target,
            'summary': results_summary
        })
    
    def update_shared_data(self, key: str, value: Any) -> None:
        """Update shared data"""
        self.send_message(MessageType.DATA_UPDATE, {
            'key': key,
            'value': value
        })
    
    def update_status(self, current_page: str) -> None:
        """Update user's current page/status"""
        self.user.current_page = current_page
        self.send_message(MessageType.DATA_UPDATE, {
            'key': f'user_status:{self.user.id}',
            'value': {
                'current_page': current_page,
                'last_seen': datetime.now().isoformat()
            }
        })
    
    @property
    def is_connected(self) -> bool:
        return self._connected


class CollaborationServer:
    """
    Simple WebSocket server for collaboration.
    For production, use a proper message broker like Redis.
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.sessions: Dict[str, CollaborationSession] = {}
        self.connections: Dict[str, Set[websockets.WebSocketServerProtocol]] = {}
    
    async def start(self) -> None:
        """Start the collaboration server"""
        server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port
        )
        logger.info(f"Collaboration server started on ws://{self.host}:{self.port}")
        await server.wait_closed()
    
    async def _handle_connection(self, 
                                  websocket: websockets.WebSocketServerProtocol,
                                  path: str) -> None:
        """Handle a new WebSocket connection"""
        session_id = None
        user_id = None
        
        try:
            async for message in websocket:
                msg = CollaborationMessage.from_json(message)
                
                if msg.type == MessageType.JOIN:
                    session_id = msg.data.get('session_id')
                    user_data = msg.data.get('user', {})
                    user_id = user_data.get('id')
                    
                    # Create or get session
                    if session_id not in self.sessions:
                        self.sessions[session_id] = CollaborationSession(
                            id=session_id,
                            name=f"Session {session_id[:8]}",
                            owner_id=user_id
                        )
                        self.connections[session_id] = set()
                    
                    session = self.sessions[session_id]
                    
                    # Check password if private
                    if session.is_private:
                        password_hash = msg.data.get('password')
                        if password_hash != session.password_hash:
                            await websocket.send(CollaborationMessage(
                                type=MessageType.PERMISSION_DENY,
                                sender_id="server",
                                data={'reason': 'Invalid password'}
                            ).to_json())
                            continue
                    
                    # Add user to session
                    user = CollaborationUser(
                        id=user_id,
                        username=user_data.get('username', 'Unknown'),
                        role=UserRole(user_data.get('role', 'viewer'))
                    )
                    session.users[user_id] = user
                    self.connections[session_id].add(websocket)
                    
                    # Send sync response
                    await websocket.send(CollaborationMessage(
                        type=MessageType.SYNC_RESPONSE,
                        sender_id="server",
                        data={
                            'session_name': session.name,
                            'owner_id': session.owner_id,
                            'shared_data': session.shared_data,
                            'chat_history': session.chat_history[-50:],
                            'users': [u.to_dict() for u in session.users.values()]
                        }
                    ).to_json())
                    
                    # Broadcast join to others
                    await self._broadcast(session_id, msg, exclude=websocket)
                    
                elif msg.type == MessageType.LEAVE:
                    if session_id and user_id:
                        session = self.sessions.get(session_id)
                        if session and user_id in session.users:
                            del session.users[user_id]
                        if session_id in self.connections:
                            self.connections[session_id].discard(websocket)
                        await self._broadcast(session_id, msg)
                    
                elif msg.type == MessageType.CHAT:
                    if session_id:
                        session = self.sessions.get(session_id)
                        if session:
                            session.chat_history.append({
                                'sender_id': msg.sender_id,
                                'message': msg.data.get('message', ''),
                                'timestamp': msg.timestamp.isoformat()
                            })
                            # Keep only last 100 messages
                            session.chat_history = session.chat_history[-100:]
                        await self._broadcast(session_id, msg)
                
                elif msg.type in [MessageType.DATA_UPDATE, MessageType.FINDING,
                                 MessageType.SCAN_START, MessageType.SCAN_COMPLETE,
                                 MessageType.TARGET_ADD]:
                    # Broadcast to all session members
                    if session_id:
                        if msg.type == MessageType.DATA_UPDATE:
                            session = self.sessions.get(session_id)
                            if session:
                                key = msg.data.get('key')
                                value = msg.data.get('value')
                                if key:
                                    session.shared_data[key] = value
                        await self._broadcast(session_id, msg)
                
                elif msg.type == MessageType.HEARTBEAT:
                    # Update user last seen
                    if session_id and user_id:
                        session = self.sessions.get(session_id)
                        if session and user_id in session.users:
                            session.users[user_id].last_seen = datetime.now()
                    
        except websockets.ConnectionClosed:
            pass
        finally:
            # Clean up on disconnect
            if session_id and user_id:
                session = self.sessions.get(session_id)
                if session and user_id in session.users:
                    del session.users[user_id]
                if session_id in self.connections:
                    self.connections[session_id].discard(websocket)
                    
                # Broadcast leave
                leave_msg = CollaborationMessage(
                    type=MessageType.LEAVE,
                    sender_id=user_id
                )
                await self._broadcast(session_id, leave_msg)
    
    async def _broadcast(self, session_id: str, 
                         message: CollaborationMessage,
                         exclude: websockets.WebSocketServerProtocol = None) -> None:
        """Broadcast a message to all session members"""
        if session_id not in self.connections:
            return
        
        for ws in self.connections[session_id]:
            if ws != exclude:
                try:
                    await ws.send(message.to_json())
                except websockets.ConnectionClosed:
                    self.connections[session_id].discard(ws)
    
    def create_session(self, name: str, owner_id: str,
                       is_private: bool = False,
                       password: Optional[str] = None) -> str:
        """Create a new collaboration session"""
        session_id = str(uuid.uuid4())
        
        session = CollaborationSession(
            id=session_id,
            name=name,
            owner_id=owner_id,
            is_private=is_private,
            password_hash=hashlib.sha256(password.encode()).hexdigest() if password else None
        )
        
        self.sessions[session_id] = session
        self.connections[session_id] = set()
        
        return session_id


class CollaborationManager:
    """
    High-level manager for collaboration features.
    Used by the application to manage collaboration.
    """
    
    def __init__(self, username: str):
        self.user = CollaborationUser(
            id=str(uuid.uuid4()),
            username=username
        )
        self.client: Optional[CollaborationClient] = None
        self._listeners: Dict[str, List[Callable]] = {}
    
    async def create_session(self, server_url: str,
                             session_name: str = "New Session") -> str:
        """Create and join a new session"""
        self.user.role = UserRole.OWNER
        self.client = CollaborationClient(self.user)
        
        # For simplicity, session ID is generated client-side
        session_id = str(uuid.uuid4())
        
        if await self.client.connect(server_url, session_id):
            return session_id
        return ""
    
    async def join_session(self, server_url: str,
                           session_id: str,
                           password: Optional[str] = None) -> bool:
        """Join an existing session"""
        self.client = CollaborationClient(self.user)
        return await self.client.connect(server_url, session_id, password)
    
    async def leave_session(self) -> None:
        """Leave the current session"""
        if self.client:
            await self.client.disconnect()
            self.client = None
    
    def on_event(self, event: str, handler: Callable) -> None:
        """Register an event handler"""
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(handler)
        
        # Map to message types
        type_mapping = {
            'user_joined': MessageType.JOIN,
            'user_left': MessageType.LEAVE,
            'chat': MessageType.CHAT,
            'finding': MessageType.FINDING,
            'scan_start': MessageType.SCAN_START,
            'scan_complete': MessageType.SCAN_COMPLETE,
            'data_update': MessageType.DATA_UPDATE,
        }
        
        if event in type_mapping and self.client:
            self.client.on_message(type_mapping[event], handler)
    
    def send_chat(self, message: str) -> None:
        """Send a chat message"""
        if self.client:
            self.client.send_chat(message)
    
    def share_finding(self, finding: dict) -> None:
        """Share a finding"""
        if self.client:
            self.client.share_finding(finding)
    
    def notify_scan_start(self, target: str, scan_type: str) -> None:
        """Notify team of scan start"""
        if self.client:
            self.client.share_scan_start(target, scan_type)
    
    def notify_scan_complete(self, target: str, summary: dict) -> None:
        """Notify team of scan completion"""
        if self.client:
            self.client.share_scan_complete(target, summary)
    
    def update_page(self, page: str) -> None:
        """Update current page"""
        if self.client:
            self.client.update_status(page)
    
    def get_users(self) -> List[CollaborationUser]:
        """Get list of connected users"""
        if self.client and self.client.session:
            return list(self.client.session.users.values())
        return []
    
    def get_chat_history(self) -> List[Dict]:
        """Get chat history"""
        if self.client and self.client.session:
            return self.client.session.chat_history
        return []
    
    @property
    def is_connected(self) -> bool:
        return self.client is not None and self.client.is_connected
    
    @property
    def session_id(self) -> Optional[str]:
        if self.client and self.client.session:
            return self.client.session.id
        return None


# Standalone server runner
async def run_server(host: str = "0.0.0.0", port: int = 8765):
    """Run the collaboration server standalone"""
    server = CollaborationServer(host, port)
    await server.start()


if __name__ == "__main__":
    asyncio.run(run_server())
