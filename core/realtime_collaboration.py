"""
HydraRecon Real-time Collaboration System
==========================================

Advanced multi-user collaboration for security operations:
- Real-time synchronized workspaces
- Live cursor and selection sharing
- Voice and video chat integration
- Shared 3D visualization sessions
- Collaborative attack simulations
- Team knowledge base and notes
- Role-based access and permissions
- Conflict resolution for concurrent edits
- Session recording and playback
- Integration with security orchestration
"""

import asyncio
import json
import hashlib
import time
import uuid
import threading
import queue
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from datetime import datetime
from enum import Enum, auto
from abc import ABC, abstractmethod
import numpy as np

# Optional imports for real collaboration
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class CollaborationRole(Enum):
    """User roles in collaboration sessions"""
    OWNER = auto()
    ADMIN = auto()
    ANALYST = auto()
    VIEWER = auto()
    GUEST = auto()


class OperationType(Enum):
    """Types of operations for CRDT"""
    INSERT = auto()
    DELETE = auto()
    UPDATE = auto()
    MOVE = auto()


class SyncState(Enum):
    """Synchronization states"""
    SYNCED = auto()
    SYNCING = auto()
    CONFLICT = auto()
    OFFLINE = auto()


@dataclass
class CollaboratorInfo:
    """Information about a collaborator"""
    user_id: str
    username: str
    display_name: str
    role: CollaborationRole
    avatar_url: Optional[str] = None
    cursor_position: Optional[Dict[str, Any]] = None
    selection: Optional[Dict[str, Any]] = None
    color: str = "#00FF00"
    last_active: float = field(default_factory=time.time)
    status: str = "online"
    camera_position: Optional[List[float]] = None  # For 3D view sync
    audio_enabled: bool = False
    video_enabled: bool = False


@dataclass
class Operation:
    """A single operation in the operational transform"""
    op_id: str
    op_type: OperationType
    user_id: str
    timestamp: float
    path: List[str]  # Document path
    value: Any
    prev_value: Optional[Any] = None
    parent_version: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'op_id': self.op_id,
            'op_type': self.op_type.name,
            'user_id': self.user_id,
            'timestamp': self.timestamp,
            'path': self.path,
            'value': self.value,
            'prev_value': self.prev_value,
            'parent_version': self.parent_version
        }


class VectorClock:
    """Vector clock for causality tracking"""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.clock: Dict[str, int] = {node_id: 0}
    
    def increment(self) -> Dict[str, int]:
        """Increment local clock"""
        self.clock[self.node_id] = self.clock.get(self.node_id, 0) + 1
        return self.clock.copy()
    
    def update(self, other_clock: Dict[str, int]):
        """Update with received clock"""
        for node, time in other_clock.items():
            self.clock[node] = max(self.clock.get(node, 0), time)
        self.increment()
    
    def happens_before(self, other_clock: Dict[str, int]) -> bool:
        """Check if this clock happens before other"""
        all_le = True
        some_lt = False
        
        all_nodes = set(self.clock.keys()) | set(other_clock.keys())
        for node in all_nodes:
            self_time = self.clock.get(node, 0)
            other_time = other_clock.get(node, 0)
            
            if self_time > other_time:
                all_le = False
            if self_time < other_time:
                some_lt = True
        
        return all_le and some_lt
    
    def concurrent_with(self, other_clock: Dict[str, int]) -> bool:
        """Check if events are concurrent"""
        return not self.happens_before(other_clock) and not self._other_happens_before(other_clock)
    
    def _other_happens_before(self, other_clock: Dict[str, int]) -> bool:
        """Check if other happens before this"""
        all_le = True
        some_lt = False
        
        all_nodes = set(self.clock.keys()) | set(other_clock.keys())
        for node in all_nodes:
            self_time = self.clock.get(node, 0)
            other_time = other_clock.get(node, 0)
            
            if other_time > self_time:
                all_le = False
            if other_time < self_time:
                some_lt = True
        
        return all_le and some_lt


class CRDT:
    """Conflict-free Replicated Data Type for collaborative editing"""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.clock = VectorClock(node_id)
        self.state: Dict[str, Any] = {}
        self.tombstones: Set[str] = set()  # Deleted item IDs
        self.history: List[Operation] = []
    
    def generate_id(self) -> str:
        """Generate unique ID for operations"""
        return f"{self.node_id}_{time.time()}_{uuid.uuid4().hex[:8]}"
    
    def insert(self, path: List[str], value: Any) -> Operation:
        """Insert value at path"""
        op = Operation(
            op_id=self.generate_id(),
            op_type=OperationType.INSERT,
            user_id=self.node_id,
            timestamp=time.time(),
            path=path,
            value=value,
            parent_version=len(self.history)
        )
        self._apply_local(op)
        return op
    
    def update(self, path: List[str], value: Any) -> Operation:
        """Update value at path"""
        prev_value = self._get_at_path(path)
        op = Operation(
            op_id=self.generate_id(),
            op_type=OperationType.UPDATE,
            user_id=self.node_id,
            timestamp=time.time(),
            path=path,
            value=value,
            prev_value=prev_value,
            parent_version=len(self.history)
        )
        self._apply_local(op)
        return op
    
    def delete(self, path: List[str]) -> Operation:
        """Delete value at path"""
        prev_value = self._get_at_path(path)
        op = Operation(
            op_id=self.generate_id(),
            op_type=OperationType.DELETE,
            user_id=self.node_id,
            timestamp=time.time(),
            path=path,
            value=None,
            prev_value=prev_value,
            parent_version=len(self.history)
        )
        self._apply_local(op)
        return op
    
    def merge(self, remote_op: Operation) -> bool:
        """Merge remote operation"""
        # Check for conflicts
        if remote_op.op_id in [op.op_id for op in self.history]:
            return False  # Already applied
        
        # Apply using LWW (Last-Writer-Wins) semantics
        self._apply_remote(remote_op)
        return True
    
    def _apply_local(self, op: Operation):
        """Apply local operation"""
        self._set_at_path(op.path, op.value if op.op_type != OperationType.DELETE else None, op.op_type)
        self.history.append(op)
        self.clock.increment()
    
    def _apply_remote(self, op: Operation):
        """Apply remote operation with conflict resolution"""
        if op.op_type == OperationType.DELETE:
            self.tombstones.add('/'.join(op.path))
        elif '/'.join(op.path) not in self.tombstones:
            self._set_at_path(op.path, op.value, op.op_type)
        self.history.append(op)
    
    def _get_at_path(self, path: List[str]) -> Any:
        """Get value at path"""
        current = self.state
        for key in path[:-1]:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current.get(path[-1]) if isinstance(current, dict) and path else current
    
    def _set_at_path(self, path: List[str], value: Any, op_type: OperationType):
        """Set value at path"""
        if not path:
            return
        
        current = self.state
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        if op_type == OperationType.DELETE:
            current.pop(path[-1], None)
        else:
            current[path[-1]] = value


class PresenceTracker:
    """Track user presence and activity"""
    
    def __init__(self):
        self.users: Dict[str, CollaboratorInfo] = {}
        self.callbacks: List[Callable] = []
        self.heartbeat_interval = 5.0  # seconds
        self.timeout = 30.0  # seconds before marking offline
    
    def add_user(self, user_info: CollaboratorInfo):
        """Add or update user"""
        user_info.last_active = time.time()
        self.users[user_info.user_id] = user_info
        self._notify('user_joined', user_info)
    
    def remove_user(self, user_id: str):
        """Remove user"""
        if user_id in self.users:
            user = self.users.pop(user_id)
            self._notify('user_left', user)
    
    def update_cursor(self, user_id: str, position: Dict[str, Any]):
        """Update user cursor position"""
        if user_id in self.users:
            self.users[user_id].cursor_position = position
            self.users[user_id].last_active = time.time()
            self._notify('cursor_update', self.users[user_id])
    
    def update_selection(self, user_id: str, selection: Dict[str, Any]):
        """Update user selection"""
        if user_id in self.users:
            self.users[user_id].selection = selection
            self.users[user_id].last_active = time.time()
            self._notify('selection_update', self.users[user_id])
    
    def update_camera(self, user_id: str, camera_position: List[float]):
        """Update user's 3D camera position"""
        if user_id in self.users:
            self.users[user_id].camera_position = camera_position
            self.users[user_id].last_active = time.time()
            self._notify('camera_update', self.users[user_id])
    
    def heartbeat(self, user_id: str):
        """Update user heartbeat"""
        if user_id in self.users:
            self.users[user_id].last_active = time.time()
            self.users[user_id].status = "online"
    
    def check_timeouts(self):
        """Check for timed out users"""
        current_time = time.time()
        for user_id, user in list(self.users.items()):
            if current_time - user.last_active > self.timeout:
                user.status = "offline"
                self._notify('user_timeout', user)
    
    def on_change(self, callback: Callable):
        """Register presence change callback"""
        self.callbacks.append(callback)
    
    def _notify(self, event: str, data: Any):
        """Notify callbacks"""
        for callback in self.callbacks:
            try:
                callback(event, data)
            except Exception:
                pass


class MessageBus:
    """Pub/Sub message bus for real-time communication"""
    
    def __init__(self):
        self.channels: Dict[str, List[Callable]] = {}
        self.message_queue: queue.Queue = queue.Queue()
        self.running = False
        self._worker_thread: Optional[threading.Thread] = None
    
    def subscribe(self, channel: str, callback: Callable):
        """Subscribe to channel"""
        if channel not in self.channels:
            self.channels[channel] = []
        self.channels[channel].append(callback)
    
    def unsubscribe(self, channel: str, callback: Callable):
        """Unsubscribe from channel"""
        if channel in self.channels:
            self.channels[channel] = [cb for cb in self.channels[channel] if cb != callback]
    
    def publish(self, channel: str, message: Any):
        """Publish message to channel"""
        self.message_queue.put((channel, message))
    
    def start(self):
        """Start message processing"""
        self.running = True
        self._worker_thread = threading.Thread(target=self._process_messages, daemon=True)
        self._worker_thread.start()
    
    def stop(self):
        """Stop message processing"""
        self.running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=1.0)
    
    def _process_messages(self):
        """Process messages in queue"""
        while self.running:
            try:
                channel, message = self.message_queue.get(timeout=0.1)
                if channel in self.channels:
                    for callback in self.channels[channel]:
                        try:
                            callback(message)
                        except Exception:
                            pass
            except queue.Empty:
                continue


class CollaborationSession:
    """A collaborative session for multiple users"""
    
    def __init__(self, session_id: str, owner_id: str):
        self.session_id = session_id
        self.owner_id = owner_id
        self.created_at = datetime.now()
        self.name = f"Session {session_id[:8]}"
        self.description = ""
        
        # Collaboration components
        self.crdt = CRDT(owner_id)
        self.presence = PresenceTracker()
        self.message_bus = MessageBus()
        
        # Session state
        self.shared_state: Dict[str, Any] = {
            'targets': [],
            'findings': [],
            'notes': [],
            'markers': [],
            'annotations': []
        }
        
        # Permissions
        self.permissions: Dict[str, CollaborationRole] = {owner_id: CollaborationRole.OWNER}
        
        # Recording
        self.recording = False
        self.recorded_events: List[Dict] = []
        
        # Voice/Video
        self.voice_channels: Dict[str, List[str]] = {}  # channel_id -> user_ids
        
        self.message_bus.start()
    
    def join(self, user_info: CollaboratorInfo) -> bool:
        """User joins session"""
        if user_info.user_id not in self.permissions:
            self.permissions[user_info.user_id] = CollaborationRole.ANALYST
        
        user_info.role = self.permissions[user_info.user_id]
        self.presence.add_user(user_info)
        
        # Notify others
        self.message_bus.publish('user_events', {
            'type': 'user_joined',
            'user': asdict(user_info)
        })
        
        # Record if recording
        if self.recording:
            self.recorded_events.append({
                'type': 'user_joined',
                'user_id': user_info.user_id,
                'timestamp': time.time()
            })
        
        return True
    
    def leave(self, user_id: str):
        """User leaves session"""
        self.presence.remove_user(user_id)
        
        self.message_bus.publish('user_events', {
            'type': 'user_left',
            'user_id': user_id
        })
        
        if self.recording:
            self.recorded_events.append({
                'type': 'user_left',
                'user_id': user_id,
                'timestamp': time.time()
            })
    
    def update_shared_state(self, path: List[str], value: Any, user_id: str) -> Operation:
        """Update shared state with CRDT"""
        if not self._can_edit(user_id):
            raise PermissionError("User cannot edit")
        
        op = self.crdt.update(path, value)
        
        # Update local shared state
        self._apply_to_shared_state(path, value)
        
        # Broadcast
        self.message_bus.publish('state_updates', {
            'type': 'state_update',
            'operation': op.to_dict(),
            'user_id': user_id
        })
        
        return op
    
    def add_target(self, target: Dict[str, Any], user_id: str) -> str:
        """Add scan target"""
        target_id = str(uuid.uuid4())
        target['id'] = target_id
        target['added_by'] = user_id
        target['added_at'] = time.time()
        
        self.shared_state['targets'].append(target)
        
        self.message_bus.publish('targets', {
            'type': 'target_added',
            'target': target,
            'user_id': user_id
        })
        
        return target_id
    
    def add_finding(self, finding: Dict[str, Any], user_id: str) -> str:
        """Add security finding"""
        finding_id = str(uuid.uuid4())
        finding['id'] = finding_id
        finding['found_by'] = user_id
        finding['found_at'] = time.time()
        finding['status'] = 'new'
        
        self.shared_state['findings'].append(finding)
        
        self.message_bus.publish('findings', {
            'type': 'finding_added',
            'finding': finding,
            'user_id': user_id
        })
        
        return finding_id
    
    def add_note(self, note: Dict[str, Any], user_id: str) -> str:
        """Add collaborative note"""
        note_id = str(uuid.uuid4())
        note['id'] = note_id
        note['author'] = user_id
        note['created_at'] = time.time()
        note['updated_at'] = time.time()
        
        self.shared_state['notes'].append(note)
        
        self.message_bus.publish('notes', {
            'type': 'note_added',
            'note': note,
            'user_id': user_id
        })
        
        return note_id
    
    def add_3d_marker(self, marker: Dict[str, Any], user_id: str) -> str:
        """Add 3D visualization marker"""
        marker_id = str(uuid.uuid4())
        marker['id'] = marker_id
        marker['created_by'] = user_id
        marker['created_at'] = time.time()
        
        self.shared_state['markers'].append(marker)
        
        self.message_bus.publish('visualization', {
            'type': 'marker_added',
            'marker': marker,
            'user_id': user_id
        })
        
        return marker_id
    
    def broadcast_cursor(self, user_id: str, position: Dict[str, Any]):
        """Broadcast cursor position"""
        self.presence.update_cursor(user_id, position)
        
        self.message_bus.publish('cursors', {
            'type': 'cursor_move',
            'user_id': user_id,
            'position': position
        })
    
    def broadcast_camera(self, user_id: str, camera: Dict[str, Any]):
        """Broadcast 3D camera position"""
        self.presence.update_camera(user_id, camera.get('position', [0, 0, 0]))
        
        self.message_bus.publish('cameras', {
            'type': 'camera_update',
            'user_id': user_id,
            'camera': camera
        })
    
    def start_recording(self):
        """Start session recording"""
        self.recording = True
        self.recorded_events = []
        self.recorded_events.append({
            'type': 'recording_started',
            'timestamp': time.time(),
            'initial_state': self.shared_state.copy()
        })
    
    def stop_recording(self) -> List[Dict]:
        """Stop recording and return events"""
        self.recording = False
        self.recorded_events.append({
            'type': 'recording_stopped',
            'timestamp': time.time()
        })
        return self.recorded_events
    
    def _can_edit(self, user_id: str) -> bool:
        """Check if user can edit"""
        role = self.permissions.get(user_id, CollaborationRole.GUEST)
        return role in [CollaborationRole.OWNER, CollaborationRole.ADMIN, CollaborationRole.ANALYST]
    
    def _apply_to_shared_state(self, path: List[str], value: Any):
        """Apply update to shared state"""
        current = self.shared_state
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        if path:
            current[path[-1]] = value
    
    def get_state_snapshot(self) -> Dict[str, Any]:
        """Get current state snapshot"""
        return {
            'session_id': self.session_id,
            'name': self.name,
            'owner_id': self.owner_id,
            'created_at': self.created_at.isoformat(),
            'users': [asdict(u) for u in self.presence.users.values()],
            'shared_state': self.shared_state,
            'recording': self.recording
        }


class CollaborationServer:
    """WebSocket server for real-time collaboration"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.sessions: Dict[str, CollaborationSession] = {}
        self.connections: Dict[str, Any] = {}  # user_id -> websocket
        self.user_sessions: Dict[str, str] = {}  # user_id -> session_id
        self.running = False
        
        # Encryption
        self.encryption_key: Optional[bytes] = None
        if CRYPTO_AVAILABLE:
            self.encryption_key = Fernet.generate_key()
            self.cipher = Fernet(self.encryption_key)
    
    async def start(self):
        """Start collaboration server"""
        if not WEBSOCKETS_AVAILABLE:
            raise RuntimeError("websockets package not available")
        
        self.running = True
        async with websockets.serve(self._handle_connection, self.host, self.port):
            await asyncio.Future()  # Run forever
    
    def stop(self):
        """Stop server"""
        self.running = False
    
    async def _handle_connection(self, websocket, path):
        """Handle new WebSocket connection"""
        user_id = None
        try:
            # Authenticate
            auth_msg = await websocket.recv()
            auth_data = json.loads(auth_msg)
            
            user_id = auth_data.get('user_id')
            if not user_id:
                await websocket.close(1008, "Authentication required")
                return
            
            self.connections[user_id] = websocket
            
            # Handle messages
            async for message in websocket:
                await self._handle_message(user_id, message)
        
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if user_id:
                self._cleanup_user(user_id)
    
    async def _handle_message(self, user_id: str, message: str):
        """Handle incoming message"""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'create_session':
                await self._create_session(user_id, data)
            elif msg_type == 'join_session':
                await self._join_session(user_id, data)
            elif msg_type == 'leave_session':
                await self._leave_session(user_id)
            elif msg_type == 'state_update':
                await self._handle_state_update(user_id, data)
            elif msg_type == 'cursor_update':
                await self._broadcast_cursor(user_id, data)
            elif msg_type == 'camera_update':
                await self._broadcast_camera(user_id, data)
            elif msg_type == 'chat_message':
                await self._broadcast_chat(user_id, data)
            elif msg_type == 'add_target':
                await self._add_target(user_id, data)
            elif msg_type == 'add_finding':
                await self._add_finding(user_id, data)
        
        except json.JSONDecodeError:
            pass
    
    async def _create_session(self, user_id: str, data: Dict):
        """Create new session"""
        session_id = str(uuid.uuid4())
        session = CollaborationSession(session_id, user_id)
        session.name = data.get('name', f"Session {session_id[:8]}")
        
        self.sessions[session_id] = session
        self.user_sessions[user_id] = session_id
        
        # Add owner
        user_info = CollaboratorInfo(
            user_id=user_id,
            username=data.get('username', user_id),
            display_name=data.get('display_name', user_id),
            role=CollaborationRole.OWNER,
            color=data.get('color', '#00FF00')
        )
        session.join(user_info)
        
        await self._send(user_id, {
            'type': 'session_created',
            'session_id': session_id,
            'state': session.get_state_snapshot()
        })
    
    async def _join_session(self, user_id: str, data: Dict):
        """Join existing session"""
        session_id = data.get('session_id')
        if session_id not in self.sessions:
            await self._send(user_id, {'type': 'error', 'message': 'Session not found'})
            return
        
        session = self.sessions[session_id]
        self.user_sessions[user_id] = session_id
        
        user_info = CollaboratorInfo(
            user_id=user_id,
            username=data.get('username', user_id),
            display_name=data.get('display_name', user_id),
            role=CollaborationRole.ANALYST,
            color=data.get('color', '#00FF00')
        )
        session.join(user_info)
        
        # Send state to new user
        await self._send(user_id, {
            'type': 'session_joined',
            'session_id': session_id,
            'state': session.get_state_snapshot()
        })
        
        # Notify others
        await self._broadcast_to_session(session_id, {
            'type': 'user_joined',
            'user': asdict(user_info)
        }, exclude=user_id)
    
    async def _leave_session(self, user_id: str):
        """Leave session"""
        session_id = self.user_sessions.get(user_id)
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            session.leave(user_id)
            del self.user_sessions[user_id]
            
            await self._broadcast_to_session(session_id, {
                'type': 'user_left',
                'user_id': user_id
            })
    
    async def _handle_state_update(self, user_id: str, data: Dict):
        """Handle state update"""
        session_id = self.user_sessions.get(user_id)
        if not session_id or session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        path = data.get('path', [])
        value = data.get('value')
        
        try:
            op = session.update_shared_state(path, value, user_id)
            
            await self._broadcast_to_session(session_id, {
                'type': 'state_update',
                'operation': op.to_dict(),
                'user_id': user_id
            }, exclude=user_id)
        
        except PermissionError:
            await self._send(user_id, {'type': 'error', 'message': 'Permission denied'})
    
    async def _broadcast_cursor(self, user_id: str, data: Dict):
        """Broadcast cursor position"""
        session_id = self.user_sessions.get(user_id)
        if session_id:
            await self._broadcast_to_session(session_id, {
                'type': 'cursor_update',
                'user_id': user_id,
                'position': data.get('position')
            }, exclude=user_id)
    
    async def _broadcast_camera(self, user_id: str, data: Dict):
        """Broadcast camera position"""
        session_id = self.user_sessions.get(user_id)
        if session_id:
            await self._broadcast_to_session(session_id, {
                'type': 'camera_update',
                'user_id': user_id,
                'camera': data.get('camera')
            }, exclude=user_id)
    
    async def _broadcast_chat(self, user_id: str, data: Dict):
        """Broadcast chat message"""
        session_id = self.user_sessions.get(user_id)
        if session_id:
            await self._broadcast_to_session(session_id, {
                'type': 'chat_message',
                'user_id': user_id,
                'message': data.get('message'),
                'timestamp': time.time()
            })
    
    async def _add_target(self, user_id: str, data: Dict):
        """Add target to session"""
        session_id = self.user_sessions.get(user_id)
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            target_id = session.add_target(data.get('target', {}), user_id)
            
            await self._broadcast_to_session(session_id, {
                'type': 'target_added',
                'target_id': target_id,
                'target': data.get('target'),
                'user_id': user_id
            })
    
    async def _add_finding(self, user_id: str, data: Dict):
        """Add finding to session"""
        session_id = self.user_sessions.get(user_id)
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            finding_id = session.add_finding(data.get('finding', {}), user_id)
            
            await self._broadcast_to_session(session_id, {
                'type': 'finding_added',
                'finding_id': finding_id,
                'finding': data.get('finding'),
                'user_id': user_id
            })
    
    async def _send(self, user_id: str, data: Dict):
        """Send message to user"""
        if user_id in self.connections:
            try:
                message = json.dumps(data)
                if self.encryption_key:
                    message = self.cipher.encrypt(message.encode()).decode()
                await self.connections[user_id].send(message)
            except Exception:
                pass
    
    async def _broadcast_to_session(self, session_id: str, data: Dict, exclude: Optional[str] = None):
        """Broadcast to all users in session"""
        for uid, sid in self.user_sessions.items():
            if sid == session_id and uid != exclude:
                await self._send(uid, data)
    
    def _cleanup_user(self, user_id: str):
        """Clean up user on disconnect"""
        if user_id in self.connections:
            del self.connections[user_id]
        
        session_id = self.user_sessions.get(user_id)
        if session_id and session_id in self.sessions:
            self.sessions[session_id].leave(user_id)
        
        if user_id in self.user_sessions:
            del self.user_sessions[user_id]


class CollaborationClient:
    """Client for connecting to collaboration sessions"""
    
    def __init__(self, server_url: str, user_id: str, username: str):
        self.server_url = server_url
        self.user_id = user_id
        self.username = username
        self.websocket = None
        self.session_id: Optional[str] = None
        self.local_state: Dict[str, Any] = {}
        
        # Callbacks
        self.on_user_joined: Optional[Callable] = None
        self.on_user_left: Optional[Callable] = None
        self.on_state_update: Optional[Callable] = None
        self.on_cursor_update: Optional[Callable] = None
        self.on_camera_update: Optional[Callable] = None
        self.on_chat_message: Optional[Callable] = None
        self.on_target_added: Optional[Callable] = None
        self.on_finding_added: Optional[Callable] = None
        
        self._receive_task: Optional[asyncio.Task] = None
    
    async def connect(self):
        """Connect to server"""
        if not WEBSOCKETS_AVAILABLE:
            raise RuntimeError("websockets package not available")
        
        self.websocket = await websockets.connect(self.server_url)
        
        # Authenticate
        await self.websocket.send(json.dumps({
            'user_id': self.user_id,
            'username': self.username
        }))
        
        # Start receiving
        self._receive_task = asyncio.create_task(self._receive_loop())
    
    async def disconnect(self):
        """Disconnect from server"""
        if self._receive_task:
            self._receive_task.cancel()
        if self.websocket:
            await self.websocket.close()
    
    async def create_session(self, name: str = None, color: str = "#00FF00") -> str:
        """Create new session"""
        await self._send({
            'type': 'create_session',
            'name': name,
            'username': self.username,
            'display_name': self.username,
            'color': color
        })
        
        # Wait for response
        response = await self._receive_one()
        if response.get('type') == 'session_created':
            self.session_id = response['session_id']
            self.local_state = response.get('state', {}).get('shared_state', {})
            return self.session_id
        raise RuntimeError("Failed to create session")
    
    async def join_session(self, session_id: str, color: str = "#00FF00") -> Dict:
        """Join existing session"""
        await self._send({
            'type': 'join_session',
            'session_id': session_id,
            'username': self.username,
            'display_name': self.username,
            'color': color
        })
        
        response = await self._receive_one()
        if response.get('type') == 'session_joined':
            self.session_id = session_id
            self.local_state = response.get('state', {}).get('shared_state', {})
            return response.get('state', {})
        raise RuntimeError("Failed to join session")
    
    async def leave_session(self):
        """Leave current session"""
        await self._send({'type': 'leave_session'})
        self.session_id = None
    
    async def update_state(self, path: List[str], value: Any):
        """Update shared state"""
        await self._send({
            'type': 'state_update',
            'path': path,
            'value': value
        })
    
    async def send_cursor(self, position: Dict[str, Any]):
        """Send cursor position"""
        await self._send({
            'type': 'cursor_update',
            'position': position
        })
    
    async def send_camera(self, camera: Dict[str, Any]):
        """Send camera position"""
        await self._send({
            'type': 'camera_update',
            'camera': camera
        })
    
    async def send_chat(self, message: str):
        """Send chat message"""
        await self._send({
            'type': 'chat_message',
            'message': message
        })
    
    async def add_target(self, target: Dict[str, Any]):
        """Add target"""
        await self._send({
            'type': 'add_target',
            'target': target
        })
    
    async def add_finding(self, finding: Dict[str, Any]):
        """Add finding"""
        await self._send({
            'type': 'add_finding',
            'finding': finding
        })
    
    async def _send(self, data: Dict):
        """Send message"""
        if self.websocket:
            await self.websocket.send(json.dumps(data))
    
    async def _receive_one(self) -> Dict:
        """Receive single message"""
        if self.websocket:
            message = await self.websocket.recv()
            return json.loads(message)
        return {}
    
    async def _receive_loop(self):
        """Receive messages loop"""
        try:
            while True:
                message = await self._receive_one()
                self._handle_message(message)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
    
    def _handle_message(self, message: Dict):
        """Handle received message"""
        msg_type = message.get('type')
        
        if msg_type == 'user_joined' and self.on_user_joined:
            self.on_user_joined(message.get('user'))
        elif msg_type == 'user_left' and self.on_user_left:
            self.on_user_left(message.get('user_id'))
        elif msg_type == 'state_update' and self.on_state_update:
            self.on_state_update(message.get('operation'), message.get('user_id'))
        elif msg_type == 'cursor_update' and self.on_cursor_update:
            self.on_cursor_update(message.get('user_id'), message.get('position'))
        elif msg_type == 'camera_update' and self.on_camera_update:
            self.on_camera_update(message.get('user_id'), message.get('camera'))
        elif msg_type == 'chat_message' and self.on_chat_message:
            self.on_chat_message(message.get('user_id'), message.get('message'), message.get('timestamp'))
        elif msg_type == 'target_added' and self.on_target_added:
            self.on_target_added(message.get('target'), message.get('user_id'))
        elif msg_type == 'finding_added' and self.on_finding_added:
            self.on_finding_added(message.get('finding'), message.get('user_id'))


class SharedVisualization:
    """Shared 3D visualization state"""
    
    def __init__(self, session: CollaborationSession):
        self.session = session
        self.view_state: Dict[str, Any] = {
            'camera': {'position': [0, 0, 10], 'rotation': [0, 0, 0]},
            'zoom': 1.0,
            'selected_nodes': [],
            'highlighted_paths': [],
            'visible_layers': ['all'],
            'annotations': [],
            'shared_pointers': {}
        }
        
        # Subscribe to visualization events
        session.message_bus.subscribe('visualization', self._on_visualization_event)
    
    def sync_camera(self, user_id: str, camera: Dict[str, Any]):
        """Sync camera position"""
        self.view_state['shared_pointers'][user_id] = camera
        self.session.broadcast_camera(user_id, camera)
    
    def add_annotation(self, annotation: Dict[str, Any], user_id: str) -> str:
        """Add 3D annotation"""
        annotation_id = str(uuid.uuid4())
        annotation['id'] = annotation_id
        annotation['author'] = user_id
        annotation['created_at'] = time.time()
        
        self.view_state['annotations'].append(annotation)
        
        self.session.message_bus.publish('visualization', {
            'type': 'annotation_added',
            'annotation': annotation
        })
        
        return annotation_id
    
    def highlight_path(self, path_nodes: List[str], color: str, user_id: str):
        """Highlight path for all users"""
        highlight = {
            'id': str(uuid.uuid4()),
            'nodes': path_nodes,
            'color': color,
            'highlighted_by': user_id
        }
        
        self.view_state['highlighted_paths'].append(highlight)
        
        self.session.message_bus.publish('visualization', {
            'type': 'path_highlighted',
            'highlight': highlight
        })
    
    def select_nodes(self, node_ids: List[str], user_id: str):
        """Select nodes for all to see"""
        self.view_state['selected_nodes'] = node_ids
        
        self.session.message_bus.publish('visualization', {
            'type': 'nodes_selected',
            'nodes': node_ids,
            'selected_by': user_id
        })
    
    def _on_visualization_event(self, event: Dict):
        """Handle visualization event"""
        pass  # Override in subclass


class TeamKnowledgeBase:
    """Shared knowledge base for security teams"""
    
    def __init__(self):
        self.articles: Dict[str, Dict] = {}
        self.tags: Dict[str, Set[str]] = {}  # tag -> article_ids
        self.search_index: Dict[str, Set[str]] = {}  # word -> article_ids
    
    def add_article(self, title: str, content: str, author: str, tags: List[str] = None) -> str:
        """Add knowledge article"""
        article_id = str(uuid.uuid4())
        
        article = {
            'id': article_id,
            'title': title,
            'content': content,
            'author': author,
            'created_at': time.time(),
            'updated_at': time.time(),
            'tags': tags or [],
            'views': 0,
            'helpful_votes': 0,
            'comments': []
        }
        
        self.articles[article_id] = article
        
        # Index tags
        for tag in article['tags']:
            if tag not in self.tags:
                self.tags[tag] = set()
            self.tags[tag].add(article_id)
        
        # Index words
        self._index_article(article_id, title + " " + content)
        
        return article_id
    
    def search(self, query: str) -> List[Dict]:
        """Search articles"""
        words = query.lower().split()
        matching_ids: Optional[Set[str]] = None
        
        for word in words:
            if word in self.search_index:
                if matching_ids is None:
                    matching_ids = self.search_index[word].copy()
                else:
                    matching_ids &= self.search_index[word]
        
        if not matching_ids:
            return []
        
        return [self.articles[aid] for aid in matching_ids if aid in self.articles]
    
    def get_by_tag(self, tag: str) -> List[Dict]:
        """Get articles by tag"""
        if tag not in self.tags:
            return []
        return [self.articles[aid] for aid in self.tags[tag] if aid in self.articles]
    
    def add_comment(self, article_id: str, comment: str, author: str):
        """Add comment to article"""
        if article_id in self.articles:
            self.articles[article_id]['comments'].append({
                'id': str(uuid.uuid4()),
                'content': comment,
                'author': author,
                'created_at': time.time()
            })
    
    def vote_helpful(self, article_id: str):
        """Vote article as helpful"""
        if article_id in self.articles:
            self.articles[article_id]['helpful_votes'] += 1
    
    def _index_article(self, article_id: str, text: str):
        """Index article for search"""
        words = set(text.lower().split())
        for word in words:
            if len(word) > 2:  # Skip short words
                if word not in self.search_index:
                    self.search_index[word] = set()
                self.search_index[word].add(article_id)


class CollaborationManager:
    """Main manager for collaboration features"""
    
    def __init__(self):
        self.server: Optional[CollaborationServer] = None
        self.client: Optional[CollaborationClient] = None
        self.current_session: Optional[CollaborationSession] = None
        self.knowledge_base = TeamKnowledgeBase()
        
        # Local user info
        self.user_id = str(uuid.uuid4())
        self.username = "User"
        self.display_name = "User"
        self.user_color = self._generate_user_color()
    
    def _generate_user_color(self) -> str:
        """Generate unique user color"""
        colors = [
            "#FF0080", "#00FF80", "#8000FF", "#FF8000",
            "#00FFFF", "#FF00FF", "#80FF00", "#0080FF"
        ]
        return colors[hash(self.user_id) % len(colors)]
    
    def start_server(self, port: int = 8765):
        """Start collaboration server"""
        self.server = CollaborationServer(port=port)
        
        # Run in background
        thread = threading.Thread(
            target=lambda: asyncio.run(self.server.start()),
            daemon=True
        )
        thread.start()
    
    def create_local_session(self, name: str = None) -> CollaborationSession:
        """Create local session (no server)"""
        session_id = str(uuid.uuid4())
        self.current_session = CollaborationSession(session_id, self.user_id)
        
        if name:
            self.current_session.name = name
        
        # Join as owner
        user_info = CollaboratorInfo(
            user_id=self.user_id,
            username=self.username,
            display_name=self.display_name,
            role=CollaborationRole.OWNER,
            color=self.user_color
        )
        self.current_session.join(user_info)
        
        return self.current_session
    
    async def connect_to_server(self, server_url: str):
        """Connect to remote server"""
        self.client = CollaborationClient(server_url, self.user_id, self.username)
        await self.client.connect()
    
    async def create_remote_session(self, name: str = None) -> str:
        """Create session on remote server"""
        if not self.client:
            raise RuntimeError("Not connected to server")
        return await self.client.create_session(name, self.user_color)
    
    async def join_remote_session(self, session_id: str) -> Dict:
        """Join remote session"""
        if not self.client:
            raise RuntimeError("Not connected to server")
        return await self.client.join_session(session_id, self.user_color)
    
    def get_session_invite_link(self) -> Optional[str]:
        """Get invite link for current session"""
        if self.current_session:
            return f"hydra://session/{self.current_session.session_id}"
        return None
    
    def export_session_state(self) -> Dict[str, Any]:
        """Export current session state"""
        if self.current_session:
            return self.current_session.get_state_snapshot()
        return {}
    
    def import_session_state(self, state: Dict[str, Any]):
        """Import session state"""
        if self.current_session:
            self.current_session.shared_state = state.get('shared_state', {})


# Global instance
collaboration_manager = CollaborationManager()


def get_collaboration_manager() -> CollaborationManager:
    """Get global collaboration manager"""
    return collaboration_manager
