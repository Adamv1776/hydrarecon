"""
HydraRecon Attack Replay System
Record, replay, and analyze entire pentest sessions like a DVR
"""

import asyncio
import json
import sqlite3
import gzip
import base64
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, AsyncGenerator
from enum import Enum
import hashlib
import uuid


class EventType(Enum):
    """Types of recorded events"""
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    FINDING_DISCOVERED = "finding_discovered"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_SUCCESS = "exploit_success"
    EXPLOIT_FAILED = "exploit_failed"
    SHELL_COMMAND = "shell_command"
    FILE_OPERATION = "file_operation"
    NETWORK_TRAFFIC = "network_traffic"
    CREDENTIAL_CAPTURED = "credential_captured"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfil"
    USER_ACTION = "user_action"
    SYSTEM_EVENT = "system_event"
    NOTE_ADDED = "note_added"
    SCREENSHOT = "screenshot"
    MARKER = "marker"


class RecordingState(Enum):
    """State of a recording"""
    RECORDING = "recording"
    PAUSED = "paused"
    STOPPED = "stopped"
    CORRUPTED = "corrupted"


class PlaybackState(Enum):
    """State of playback"""
    PLAYING = "playing"
    PAUSED = "paused"
    STOPPED = "stopped"
    SEEKING = "seeking"
    BUFFERING = "buffering"


@dataclass
class RecordedEvent:
    """A single recorded event"""
    event_id: str
    session_id: str
    timestamp: datetime
    event_type: EventType
    source: str
    target: str
    data: Dict[str, Any]
    duration_ms: int = 0
    success: bool = True
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    screenshot: Optional[bytes] = None
    parent_event_id: Optional[str] = None


@dataclass
class RecordingSession:
    """A complete recording session"""
    session_id: str
    name: str
    description: str
    created_at: datetime
    started_at: datetime
    ended_at: Optional[datetime]
    state: RecordingState
    operator: str
    target_scope: List[str]
    event_count: int = 0
    duration_seconds: float = 0.0
    findings_count: int = 0
    critical_findings: int = 0
    exploits_attempted: int = 0
    exploits_successful: int = 0
    data_size_bytes: int = 0
    compression_ratio: float = 1.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybackPosition:
    """Current playback position"""
    session_id: str
    current_event_id: str
    current_timestamp: datetime
    events_played: int
    total_events: int
    elapsed_seconds: float
    remaining_seconds: float
    speed: float = 1.0


@dataclass
class SessionMarker:
    """Bookmark/marker in a session"""
    marker_id: str
    session_id: str
    timestamp: datetime
    event_id: str
    label: str
    description: str
    marker_type: str  # "finding", "exploit", "important", "question", etc.
    color: str = "#00ff00"


@dataclass
class TimelineSegment:
    """A segment of the session timeline"""
    start_time: datetime
    end_time: datetime
    event_count: int
    event_types: Dict[str, int]
    has_findings: bool
    has_exploits: bool
    highlight: bool = False


class AttackReplaySystem:
    """
    Record and replay entire pentest sessions
    
    Features:
    - Full session recording with compression
    - DVR-style playback controls
    - Timeline navigation with markers
    - Event filtering and search
    - Session comparison
    - Export to multiple formats
    - Real-time annotation
    """
    
    def __init__(self, db_path: str = "attack_replay.db"):
        self.db_path = db_path
        self.active_recordings: Dict[str, RecordingSession] = {}
        self.event_buffer: Dict[str, List[RecordedEvent]] = {}
        self.playback_callbacks: List[Callable] = []
        self.recording_callbacks: List[Callable] = []
        self.buffer_size = 1000
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize the replay database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recording_sessions (
                session_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP,
                started_at TIMESTAMP,
                ended_at TIMESTAMP,
                state TEXT,
                operator TEXT,
                target_scope TEXT,
                event_count INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                critical_findings INTEGER DEFAULT 0,
                exploits_attempted INTEGER DEFAULT 0,
                exploits_successful INTEGER DEFAULT 0,
                data_size_bytes INTEGER DEFAULT 0,
                compression_ratio REAL DEFAULT 1.0,
                tags TEXT,
                metadata TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recorded_events (
                event_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                timestamp TIMESTAMP,
                event_type TEXT,
                source TEXT,
                target TEXT,
                data TEXT,
                duration_ms INTEGER DEFAULT 0,
                success INTEGER DEFAULT 1,
                notes TEXT,
                tags TEXT,
                screenshot BLOB,
                parent_event_id TEXT,
                FOREIGN KEY (session_id) REFERENCES recording_sessions(session_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_markers (
                marker_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                timestamp TIMESTAMP,
                event_id TEXT,
                label TEXT,
                description TEXT,
                marker_type TEXT,
                color TEXT,
                FOREIGN KEY (session_id) REFERENCES recording_sessions(session_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_session ON recorded_events(session_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON recorded_events(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_type ON recorded_events(event_type)
        """)
        
        conn.commit()
        conn.close()
    
    async def start_recording(self, name: str, operator: str,
                             target_scope: List[str] = None,
                             description: str = "") -> RecordingSession:
        """Start a new recording session"""
        session = RecordingSession(
            session_id=str(uuid.uuid4()),
            name=name,
            description=description,
            created_at=datetime.now(),
            started_at=datetime.now(),
            ended_at=None,
            state=RecordingState.RECORDING,
            operator=operator,
            target_scope=target_scope or []
        )
        
        self.active_recordings[session.session_id] = session
        self.event_buffer[session.session_id] = []
        
        # Persist to database
        await self._persist_session(session)
        
        # Notify callbacks
        for callback in self.recording_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback("recording_started", session)
                else:
                    callback("recording_started", session)
            except Exception as e:
                print(f"Recording callback error: {e}")
        
        return session
    
    async def stop_recording(self, session_id: str) -> RecordingSession:
        """Stop a recording session"""
        if session_id not in self.active_recordings:
            raise ValueError("Session not found")
        
        session = self.active_recordings[session_id]
        session.ended_at = datetime.now()
        session.state = RecordingState.STOPPED
        session.duration_seconds = (session.ended_at - session.started_at).total_seconds()
        
        # Flush event buffer
        await self._flush_buffer(session_id)
        
        # Update session in database
        await self._persist_session(session)
        
        # Remove from active recordings
        del self.active_recordings[session_id]
        if session_id in self.event_buffer:
            del self.event_buffer[session_id]
        
        return session
    
    async def pause_recording(self, session_id: str) -> bool:
        """Pause a recording"""
        if session_id not in self.active_recordings:
            return False
        
        self.active_recordings[session_id].state = RecordingState.PAUSED
        await self._flush_buffer(session_id)
        return True
    
    async def resume_recording(self, session_id: str) -> bool:
        """Resume a paused recording"""
        if session_id not in self.active_recordings:
            return False
        
        self.active_recordings[session_id].state = RecordingState.RECORDING
        return True
    
    async def record_event(self, session_id: str, event_type: EventType,
                          source: str, target: str, data: Dict[str, Any],
                          duration_ms: int = 0, success: bool = True,
                          notes: str = "", tags: List[str] = None,
                          screenshot: bytes = None,
                          parent_event_id: str = None) -> Optional[RecordedEvent]:
        """Record an event to the session"""
        if session_id not in self.active_recordings:
            return None
        
        session = self.active_recordings[session_id]
        if session.state != RecordingState.RECORDING:
            return None
        
        event = RecordedEvent(
            event_id=str(uuid.uuid4()),
            session_id=session_id,
            timestamp=datetime.now(),
            event_type=event_type,
            source=source,
            target=target,
            data=data,
            duration_ms=duration_ms,
            success=success,
            notes=notes,
            tags=tags or [],
            screenshot=screenshot,
            parent_event_id=parent_event_id
        )
        
        # Update session counters
        session.event_count += 1
        if event_type == EventType.FINDING_DISCOVERED:
            session.findings_count += 1
            if data.get("severity") == "critical":
                session.critical_findings += 1
        elif event_type == EventType.EXPLOIT_ATTEMPT:
            session.exploits_attempted += 1
        elif event_type == EventType.EXPLOIT_SUCCESS:
            session.exploits_successful += 1
        
        # Add to buffer
        self.event_buffer[session_id].append(event)
        
        # Flush if buffer is full
        if len(self.event_buffer[session_id]) >= self.buffer_size:
            await self._flush_buffer(session_id)
        
        return event
    
    async def _flush_buffer(self, session_id: str):
        """Flush event buffer to database"""
        if session_id not in self.event_buffer:
            return
        
        events = self.event_buffer[session_id]
        if not events:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for event in events:
            # Compress data
            data_json = json.dumps(event.data)
            data_compressed = gzip.compress(data_json.encode())
            
            cursor.execute("""
                INSERT INTO recorded_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.session_id,
                event.timestamp.isoformat(),
                event.event_type.value,
                event.source,
                event.target,
                base64.b64encode(data_compressed).decode(),
                event.duration_ms,
                1 if event.success else 0,
                event.notes,
                json.dumps(event.tags),
                event.screenshot,
                event.parent_event_id
            ))
        
        conn.commit()
        conn.close()
        
        self.event_buffer[session_id] = []
    
    async def _persist_session(self, session: RecordingSession):
        """Persist session to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO recording_sessions VALUES 
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.session_id,
            session.name,
            session.description,
            session.created_at.isoformat(),
            session.started_at.isoformat(),
            session.ended_at.isoformat() if session.ended_at else None,
            session.state.value,
            session.operator,
            json.dumps(session.target_scope),
            session.event_count,
            session.duration_seconds,
            session.findings_count,
            session.critical_findings,
            session.exploits_attempted,
            session.exploits_successful,
            session.data_size_bytes,
            session.compression_ratio,
            json.dumps(session.tags),
            json.dumps(session.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    async def add_marker(self, session_id: str, event_id: str, label: str,
                        description: str = "", marker_type: str = "important",
                        color: str = "#00ff00") -> SessionMarker:
        """Add a marker/bookmark to the session"""
        # Get event timestamp
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT timestamp FROM recorded_events WHERE event_id = ?",
            (event_id,)
        )
        row = cursor.fetchone()
        timestamp = datetime.fromisoformat(row[0]) if row else datetime.now()
        
        marker = SessionMarker(
            marker_id=str(uuid.uuid4()),
            session_id=session_id,
            timestamp=timestamp,
            event_id=event_id,
            label=label,
            description=description,
            marker_type=marker_type,
            color=color
        )
        
        cursor.execute("""
            INSERT INTO session_markers VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            marker.marker_id,
            marker.session_id,
            marker.timestamp.isoformat(),
            marker.event_id,
            marker.label,
            marker.description,
            marker.marker_type,
            marker.color
        ))
        
        conn.commit()
        conn.close()
        
        return marker
    
    async def get_session(self, session_id: str) -> Optional[RecordingSession]:
        """Get a recording session by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM recording_sessions WHERE session_id = ?",
            (session_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return RecordingSession(
            session_id=row[0],
            name=row[1],
            description=row[2],
            created_at=datetime.fromisoformat(row[3]),
            started_at=datetime.fromisoformat(row[4]),
            ended_at=datetime.fromisoformat(row[5]) if row[5] else None,
            state=RecordingState(row[6]),
            operator=row[7],
            target_scope=json.loads(row[8]) if row[8] else [],
            event_count=row[9],
            duration_seconds=row[10],
            findings_count=row[11],
            critical_findings=row[12],
            exploits_attempted=row[13],
            exploits_successful=row[14],
            data_size_bytes=row[15],
            compression_ratio=row[16],
            tags=json.loads(row[17]) if row[17] else [],
            metadata=json.loads(row[18]) if row[18] else {}
        )
    
    async def list_sessions(self, limit: int = 50, 
                           operator: str = None) -> List[RecordingSession]:
        """List recording sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if operator:
            cursor.execute("""
                SELECT * FROM recording_sessions
                WHERE operator = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (operator, limit))
        else:
            cursor.execute("""
                SELECT * FROM recording_sessions
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            sessions.append(RecordingSession(
                session_id=row[0],
                name=row[1],
                description=row[2],
                created_at=datetime.fromisoformat(row[3]),
                started_at=datetime.fromisoformat(row[4]),
                ended_at=datetime.fromisoformat(row[5]) if row[5] else None,
                state=RecordingState(row[6]),
                operator=row[7],
                target_scope=json.loads(row[8]) if row[8] else [],
                event_count=row[9],
                duration_seconds=row[10],
                findings_count=row[11],
                critical_findings=row[12],
                exploits_attempted=row[13],
                exploits_successful=row[14],
                data_size_bytes=row[15],
                compression_ratio=row[16],
                tags=json.loads(row[17]) if row[17] else [],
                metadata=json.loads(row[18]) if row[18] else {}
            ))
        
        return sessions
    
    async def get_events(self, session_id: str, 
                        start_time: datetime = None,
                        end_time: datetime = None,
                        event_types: List[EventType] = None,
                        limit: int = 1000) -> List[RecordedEvent]:
        """Get events from a session with optional filtering"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM recorded_events WHERE session_id = ?"
        params = [session_id]
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        if event_types:
            placeholders = ",".join("?" * len(event_types))
            query += f" AND event_type IN ({placeholders})"
            params.extend([et.value for et in event_types])
        
        query += " ORDER BY timestamp LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            # Decompress data
            try:
                data_compressed = base64.b64decode(row[6])
                data_json = gzip.decompress(data_compressed).decode()
                data = json.loads(data_json)
            except Exception:
                data = json.loads(row[6]) if row[6] else {}
            
            events.append(RecordedEvent(
                event_id=row[0],
                session_id=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                event_type=EventType(row[3]),
                source=row[4],
                target=row[5],
                data=data,
                duration_ms=row[7],
                success=bool(row[8]),
                notes=row[9],
                tags=json.loads(row[10]) if row[10] else [],
                screenshot=row[11],
                parent_event_id=row[12]
            ))
        
        return events
    
    async def playback_session(self, session_id: str, 
                              speed: float = 1.0,
                              start_from: datetime = None) -> AsyncGenerator[RecordedEvent, None]:
        """Play back a session in real-time (generator)"""
        events = await self.get_events(session_id, start_time=start_from)
        
        if not events:
            return
        
        prev_timestamp = events[0].timestamp
        
        for event in events:
            # Calculate delay
            time_diff = (event.timestamp - prev_timestamp).total_seconds()
            delay = time_diff / speed
            
            if delay > 0 and delay < 60:  # Cap at 60 seconds
                await asyncio.sleep(delay)
            
            # Notify callbacks
            for callback in self.playback_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event)
                    else:
                        callback(event)
                except Exception as e:
                    print(f"Playback callback error: {e}")
            
            yield event
            prev_timestamp = event.timestamp
    
    async def get_timeline(self, session_id: str, 
                          segment_duration: int = 60) -> List[TimelineSegment]:
        """Get session timeline divided into segments"""
        session = await self.get_session(session_id)
        if not session:
            return []
        
        events = await self.get_events(session_id)
        if not events:
            return []
        
        segments = []
        current_start = events[0].timestamp
        current_events = []
        
        for event in events:
            if (event.timestamp - current_start).total_seconds() > segment_duration:
                # Create segment
                if current_events:
                    event_types = {}
                    has_findings = False
                    has_exploits = False
                    
                    for e in current_events:
                        event_types[e.event_type.value] = event_types.get(e.event_type.value, 0) + 1
                        if e.event_type == EventType.FINDING_DISCOVERED:
                            has_findings = True
                        if e.event_type in [EventType.EXPLOIT_ATTEMPT, EventType.EXPLOIT_SUCCESS]:
                            has_exploits = True
                    
                    segments.append(TimelineSegment(
                        start_time=current_start,
                        end_time=current_events[-1].timestamp,
                        event_count=len(current_events),
                        event_types=event_types,
                        has_findings=has_findings,
                        has_exploits=has_exploits,
                        highlight=has_findings or has_exploits
                    ))
                
                current_start = event.timestamp
                current_events = []
            
            current_events.append(event)
        
        # Final segment
        if current_events:
            event_types = {}
            has_findings = False
            has_exploits = False
            
            for e in current_events:
                event_types[e.event_type.value] = event_types.get(e.event_type.value, 0) + 1
                if e.event_type == EventType.FINDING_DISCOVERED:
                    has_findings = True
                if e.event_type in [EventType.EXPLOIT_ATTEMPT, EventType.EXPLOIT_SUCCESS]:
                    has_exploits = True
            
            segments.append(TimelineSegment(
                start_time=current_start,
                end_time=current_events[-1].timestamp,
                event_count=len(current_events),
                event_types=event_types,
                has_findings=has_findings,
                has_exploits=has_exploits,
                highlight=has_findings or has_exploits
            ))
        
        return segments
    
    async def get_markers(self, session_id: str) -> List[SessionMarker]:
        """Get all markers for a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM session_markers
            WHERE session_id = ?
            ORDER BY timestamp
        """, (session_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        markers = []
        for row in rows:
            markers.append(SessionMarker(
                marker_id=row[0],
                session_id=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                event_id=row[3],
                label=row[4],
                description=row[5],
                marker_type=row[6],
                color=row[7]
            ))
        
        return markers
    
    async def search_events(self, session_id: str, query: str,
                           limit: int = 100) -> List[RecordedEvent]:
        """Search events in a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Search in source, target, notes
        cursor.execute("""
            SELECT * FROM recorded_events
            WHERE session_id = ?
            AND (source LIKE ? OR target LIKE ? OR notes LIKE ?)
            ORDER BY timestamp
            LIMIT ?
        """, (session_id, f"%{query}%", f"%{query}%", f"%{query}%", limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            try:
                data_compressed = base64.b64decode(row[6])
                data_json = gzip.decompress(data_compressed).decode()
                data = json.loads(data_json)
            except Exception:
                data = json.loads(row[6]) if row[6] else {}
            
            events.append(RecordedEvent(
                event_id=row[0],
                session_id=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                event_type=EventType(row[3]),
                source=row[4],
                target=row[5],
                data=data,
                duration_ms=row[7],
                success=bool(row[8]),
                notes=row[9],
                tags=json.loads(row[10]) if row[10] else [],
                screenshot=row[11],
                parent_event_id=row[12]
            ))
        
        return events
    
    async def export_session(self, session_id: str, 
                            format: str = "json") -> bytes:
        """Export session to specified format"""
        session = await self.get_session(session_id)
        if not session:
            return b""
        
        events = await self.get_events(session_id, limit=100000)
        markers = await self.get_markers(session_id)
        
        if format == "json":
            export_data = {
                "session": {
                    "session_id": session.session_id,
                    "name": session.name,
                    "description": session.description,
                    "started_at": session.started_at.isoformat(),
                    "ended_at": session.ended_at.isoformat() if session.ended_at else None,
                    "operator": session.operator,
                    "target_scope": session.target_scope,
                    "event_count": session.event_count,
                    "findings_count": session.findings_count,
                    "critical_findings": session.critical_findings
                },
                "events": [
                    {
                        "event_id": e.event_id,
                        "timestamp": e.timestamp.isoformat(),
                        "event_type": e.event_type.value,
                        "source": e.source,
                        "target": e.target,
                        "data": e.data,
                        "success": e.success,
                        "notes": e.notes
                    }
                    for e in events
                ],
                "markers": [
                    {
                        "marker_id": m.marker_id,
                        "timestamp": m.timestamp.isoformat(),
                        "label": m.label,
                        "description": m.description,
                        "type": m.marker_type
                    }
                    for m in markers
                ]
            }
            return json.dumps(export_data, indent=2).encode()
        
        elif format == "timeline":
            # Generate timeline HTML
            timeline = await self.get_timeline(session_id)
            html = self._generate_timeline_html(session, events, markers, timeline)
            return html.encode()
        
        return b""
    
    def _generate_timeline_html(self, session: RecordingSession,
                               events: List[RecordedEvent],
                               markers: List[SessionMarker],
                               timeline: List[TimelineSegment]) -> str:
        """Generate HTML timeline visualization"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Session: {session.name}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0a; color: #00ff00; padding: 20px; }}
        .header {{ border-bottom: 2px solid #00ff00; padding-bottom: 10px; margin-bottom: 20px; }}
        .timeline {{ position: relative; padding: 20px 0; }}
        .event {{ margin: 10px 0; padding: 10px; background: #111; border-left: 3px solid #00ff00; }}
        .event.finding {{ border-left-color: #ff6600; }}
        .event.exploit {{ border-left-color: #ff0000; }}
        .event.success {{ border-left-color: #00ff00; }}
        .marker {{ background: #222; border: 1px solid #00ff00; padding: 5px 10px; margin: 5px 0; }}
        .timestamp {{ color: #666; font-size: 0.8em; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }}
        .stat {{ background: #111; padding: 15px; text-align: center; }}
        .stat-value {{ font-size: 2em; color: #00ff00; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔴 {session.name}</h1>
        <p>Operator: {session.operator} | Duration: {session.duration_seconds:.0f}s</p>
    </div>
    
    <div class="stats">
        <div class="stat"><div class="stat-value">{session.event_count}</div>Events</div>
        <div class="stat"><div class="stat-value">{session.findings_count}</div>Findings</div>
        <div class="stat"><div class="stat-value">{session.critical_findings}</div>Critical</div>
        <div class="stat"><div class="stat-value">{session.exploits_successful}</div>Exploits</div>
    </div>
    
    <div class="timeline">
"""
        
        for event in events[:100]:  # Limit for HTML
            event_class = "event"
            if event.event_type == EventType.FINDING_DISCOVERED:
                event_class += " finding"
            elif event.event_type in [EventType.EXPLOIT_ATTEMPT, EventType.EXPLOIT_SUCCESS]:
                event_class += " exploit"
            if event.success:
                event_class += " success"
            
            html += f"""
        <div class="{event_class}">
            <div class="timestamp">{event.timestamp.strftime('%H:%M:%S')}</div>
            <strong>{event.event_type.value}</strong>: {event.source} → {event.target}
            {f'<p>{event.notes}</p>' if event.notes else ''}
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    async def compare_sessions(self, session_id_1: str, 
                              session_id_2: str) -> Dict[str, Any]:
        """Compare two sessions"""
        session1 = await self.get_session(session_id_1)
        session2 = await self.get_session(session_id_2)
        
        if not session1 or not session2:
            return {"error": "Session not found"}
        
        events1 = await self.get_events(session_id_1)
        events2 = await self.get_events(session_id_2)
        
        # Compare statistics
        comparison = {
            "session_1": {
                "name": session1.name,
                "event_count": session1.event_count,
                "findings_count": session1.findings_count,
                "critical_findings": session1.critical_findings,
                "duration": session1.duration_seconds
            },
            "session_2": {
                "name": session2.name,
                "event_count": session2.event_count,
                "findings_count": session2.findings_count,
                "critical_findings": session2.critical_findings,
                "duration": session2.duration_seconds
            },
            "differences": {
                "event_count_diff": session2.event_count - session1.event_count,
                "findings_diff": session2.findings_count - session1.findings_count,
                "duration_diff": session2.duration_seconds - session1.duration_seconds
            },
            "common_targets": list(set(session1.target_scope) & set(session2.target_scope)),
            "unique_to_1": list(set(session1.target_scope) - set(session2.target_scope)),
            "unique_to_2": list(set(session2.target_scope) - set(session1.target_scope))
        }
        
        return comparison
    
    def add_playback_callback(self, callback: Callable):
        """Add a callback for playback events"""
        self.playback_callbacks.append(callback)
    
    def add_recording_callback(self, callback: Callable):
        """Add a callback for recording events"""
        self.recording_callbacks.append(callback)
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM recorded_events WHERE session_id = ?", (session_id,))
        cursor.execute("DELETE FROM session_markers WHERE session_id = ?", (session_id,))
        cursor.execute("DELETE FROM recording_sessions WHERE session_id = ?", (session_id,))
        
        conn.commit()
        conn.close()
        
        return True
