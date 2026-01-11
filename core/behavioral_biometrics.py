#!/usr/bin/env python3
"""
Behavioral Biometrics Engine - User Behavior Profiling & Anomaly Detection
Revolutionary behavioral analysis and continuous authentication platform.
"""

import asyncio
import hashlib
import json
import logging
import math
import sqlite3
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid


class BehaviorType(Enum):
    """Types of behavioral biometrics."""
    KEYSTROKE_DYNAMICS = auto()
    MOUSE_DYNAMICS = auto()
    TOUCH_DYNAMICS = auto()
    GAIT_ANALYSIS = auto()
    VOICE_PATTERNS = auto()
    COGNITIVE_PATTERNS = auto()
    NAVIGATION_PATTERNS = auto()
    TYPING_RHYTHM = auto()
    GESTURE_PATTERNS = auto()
    INTERACTION_PATTERNS = auto()


class AuthenticationState(Enum):
    """Continuous authentication states."""
    AUTHENTICATED = auto()
    SUSPICIOUS = auto()
    CHALLENGED = auto()
    LOCKED = auto()
    UNKNOWN = auto()


class AnomalyType(Enum):
    """Types of behavioral anomalies."""
    VELOCITY_ANOMALY = auto()
    PATTERN_DEVIATION = auto()
    TIMING_ANOMALY = auto()
    SEQUENCE_ANOMALY = auto()
    LOCATION_ANOMALY = auto()
    DEVICE_ANOMALY = auto()
    COGNITIVE_ANOMALY = auto()
    IMPERSONATION = auto()
    BOT_BEHAVIOR = auto()
    CREDENTIAL_SHARING = auto()


class RiskLevel(Enum):
    """Risk levels for anomalies."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    MINIMAL = auto()


@dataclass
class KeystrokeEvent:
    """Represents a keystroke event."""
    event_id: str
    key_code: int
    key_char: str
    press_time: datetime
    release_time: datetime
    hold_duration: float  # ms
    flight_time: float  # ms since previous key
    pressure: float
    is_error: bool
    context: str


@dataclass
class MouseEvent:
    """Represents a mouse movement/click event."""
    event_id: str
    event_type: str  # move, click, scroll
    x: float
    y: float
    timestamp: datetime
    velocity: float
    acceleration: float
    angle: float
    button: Optional[int]
    click_duration: Optional[float]
    path_deviation: float


@dataclass
class BehavioralProfile:
    """User behavioral profile."""
    profile_id: str
    user_id: str
    created_at: datetime
    updated_at: datetime
    sample_count: int
    confidence_score: float
    keystroke_features: Dict[str, Any]
    mouse_features: Dict[str, Any]
    navigation_features: Dict[str, Any]
    cognitive_features: Dict[str, Any]
    temporal_patterns: Dict[str, Any]
    device_fingerprints: List[str]
    risk_factors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralSession:
    """Represents an active user session."""
    session_id: str
    user_id: str
    start_time: datetime
    last_activity: datetime
    auth_state: AuthenticationState
    confidence_score: float
    anomaly_count: int
    events: List[Any]
    profile_match_score: float
    risk_level: RiskLevel
    device_fingerprint: str
    ip_address: str
    user_agent: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralAnomaly:
    """Represents a detected behavioral anomaly."""
    anomaly_id: str
    session_id: str
    user_id: str
    anomaly_type: AnomalyType
    timestamp: datetime
    severity: RiskLevel
    confidence: float
    expected_value: Any
    observed_value: Any
    deviation_score: float
    context: str
    recommended_action: str
    false_positive_likelihood: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthenticationChallenge:
    """Represents an authentication challenge."""
    challenge_id: str
    session_id: str
    user_id: str
    challenge_type: str
    created_at: datetime
    expires_at: datetime
    completed: bool
    success: bool
    attempts: int
    max_attempts: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TypingBiometrics:
    """Typing biometric features."""
    avg_hold_time: float
    std_hold_time: float
    avg_flight_time: float
    std_flight_time: float
    avg_digraph_latency: Dict[str, float]
    typing_speed_wpm: float
    error_rate: float
    pause_patterns: List[float]
    rhythm_signature: List[float]
    key_preference: Dict[str, float]


@dataclass
class MouseBiometrics:
    """Mouse biometric features."""
    avg_velocity: float
    std_velocity: float
    avg_acceleration: float
    avg_click_duration: float
    click_patterns: Dict[str, float]
    movement_angle_distribution: List[float]
    path_straightness: float
    hover_time_avg: float
    scroll_patterns: Dict[str, float]
    dominant_hand_indicator: float


class BehavioralBiometricsEngine:
    """
    Revolutionary behavioral biometrics and continuous authentication platform.
    
    Features:
    - Keystroke dynamics analysis
    - Mouse movement profiling
    - Cognitive pattern recognition
    - Continuous authentication
    - Impersonation detection
    - Bot/automation detection
    - Credential sharing detection
    - Risk-based authentication
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "behavioral_biometrics.db"
        self.logger = logging.getLogger("BehavioralBiometrics")
        self.profiles: Dict[str, BehavioralProfile] = {}
        self.sessions: Dict[str, BehavioralSession] = {}
        self.anomalies: List[BehavioralAnomaly] = []
        self.challenges: Dict[str, AuthenticationChallenge] = {}
        self.callbacks: Dict[str, List[Callable]] = {}
        
        # Thresholds
        self.confidence_threshold = 0.7
        self.anomaly_threshold = 2.5  # Standard deviations
        self.lock_threshold = 5  # Anomalies before lock
        
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS profiles (
                profile_id TEXT PRIMARY KEY,
                user_id TEXT UNIQUE,
                created_at TEXT,
                updated_at TEXT,
                sample_count INTEGER,
                confidence_score REAL,
                keystroke_features TEXT,
                mouse_features TEXT,
                navigation_features TEXT,
                cognitive_features TEXT,
                temporal_patterns TEXT,
                device_fingerprints TEXT,
                risk_factors TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT,
                start_time TEXT,
                last_activity TEXT,
                auth_state TEXT,
                confidence_score REAL,
                anomaly_count INTEGER,
                profile_match_score REAL,
                risk_level TEXT,
                device_fingerprint TEXT,
                ip_address TEXT,
                user_agent TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS keystroke_events (
                event_id TEXT PRIMARY KEY,
                session_id TEXT,
                key_code INTEGER,
                key_char TEXT,
                press_time TEXT,
                release_time TEXT,
                hold_duration REAL,
                flight_time REAL,
                pressure REAL,
                is_error INTEGER,
                context TEXT
            );
            
            CREATE TABLE IF NOT EXISTS mouse_events (
                event_id TEXT PRIMARY KEY,
                session_id TEXT,
                event_type TEXT,
                x REAL,
                y REAL,
                timestamp TEXT,
                velocity REAL,
                acceleration REAL,
                angle REAL,
                button INTEGER,
                click_duration REAL,
                path_deviation REAL
            );
            
            CREATE TABLE IF NOT EXISTS anomalies (
                anomaly_id TEXT PRIMARY KEY,
                session_id TEXT,
                user_id TEXT,
                anomaly_type TEXT,
                timestamp TEXT,
                severity TEXT,
                confidence REAL,
                expected_value TEXT,
                observed_value TEXT,
                deviation_score REAL,
                context TEXT,
                recommended_action TEXT
            );
            
            CREATE TABLE IF NOT EXISTS challenges (
                challenge_id TEXT PRIMARY KEY,
                session_id TEXT,
                user_id TEXT,
                challenge_type TEXT,
                created_at TEXT,
                expires_at TEXT,
                completed INTEGER,
                success INTEGER,
                attempts INTEGER,
                max_attempts INTEGER
            );
            
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_keystrokes_session ON keystroke_events(session_id);
            CREATE INDEX IF NOT EXISTS idx_mouse_session ON mouse_events(session_id);
            CREATE INDEX IF NOT EXISTS idx_anomalies_session ON anomalies(session_id);
        """)
        
        conn.commit()
        conn.close()
    
    async def create_profile(
        self,
        user_id: str,
        enrollment_data: Dict[str, List[Any]]
    ) -> BehavioralProfile:
        """
        Create a behavioral profile for a user.
        
        Args:
            user_id: User identifier
            enrollment_data: Initial behavioral data for enrollment
            
        Returns:
            Created behavioral profile
        """
        profile_id = str(uuid.uuid4())[:8]
        
        # Extract keystroke features
        keystroke_features = await self._extract_keystroke_features(
            enrollment_data.get("keystrokes", [])
        )
        
        # Extract mouse features
        mouse_features = await self._extract_mouse_features(
            enrollment_data.get("mouse_events", [])
        )
        
        # Extract navigation patterns
        navigation_features = await self._extract_navigation_features(
            enrollment_data.get("navigation", [])
        )
        
        # Extract cognitive patterns
        cognitive_features = await self._extract_cognitive_features(
            enrollment_data.get("cognitive", [])
        )
        
        # Extract temporal patterns
        temporal_patterns = await self._extract_temporal_patterns(
            enrollment_data
        )
        
        profile = BehavioralProfile(
            profile_id=profile_id,
            user_id=user_id,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            sample_count=len(enrollment_data.get("keystrokes", [])),
            confidence_score=0.5,  # Initial confidence
            keystroke_features=keystroke_features,
            mouse_features=mouse_features,
            navigation_features=navigation_features,
            cognitive_features=cognitive_features,
            temporal_patterns=temporal_patterns,
            device_fingerprints=enrollment_data.get("device_fingerprints", [])
        )
        
        self.profiles[user_id] = profile
        self._save_profile(profile)
        
        return profile
    
    async def _extract_keystroke_features(
        self,
        keystrokes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extract keystroke dynamics features."""
        if not keystrokes:
            return {}
        
        hold_times = []
        flight_times = []
        digraph_latencies: Dict[str, List[float]] = {}
        errors = 0
        
        for i, ks in enumerate(keystrokes):
            hold_times.append(ks.get("hold_duration", 100))
            
            if i > 0:
                flight = ks.get("flight_time", 150)
                flight_times.append(flight)
                
                # Digraph (two consecutive keys)
                prev_char = keystrokes[i-1].get("key_char", "")
                curr_char = ks.get("key_char", "")
                digraph = f"{prev_char}{curr_char}"
                
                if digraph not in digraph_latencies:
                    digraph_latencies[digraph] = []
                digraph_latencies[digraph].append(flight)
            
            if ks.get("is_error"):
                errors += 1
        
        # Calculate average digraph latencies
        avg_digraph_latency = {
            dg: statistics.mean(times) 
            for dg, times in digraph_latencies.items()
            if len(times) >= 3
        }
        
        # Calculate typing speed (words per minute)
        if keystrokes:
            total_time = sum(hold_times) + sum(flight_times)
            chars_typed = len(keystrokes)
            # Average word length of 5 characters
            wpm = (chars_typed / 5) / (total_time / 60000) if total_time > 0 else 0
        else:
            wpm = 0
        
        return {
            "avg_hold_time": statistics.mean(hold_times) if hold_times else 0,
            "std_hold_time": statistics.stdev(hold_times) if len(hold_times) > 1 else 0,
            "avg_flight_time": statistics.mean(flight_times) if flight_times else 0,
            "std_flight_time": statistics.stdev(flight_times) if len(flight_times) > 1 else 0,
            "avg_digraph_latency": avg_digraph_latency,
            "typing_speed_wpm": wpm,
            "error_rate": errors / len(keystrokes) if keystrokes else 0,
            "rhythm_signature": self._calculate_rhythm_signature(hold_times, flight_times),
            "sample_count": len(keystrokes)
        }
    
    def _calculate_rhythm_signature(
        self,
        hold_times: List[float],
        flight_times: List[float]
    ) -> List[float]:
        """Calculate typing rhythm signature."""
        if not hold_times or not flight_times:
            return []
        
        # Normalize to create signature
        all_times = hold_times + flight_times
        mean_time = statistics.mean(all_times)
        
        if mean_time == 0:
            return [1.0] * min(10, len(all_times))
        
        # Create normalized rhythm signature
        signature = [t / mean_time for t in all_times[:10]]
        
        return signature
    
    async def _extract_mouse_features(
        self,
        mouse_events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extract mouse dynamics features."""
        if not mouse_events:
            return {}
        
        velocities = []
        accelerations = []
        angles = []
        click_durations = []
        path_deviations = []
        
        for event in mouse_events:
            if "velocity" in event:
                velocities.append(event["velocity"])
            if "acceleration" in event:
                accelerations.append(event["acceleration"])
            if "angle" in event:
                angles.append(event["angle"])
            if event.get("event_type") == "click" and "click_duration" in event:
                click_durations.append(event["click_duration"])
            if "path_deviation" in event:
                path_deviations.append(event["path_deviation"])
        
        # Calculate path straightness
        if path_deviations:
            path_straightness = 1 - (
                statistics.mean(path_deviations) / 100
            )
        else:
            path_straightness = 0.8
        
        return {
            "avg_velocity": statistics.mean(velocities) if velocities else 0,
            "std_velocity": statistics.stdev(velocities) if len(velocities) > 1 else 0,
            "avg_acceleration": statistics.mean(accelerations) if accelerations else 0,
            "avg_click_duration": statistics.mean(click_durations) if click_durations else 0,
            "std_click_duration": statistics.stdev(click_durations) if len(click_durations) > 1 else 0,
            "angle_distribution": self._calculate_angle_distribution(angles),
            "path_straightness": path_straightness,
            "sample_count": len(mouse_events)
        }
    
    def _calculate_angle_distribution(self, angles: List[float]) -> List[float]:
        """Calculate angle distribution for mouse movements."""
        if not angles:
            return [0.125] * 8  # Uniform distribution
        
        # 8 directional bins
        bins = [0] * 8
        for angle in angles:
            # Convert to 0-360 range
            normalized_angle = angle % 360
            bin_index = int(normalized_angle / 45) % 8
            bins[bin_index] += 1
        
        # Normalize
        total = sum(bins) or 1
        return [b / total for b in bins]
    
    async def _extract_navigation_features(
        self,
        navigation: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extract navigation pattern features."""
        if not navigation:
            return {}
        
        page_times = []
        scroll_depths = []
        interaction_counts = []
        
        for nav in navigation:
            if "time_on_page" in nav:
                page_times.append(nav["time_on_page"])
            if "scroll_depth" in nav:
                scroll_depths.append(nav["scroll_depth"])
            if "interaction_count" in nav:
                interaction_counts.append(nav["interaction_count"])
        
        return {
            "avg_page_time": statistics.mean(page_times) if page_times else 0,
            "std_page_time": statistics.stdev(page_times) if len(page_times) > 1 else 0,
            "avg_scroll_depth": statistics.mean(scroll_depths) if scroll_depths else 0,
            "avg_interactions": statistics.mean(interaction_counts) if interaction_counts else 0,
            "navigation_patterns": self._identify_navigation_patterns(navigation)
        }
    
    def _identify_navigation_patterns(
        self,
        navigation: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Identify user navigation patterns."""
        if not navigation:
            return {}
        
        # Track common sequences
        sequences = {}
        for i in range(len(navigation) - 1):
            current = navigation[i].get("page", "unknown")
            next_page = navigation[i + 1].get("page", "unknown")
            seq = f"{current} -> {next_page}"
            sequences[seq] = sequences.get(seq, 0) + 1
        
        return {
            "common_sequences": sorted(
                sequences.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
    
    async def _extract_cognitive_features(
        self,
        cognitive: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extract cognitive pattern features."""
        if not cognitive:
            return {}
        
        decision_times = []
        error_recovery_times = []
        task_completion_times = []
        
        for c in cognitive:
            if "decision_time" in c:
                decision_times.append(c["decision_time"])
            if "error_recovery_time" in c:
                error_recovery_times.append(c["error_recovery_time"])
            if "task_completion_time" in c:
                task_completion_times.append(c["task_completion_time"])
        
        return {
            "avg_decision_time": statistics.mean(decision_times) if decision_times else 0,
            "avg_error_recovery": statistics.mean(error_recovery_times) if error_recovery_times else 0,
            "avg_task_completion": statistics.mean(task_completion_times) if task_completion_times else 0,
            "cognitive_load_indicator": self._estimate_cognitive_load(cognitive)
        }
    
    def _estimate_cognitive_load(self, cognitive: List[Dict[str, Any]]) -> float:
        """Estimate user's cognitive load based on behavior."""
        if not cognitive:
            return 0.5
        
        # Higher decision times and more errors indicate higher cognitive load
        indicators = []
        for c in cognitive:
            if "hesitation_count" in c:
                indicators.append(c["hesitation_count"] * 0.1)
            if "correction_count" in c:
                indicators.append(c["correction_count"] * 0.15)
        
        return min(sum(indicators) / max(len(indicators), 1), 1.0)
    
    async def _extract_temporal_patterns(
        self,
        data: Dict[str, List[Any]]
    ) -> Dict[str, Any]:
        """Extract temporal usage patterns."""
        # Analyze time-based patterns
        timestamps = []
        
        for key in ["keystrokes", "mouse_events", "navigation"]:
            for item in data.get(key, []):
                if "timestamp" in item:
                    timestamps.append(item["timestamp"])
        
        if not timestamps:
            return {}
        
        # Convert to datetime if needed
        hours = []
        days = []
        for ts in timestamps:
            if isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts)
                    hours.append(dt.hour)
                    days.append(dt.weekday())
                except Exception:
                    pass
        
        # Calculate distributions
        hour_dist = [0] * 24
        day_dist = [0] * 7
        
        for h in hours:
            hour_dist[h] += 1
        for d in days:
            day_dist[d] += 1
        
        # Normalize
        total_hours = sum(hour_dist) or 1
        total_days = sum(day_dist) or 1
        
        return {
            "hourly_distribution": [h / total_hours for h in hour_dist],
            "daily_distribution": [d / total_days for d in day_dist],
            "peak_hours": sorted(
                range(24),
                key=lambda x: hour_dist[x],
                reverse=True
            )[:3],
            "active_days": sorted(
                range(7),
                key=lambda x: day_dist[x],
                reverse=True
            )[:3]
        }
    
    async def start_session(
        self,
        user_id: str,
        device_fingerprint: str,
        ip_address: str,
        user_agent: str
    ) -> BehavioralSession:
        """
        Start a new behavioral monitoring session.
        
        Args:
            user_id: User identifier
            device_fingerprint: Device fingerprint
            ip_address: Client IP address
            user_agent: Browser user agent
            
        Returns:
            New behavioral session
        """
        session_id = str(uuid.uuid4())[:8]
        
        # Check device fingerprint against profile
        profile = self.profiles.get(user_id)
        known_device = False
        if profile and device_fingerprint in profile.device_fingerprints:
            known_device = True
        
        # Initial risk assessment
        risk_level = RiskLevel.LOW if known_device else RiskLevel.MEDIUM
        
        session = BehavioralSession(
            session_id=session_id,
            user_id=user_id,
            start_time=datetime.now(),
            last_activity=datetime.now(),
            auth_state=AuthenticationState.AUTHENTICATED,
            confidence_score=0.8 if known_device else 0.5,
            anomaly_count=0,
            events=[],
            profile_match_score=1.0 if known_device else 0.5,
            risk_level=risk_level,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.sessions[session_id] = session
        self._save_session(session)
        
        # Emit session start event
        await self.emit_event("session_started", {
            "session_id": session_id,
            "user_id": user_id,
            "risk_level": risk_level.name
        })
        
        return session
    
    async def process_keystroke(
        self,
        session_id: str,
        keystroke: Dict[str, Any]
    ) -> Optional[BehavioralAnomaly]:
        """
        Process a keystroke event and check for anomalies.
        
        Args:
            session_id: Session identifier
            keystroke: Keystroke event data
            
        Returns:
            Anomaly if detected, None otherwise
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # Create keystroke event
        event = KeystrokeEvent(
            event_id=str(uuid.uuid4())[:8],
            key_code=keystroke.get("key_code", 0),
            key_char=keystroke.get("key_char", ""),
            press_time=datetime.fromisoformat(keystroke.get("press_time", datetime.now().isoformat())),
            release_time=datetime.fromisoformat(keystroke.get("release_time", datetime.now().isoformat())),
            hold_duration=keystroke.get("hold_duration", 100),
            flight_time=keystroke.get("flight_time", 150),
            pressure=keystroke.get("pressure", 1.0),
            is_error=keystroke.get("is_error", False),
            context=keystroke.get("context", "")
        )
        
        session.events.append(event)
        session.last_activity = datetime.now()
        
        # Get user profile
        profile = self.profiles.get(session.user_id)
        if not profile:
            return None
        
        # Check for anomalies
        anomaly = await self._check_keystroke_anomaly(event, profile, session)
        
        if anomaly:
            session.anomaly_count += 1
            self.anomalies.append(anomaly)
            
            # Update session state based on anomalies
            await self._update_session_state(session)
            
            await self.emit_event("anomaly_detected", {
                "session_id": session_id,
                "anomaly": self._anomaly_to_dict(anomaly)
            })
        
        # Update profile match score
        await self._update_profile_match(session, profile)
        
        return anomaly
    
    async def _check_keystroke_anomaly(
        self,
        event: KeystrokeEvent,
        profile: BehavioralProfile,
        session: BehavioralSession
    ) -> Optional[BehavioralAnomaly]:
        """Check keystroke event for anomalies."""
        keystroke_features = profile.keystroke_features
        
        if not keystroke_features:
            return None
        
        # Check hold time
        avg_hold = keystroke_features.get("avg_hold_time", 100)
        std_hold = keystroke_features.get("std_hold_time", 30)
        
        if std_hold > 0:
            z_score = abs(event.hold_duration - avg_hold) / std_hold
            
            if z_score > self.anomaly_threshold:
                return BehavioralAnomaly(
                    anomaly_id=str(uuid.uuid4())[:8],
                    session_id=session.session_id,
                    user_id=session.user_id,
                    anomaly_type=AnomalyType.TIMING_ANOMALY,
                    timestamp=datetime.now(),
                    severity=self._calculate_severity(z_score),
                    confidence=min(z_score / 5, 1.0),
                    expected_value=f"{avg_hold:.1f}ms ± {std_hold:.1f}",
                    observed_value=f"{event.hold_duration:.1f}ms",
                    deviation_score=z_score,
                    context=f"Key: {event.key_char}",
                    recommended_action=self._get_recommended_action(z_score),
                    false_positive_likelihood=max(0, 1 - z_score / 5)
                )
        
        # Check flight time
        avg_flight = keystroke_features.get("avg_flight_time", 150)
        std_flight = keystroke_features.get("std_flight_time", 50)
        
        if std_flight > 0:
            z_score = abs(event.flight_time - avg_flight) / std_flight
            
            if z_score > self.anomaly_threshold:
                return BehavioralAnomaly(
                    anomaly_id=str(uuid.uuid4())[:8],
                    session_id=session.session_id,
                    user_id=session.user_id,
                    anomaly_type=AnomalyType.VELOCITY_ANOMALY,
                    timestamp=datetime.now(),
                    severity=self._calculate_severity(z_score),
                    confidence=min(z_score / 5, 1.0),
                    expected_value=f"{avg_flight:.1f}ms ± {std_flight:.1f}",
                    observed_value=f"{event.flight_time:.1f}ms",
                    deviation_score=z_score,
                    context=f"Key transition",
                    recommended_action=self._get_recommended_action(z_score),
                    false_positive_likelihood=max(0, 1 - z_score / 5)
                )
        
        return None
    
    async def process_mouse_event(
        self,
        session_id: str,
        mouse_event: Dict[str, Any]
    ) -> Optional[BehavioralAnomaly]:
        """
        Process a mouse event and check for anomalies.
        
        Args:
            session_id: Session identifier
            mouse_event: Mouse event data
            
        Returns:
            Anomaly if detected, None otherwise
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # Create mouse event
        event = MouseEvent(
            event_id=str(uuid.uuid4())[:8],
            event_type=mouse_event.get("event_type", "move"),
            x=mouse_event.get("x", 0),
            y=mouse_event.get("y", 0),
            timestamp=datetime.fromisoformat(mouse_event.get("timestamp", datetime.now().isoformat())),
            velocity=mouse_event.get("velocity", 0),
            acceleration=mouse_event.get("acceleration", 0),
            angle=mouse_event.get("angle", 0),
            button=mouse_event.get("button"),
            click_duration=mouse_event.get("click_duration"),
            path_deviation=mouse_event.get("path_deviation", 0)
        )
        
        session.events.append(event)
        session.last_activity = datetime.now()
        
        # Get user profile
        profile = self.profiles.get(session.user_id)
        if not profile:
            return None
        
        # Check for anomalies
        anomaly = await self._check_mouse_anomaly(event, profile, session)
        
        if anomaly:
            session.anomaly_count += 1
            self.anomalies.append(anomaly)
            await self._update_session_state(session)
            
            await self.emit_event("anomaly_detected", {
                "session_id": session_id,
                "anomaly": self._anomaly_to_dict(anomaly)
            })
        
        return anomaly
    
    async def _check_mouse_anomaly(
        self,
        event: MouseEvent,
        profile: BehavioralProfile,
        session: BehavioralSession
    ) -> Optional[BehavioralAnomaly]:
        """Check mouse event for anomalies."""
        mouse_features = profile.mouse_features
        
        if not mouse_features:
            return None
        
        # Check velocity
        avg_velocity = mouse_features.get("avg_velocity", 500)
        std_velocity = mouse_features.get("std_velocity", 200)
        
        if std_velocity > 0:
            z_score = abs(event.velocity - avg_velocity) / std_velocity
            
            if z_score > self.anomaly_threshold:
                return BehavioralAnomaly(
                    anomaly_id=str(uuid.uuid4())[:8],
                    session_id=session.session_id,
                    user_id=session.user_id,
                    anomaly_type=AnomalyType.VELOCITY_ANOMALY,
                    timestamp=datetime.now(),
                    severity=self._calculate_severity(z_score),
                    confidence=min(z_score / 5, 1.0),
                    expected_value=f"{avg_velocity:.1f} ± {std_velocity:.1f}",
                    observed_value=f"{event.velocity:.1f}",
                    deviation_score=z_score,
                    context="Mouse velocity",
                    recommended_action=self._get_recommended_action(z_score),
                    false_positive_likelihood=max(0, 1 - z_score / 5)
                )
        
        # Check path straightness (bot detection)
        if event.path_deviation < 1:  # Perfectly straight paths are suspicious
            return BehavioralAnomaly(
                anomaly_id=str(uuid.uuid4())[:8],
                session_id=session.session_id,
                user_id=session.user_id,
                anomaly_type=AnomalyType.BOT_BEHAVIOR,
                timestamp=datetime.now(),
                severity=RiskLevel.HIGH,
                confidence=0.8,
                expected_value="Natural mouse movement",
                observed_value="Perfectly straight path",
                deviation_score=5.0,
                context="Possible automation detected",
                recommended_action="Challenge user authentication",
                false_positive_likelihood=0.2
            )
        
        return None
    
    async def _update_session_state(self, session: BehavioralSession) -> None:
        """Update session authentication state based on anomalies."""
        if session.anomaly_count >= self.lock_threshold:
            session.auth_state = AuthenticationState.LOCKED
            session.risk_level = RiskLevel.CRITICAL
            
            await self.emit_event("session_locked", {
                "session_id": session.session_id,
                "user_id": session.user_id,
                "reason": "Excessive behavioral anomalies"
            })
        
        elif session.anomaly_count >= 3:
            session.auth_state = AuthenticationState.CHALLENGED
            session.risk_level = RiskLevel.HIGH
            
            # Create challenge
            await self._create_challenge(session)
        
        elif session.anomaly_count >= 1:
            session.auth_state = AuthenticationState.SUSPICIOUS
            session.risk_level = RiskLevel.MEDIUM
    
    async def _update_profile_match(
        self,
        session: BehavioralSession,
        profile: BehavioralProfile
    ) -> None:
        """Update profile match score for session."""
        # Count recent anomalies
        recent_anomalies = len([
            a for a in self.anomalies
            if a.session_id == session.session_id
            and (datetime.now() - a.timestamp).seconds < 300
        ])
        
        # Decrease match score based on anomalies
        penalty = recent_anomalies * 0.1
        session.profile_match_score = max(0, 1 - penalty)
        session.confidence_score = session.profile_match_score * 0.8 + 0.2
    
    async def _create_challenge(
        self,
        session: BehavioralSession
    ) -> AuthenticationChallenge:
        """Create an authentication challenge for the session."""
        challenge = AuthenticationChallenge(
            challenge_id=str(uuid.uuid4())[:8],
            session_id=session.session_id,
            user_id=session.user_id,
            challenge_type="behavioral_verification",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(minutes=5),
            completed=False,
            success=False,
            attempts=0,
            max_attempts=3
        )
        
        self.challenges[challenge.challenge_id] = challenge
        
        await self.emit_event("challenge_created", {
            "challenge_id": challenge.challenge_id,
            "session_id": session.session_id,
            "challenge_type": challenge.challenge_type
        })
        
        return challenge
    
    async def verify_challenge(
        self,
        challenge_id: str,
        response_data: Dict[str, Any]
    ) -> bool:
        """Verify a challenge response."""
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            return False
        
        if datetime.now() > challenge.expires_at:
            challenge.completed = True
            challenge.success = False
            return False
        
        challenge.attempts += 1
        
        # Verify behavioral response
        profile = self.profiles.get(challenge.user_id)
        if not profile:
            return False
        
        match_score = await self._verify_behavioral_response(
            response_data,
            profile
        )
        
        if match_score > self.confidence_threshold:
            challenge.completed = True
            challenge.success = True
            
            # Update session state
            session = self.sessions.get(challenge.session_id)
            if session:
                session.auth_state = AuthenticationState.AUTHENTICATED
                session.anomaly_count = 0
                session.risk_level = RiskLevel.LOW
            
            return True
        
        if challenge.attempts >= challenge.max_attempts:
            challenge.completed = True
            challenge.success = False
            
            # Lock session
            session = self.sessions.get(challenge.session_id)
            if session:
                session.auth_state = AuthenticationState.LOCKED
            
            return False
        
        return False
    
    async def _verify_behavioral_response(
        self,
        response_data: Dict[str, Any],
        profile: BehavioralProfile
    ) -> float:
        """Verify behavioral challenge response against profile."""
        scores = []
        
        # Check keystroke patterns if provided
        if "keystrokes" in response_data:
            keystroke_features = await self._extract_keystroke_features(
                response_data["keystrokes"]
            )
            
            ks_score = self._compare_keystroke_features(
                keystroke_features,
                profile.keystroke_features
            )
            scores.append(ks_score)
        
        # Check mouse patterns if provided
        if "mouse_events" in response_data:
            mouse_features = await self._extract_mouse_features(
                response_data["mouse_events"]
            )
            
            mouse_score = self._compare_mouse_features(
                mouse_features,
                profile.mouse_features
            )
            scores.append(mouse_score)
        
        return statistics.mean(scores) if scores else 0.0
    
    def _compare_keystroke_features(
        self,
        observed: Dict[str, Any],
        expected: Dict[str, Any]
    ) -> float:
        """Compare keystroke features for similarity."""
        if not observed or not expected:
            return 0.5
        
        scores = []
        
        # Compare average hold time
        if "avg_hold_time" in observed and "avg_hold_time" in expected:
            diff = abs(observed["avg_hold_time"] - expected["avg_hold_time"])
            std = expected.get("std_hold_time", 30)
            if std > 0:
                z = diff / std
                scores.append(max(0, 1 - z / 3))
        
        # Compare typing speed
        if "typing_speed_wpm" in observed and "typing_speed_wpm" in expected:
            exp_wpm = expected["typing_speed_wpm"]
            if exp_wpm > 0:
                ratio = observed["typing_speed_wpm"] / exp_wpm
                scores.append(max(0, 1 - abs(1 - ratio)))
        
        return statistics.mean(scores) if scores else 0.5
    
    def _compare_mouse_features(
        self,
        observed: Dict[str, Any],
        expected: Dict[str, Any]
    ) -> float:
        """Compare mouse features for similarity."""
        if not observed or not expected:
            return 0.5
        
        scores = []
        
        # Compare velocity
        if "avg_velocity" in observed and "avg_velocity" in expected:
            diff = abs(observed["avg_velocity"] - expected["avg_velocity"])
            std = expected.get("std_velocity", 200)
            if std > 0:
                z = diff / std
                scores.append(max(0, 1 - z / 3))
        
        # Compare path straightness
        if "path_straightness" in observed and "path_straightness" in expected:
            diff = abs(observed["path_straightness"] - expected["path_straightness"])
            scores.append(max(0, 1 - diff * 2))
        
        return statistics.mean(scores) if scores else 0.5
    
    def _calculate_severity(self, z_score: float) -> RiskLevel:
        """Calculate severity based on z-score."""
        if z_score > 5:
            return RiskLevel.CRITICAL
        elif z_score > 4:
            return RiskLevel.HIGH
        elif z_score > 3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _get_recommended_action(self, z_score: float) -> str:
        """Get recommended action based on deviation."""
        if z_score > 5:
            return "Lock session and require re-authentication"
        elif z_score > 4:
            return "Challenge user with additional verification"
        elif z_score > 3:
            return "Increase monitoring intensity"
        else:
            return "Log and continue monitoring"
    
    async def detect_credential_sharing(
        self,
        user_id: str,
        lookback_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Detect potential credential sharing by analyzing sessions.
        
        Args:
            user_id: User to analyze
            lookback_hours: Hours to look back
            
        Returns:
            List of sharing indicators
        """
        indicators = []
        
        # Get user sessions
        user_sessions = [
            s for s in self.sessions.values()
            if s.user_id == user_id and
            (datetime.now() - s.start_time).seconds < lookback_hours * 3600
        ]
        
        if len(user_sessions) < 2:
            return indicators
        
        # Check for different device fingerprints with significant behavioral differences
        fingerprint_behaviors: Dict[str, List[BehavioralSession]] = {}
        
        for session in user_sessions:
            fp = session.device_fingerprint
            if fp not in fingerprint_behaviors:
                fingerprint_behaviors[fp] = []
            fingerprint_behaviors[fp].append(session)
        
        if len(fingerprint_behaviors) > 1:
            # Multiple devices - check behavioral consistency
            fingerprints = list(fingerprint_behaviors.keys())
            
            for i, fp1 in enumerate(fingerprints):
                for fp2 in fingerprints[i+1:]:
                    sessions1 = fingerprint_behaviors[fp1]
                    sessions2 = fingerprint_behaviors[fp2]
                    
                    # Compare average match scores
                    avg_score1 = statistics.mean([s.profile_match_score for s in sessions1])
                    avg_score2 = statistics.mean([s.profile_match_score for s in sessions2])
                    
                    if abs(avg_score1 - avg_score2) > 0.3:
                        indicators.append({
                            "type": "behavioral_mismatch",
                            "fingerprint1": fp1,
                            "fingerprint2": fp2,
                            "score_difference": abs(avg_score1 - avg_score2),
                            "confidence": min(abs(avg_score1 - avg_score2) / 0.5, 1.0),
                            "recommendation": "Verify account ownership"
                        })
        
        # Check for geographically impossible travel
        # (Would require IP geolocation in production)
        
        return indicators
    
    async def get_session_risk_score(
        self,
        session_id: str
    ) -> Dict[str, Any]:
        """Get comprehensive risk score for a session."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        
        profile = self.profiles.get(session.user_id)
        
        risk_factors = []
        risk_score = 0.0
        
        # Anomaly count factor
        if session.anomaly_count > 0:
            anomaly_risk = min(session.anomaly_count * 0.15, 0.5)
            risk_score += anomaly_risk
            risk_factors.append({
                "factor": "Anomaly count",
                "value": session.anomaly_count,
                "contribution": anomaly_risk
            })
        
        # Device recognition factor
        if profile and session.device_fingerprint not in profile.device_fingerprints:
            risk_score += 0.2
            risk_factors.append({
                "factor": "Unknown device",
                "value": session.device_fingerprint[:8],
                "contribution": 0.2
            })
        
        # Profile match score factor
        if session.profile_match_score < 0.7:
            match_risk = (0.7 - session.profile_match_score) * 0.5
            risk_score += match_risk
            risk_factors.append({
                "factor": "Low profile match",
                "value": session.profile_match_score,
                "contribution": match_risk
            })
        
        # Authentication state factor
        state_risks = {
            AuthenticationState.LOCKED: 1.0,
            AuthenticationState.CHALLENGED: 0.5,
            AuthenticationState.SUSPICIOUS: 0.3,
            AuthenticationState.UNKNOWN: 0.4,
            AuthenticationState.AUTHENTICATED: 0.0
        }
        state_risk = state_risks.get(session.auth_state, 0.2)
        risk_score += state_risk
        
        return {
            "session_id": session_id,
            "user_id": session.user_id,
            "risk_score": min(risk_score, 1.0),
            "risk_level": self._score_to_level(risk_score),
            "auth_state": session.auth_state.name,
            "confidence_score": session.confidence_score,
            "profile_match_score": session.profile_match_score,
            "anomaly_count": session.anomaly_count,
            "risk_factors": risk_factors,
            "recommendations": self._get_recommendations(risk_score, risk_factors)
        }
    
    def _score_to_level(self, score: float) -> str:
        """Convert risk score to level string."""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_recommendations(
        self,
        score: float,
        factors: List[Dict[str, Any]]
    ) -> List[str]:
        """Get recommendations based on risk score and factors."""
        recommendations = []
        
        if score >= 0.8:
            recommendations.append("Immediately lock the session")
            recommendations.append("Require full re-authentication")
            recommendations.append("Notify security team")
        elif score >= 0.6:
            recommendations.append("Challenge with additional verification")
            recommendations.append("Enable enhanced monitoring")
        elif score >= 0.4:
            recommendations.append("Increase monitoring intensity")
            recommendations.append("Log detailed behavioral data")
        else:
            recommendations.append("Continue normal monitoring")
        
        return recommendations
    
    def _save_profile(self, profile: BehavioralProfile) -> None:
        """Save profile to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO profiles
            (profile_id, user_id, created_at, updated_at, sample_count,
             confidence_score, keystroke_features, mouse_features,
             navigation_features, cognitive_features, temporal_patterns,
             device_fingerprints, risk_factors, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile.profile_id,
            profile.user_id,
            profile.created_at.isoformat(),
            profile.updated_at.isoformat(),
            profile.sample_count,
            profile.confidence_score,
            json.dumps(profile.keystroke_features),
            json.dumps(profile.mouse_features),
            json.dumps(profile.navigation_features),
            json.dumps(profile.cognitive_features),
            json.dumps(profile.temporal_patterns),
            json.dumps(profile.device_fingerprints),
            json.dumps(profile.risk_factors),
            json.dumps(profile.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _save_session(self, session: BehavioralSession) -> None:
        """Save session to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO sessions
            (session_id, user_id, start_time, last_activity, auth_state,
             confidence_score, anomaly_count, profile_match_score,
             risk_level, device_fingerprint, ip_address, user_agent, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.session_id,
            session.user_id,
            session.start_time.isoformat(),
            session.last_activity.isoformat(),
            session.auth_state.name,
            session.confidence_score,
            session.anomaly_count,
            session.profile_match_score,
            session.risk_level.name,
            session.device_fingerprint,
            session.ip_address,
            session.user_agent,
            json.dumps(session.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _anomaly_to_dict(self, anomaly: BehavioralAnomaly) -> Dict[str, Any]:
        """Convert anomaly to dictionary."""
        return {
            "anomaly_id": anomaly.anomaly_id,
            "session_id": anomaly.session_id,
            "user_id": anomaly.user_id,
            "anomaly_type": anomaly.anomaly_type.name,
            "timestamp": anomaly.timestamp.isoformat(),
            "severity": anomaly.severity.name,
            "confidence": anomaly.confidence,
            "expected_value": str(anomaly.expected_value),
            "observed_value": str(anomaly.observed_value),
            "deviation_score": anomaly.deviation_score,
            "context": anomaly.context,
            "recommended_action": anomaly.recommended_action
        }
    
    def register_callback(
        self,
        event_type: str,
        callback: Callable
    ) -> None:
        """Register callback for biometrics events."""
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        self.callbacks[event_type].append(callback)
    
    async def emit_event(self, event_type: str, data: Any) -> None:
        """Emit event to registered callbacks."""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self.logger.error(f"Error in callback: {e}")
