"""core.esp32_deauth_detector

ESP32 Wireless Intrusion Detection System (WIDS)
================================================
Defensive module that monitors for wireless management-frame floods,
especially deauthentication/disassociation storms.

Data source: ESP32-S3 HydraSense firmware `/scan` endpoint.

Scope: detection, alerting, and forensic logging only.
"""

import asyncio
import hashlib
import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


class AttackSeverity(Enum):
    """Severity levels for detected attacks"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FrameType(Enum):
    """802.11 management frame subtypes"""
    ASSOCIATION_REQ = 0x00
    ASSOCIATION_RESP = 0x01
    REASSOCIATION_REQ = 0x02
    REASSOCIATION_RESP = 0x03
    PROBE_REQ = 0x04
    PROBE_RESP = 0x05
    BEACON = 0x08
    ATIM = 0x09
    DISASSOCIATION = 0x0A
    AUTHENTICATION = 0x0B
    DEAUTHENTICATION = 0x0C
    ACTION = 0x0D


# Deauth reason codes (IEEE 802.11)
DEAUTH_REASONS = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending station is leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Disassociated because sending station is leaving",
    9: "Station requesting association is not authenticated",
    10: "Disassociated because power capability is unacceptable",
    11: "Disassociated because supported channels is unacceptable",
    12: "Reserved",
    13: "Invalid information element",
    14: "MIC failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "IE in 4-Way Handshake different from Association",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of security policy",
}


@dataclass
class DeauthEvent:
    """Single deauthentication/disassociation event"""
    timestamp: datetime
    device_timestamp_us: int
    source_mac: str
    bssid: str
    channel: int
    rssi: int
    subtype: int  # 0x0A=disassoc, 0x0C=deauth
    raw_frame_type: int
    
    @property
    def frame_name(self) -> str:
        return "Deauth" if self.subtype == 0x0C else "Disassoc"
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "device_timestamp_us": self.device_timestamp_us,
            "source_mac": self.source_mac,
            "bssid": self.bssid,
            "frame_type": self.frame_name,
            "channel": self.channel,
            "rssi": self.rssi,
            "subtype": self.subtype,
            "raw_frame_type": self.raw_frame_type,
        }


@dataclass
class AttackSession:
    """Represents an ongoing or completed attack session"""
    id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    target_bssid: str = ""
    target_clients: List[str] = field(default_factory=list)
    attacker_mac: str = ""  # Suspected attacker
    frame_count: int = 0
    channels_used: List[int] = field(default_factory=list)
    severity: AttackSeverity = AttackSeverity.LOW
    events: List[DeauthEvent] = field(default_factory=list)
    
    @property
    def duration(self) -> timedelta:
        end = self.end_time or datetime.now()
        return end - self.start_time
    
    @property
    def frames_per_second(self) -> float:
        secs = self.duration.total_seconds()
        return self.frame_count / secs if secs > 0 else 0
    
    @property
    def is_active(self) -> bool:
        return self.end_time is None
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration.total_seconds(),
            "target_bssid": self.target_bssid,
            "target_clients": self.target_clients,
            "attacker_mac": self.attacker_mac,
            "frame_count": self.frame_count,
            "frames_per_second": round(self.frames_per_second, 2),
            "channels_used": list(set(self.channels_used)),
            "severity": self.severity.value,
            "is_active": self.is_active,
        }


@dataclass
class Alert:
    """Security alert for detected attack"""
    id: str
    timestamp: datetime
    severity: AttackSeverity
    title: str
    description: str
    attack_session_id: Optional[str] = None
    indicators: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "attack_session_id": self.attack_session_id,
            "indicators": self.indicators,
            "acknowledged": self.acknowledged,
        }


class DeauthDetector:
    """
    Wireless Deauthentication Attack Detector
    
    Monitors ESP32-S3 HydraSense device for deauth/disassoc frames
    and provides real-time detection and alerting.
    
    Features:
    - Real-time frame monitoring via ESP32
    - Attack pattern recognition
    - Rate-based anomaly detection
    - Session tracking and correlation
    - Forensic evidence logging
    - Webhook/callback alerting
    """
    
    # Detection thresholds (tune to your environment)
    DEAUTH_RATE_THRESHOLD = 10.0  # frames/second to trigger alert
    BURST_WINDOW_SECONDS = 5
    BURST_THRESHOLD = 20  # frames in window
    SESSION_TIMEOUT_SECONDS = 30  # inactivity to end session

    _SEVERITY_RANK = {
        AttackSeverity.INFO: 0,
        AttackSeverity.LOW: 1,
        AttackSeverity.MEDIUM: 2,
        AttackSeverity.HIGH: 3,
        AttackSeverity.CRITICAL: 4,
    }
    
    def __init__(
        self,
        esp32_host: str = "hydrasense.local",
        esp32_port: int = 80,
        poll_interval: float = 1.0,
        auto_discover: bool = True,
        alert_callback: Optional[Callable[[Alert], None]] = None,
        log_file: Optional[str] = None,
    ):
        self.esp32_host = esp32_host
        self.esp32_port = esp32_port
        self.poll_interval = poll_interval
        self.auto_discover = auto_discover
        self.alert_callback = alert_callback
        self.log_file = log_file
        
        self.base_url = f"http://{esp32_host}:{esp32_port}"
        
        # State tracking
        self.running = False
        self.connected = False
        self.last_poll_time: Optional[datetime] = None
        
        # Detection state
        self.events: List[DeauthEvent] = []
        self.attack_sessions: Dict[str, AttackSession] = {}
        self.alerts: List[Alert] = []
        
        # Rate tracking per key (BSSID and attacker)
        self.frame_counts: Dict[str, Deque[datetime]] = defaultdict(deque)

        # Deduplication: ESP32 returns a sliding window; track device timestamp to avoid reprocessing
        self._last_detection_ts_us: int = 0
        
        # Known/trusted BSSIDs (whitelist)
        self.trusted_bssids: set = set()
        
        # Statistics
        self.stats = {
            "total_deauth_frames": 0,
            "total_disassoc_frames": 0,
            "total_attacks_detected": 0,
            "total_alerts": 0,
            "uptime_start": None,
            "last_event_time": None,
        }
        
        # Background tasks
        self._monitor_task: Optional[asyncio.Task] = None
        self._session_cleanup_task: Optional[asyncio.Task] = None

        # Shared HTTP session
        self._http: Optional[aiohttp.ClientSession] = None
    
    async def start(self) -> bool:
        """Start the deauth detection monitor"""
        if self.running:
            logger.warning("Detector already running")
            return True

        # Create shared HTTP session
        if self._http is None or self._http.closed:
            self._http = aiohttp.ClientSession()

        # Test connection to ESP32 (with optional auto-discovery)
        ok = await self._test_connection()
        if not ok and self.auto_discover:
            ok = await self._discover_and_connect()
        if not ok:
            logger.error(f"Cannot connect to ESP32 at {self.base_url}")
            await self.stop()
            return False
        
        self.running = True
        self.stats["uptime_start"] = datetime.now()
        
        # Start monitoring tasks
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._session_cleanup_task = asyncio.create_task(self._session_cleanup_loop())
        
        logger.info(f"Deauth detector started - monitoring {self.base_url}")
        return True
    
    async def stop(self):
        """Stop the deauth detection monitor"""
        self.running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        if self._session_cleanup_task:
            self._session_cleanup_task.cancel()
            try:
                await self._session_cleanup_task
            except asyncio.CancelledError:
                pass

        if self._http and not self._http.closed:
            await self._http.close()
        self._http = None
        
        logger.info("Deauth detector stopped")
    
    async def _test_connection(self) -> bool:
        """Test connection to ESP32"""
        try:
            if self._http is None or self._http.closed:
                self._http = aiohttp.ClientSession()
            async with self._http.get(
                f"{self.base_url}/status",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    self.connected = True
                    return True
        except Exception as e:
            logger.debug(f"Connection test failed: {e}")
        
        self.connected = False
        return False

    async def _discover_and_connect(self) -> bool:
        """Try common ESP32 hostnames/IPs and adopt the first reachable one."""
        candidates: List[str] = []
        # 1) User-provided host first
        if self.esp32_host:
            candidates.append(self.esp32_host)
        # 2) Common mDNS name
        candidates.append("hydrasense.local")
        # 3) Default HydraSense AP gateway
        candidates.append("192.168.4.1")

        tried: set = set()
        for host in candidates:
            if not host or host in tried:
                continue
            tried.add(host)
            self.esp32_host = host
            self.base_url = f"http://{self.esp32_host}:{self.esp32_port}"
            if await self._test_connection():
                logger.info(f"ESP32 discovered at {self.base_url}")
                return True
        return False
    
    async def _monitor_loop(self):
        """Main monitoring loop - polls ESP32 for scan data"""
        while self.running:
            try:
                await self._poll_esp32()
                await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                await asyncio.sleep(self.poll_interval * 2)
    
    async def _poll_esp32(self):
        """Poll ESP32 for latest scan data"""
        try:
            if self._http is None or self._http.closed:
                self._http = aiohttp.ClientSession()
            async with self._http.get(
                f"{self.base_url}/scan",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    self.connected = False
                    return

                self.connected = True
                self.last_poll_time = datetime.now()

                data = await resp.json()
                await self._process_scan_data(data)
                    
        except aiohttp.ClientError as e:
            self.connected = False
            logger.debug(f"ESP32 poll failed: {e}")
        except Exception as e:
            logger.error(f"Error polling ESP32: {e}")
    
    async def _process_scan_data(self, data: dict):
        """Process scan data from ESP32 and detect deauth/disassoc floods.

        HydraSense encodes `frame_type` as: `(type << 8) | subtype`.
        Management frames have `type == 0`.
        """
        detections = data.get("detections", [])

        max_ts_us = self._last_detection_ts_us
        for det in detections:
            ts_us = int(det.get("timestamp_us", 0) or 0)
            if ts_us <= self._last_detection_ts_us:
                continue
            if ts_us > max_ts_us:
                max_ts_us = ts_us

            raw_frame_type = int(det.get("frame_type", 0) or 0)
            frame_type = (raw_frame_type >> 8) & 0x03
            subtype = raw_frame_type & 0x0F

            # Only management deauth/disassoc
            if frame_type != 0 or subtype not in (0x0A, 0x0C):
                continue

            bssid = det.get("bssid", "") or ""
            source_mac = det.get("mac", "00:00:00:00:00:00") or "00:00:00:00:00:00"

            event = DeauthEvent(
                timestamp=datetime.now(),
                device_timestamp_us=ts_us,
                source_mac=source_mac,
                bssid=bssid,
                channel=int(det.get("channel", 0) or 0),
                rssi=int(det.get("rssi", 0) or 0),
                subtype=subtype,
                raw_frame_type=raw_frame_type,
            )
            await self._handle_deauth_event(event)

        self._last_detection_ts_us = max_ts_us
    
    async def _handle_deauth_event(self, event: DeauthEvent):
        """Handle a detected deauth/disassoc event"""
        # Update statistics
        if event.subtype == 0x0C:
            self.stats["total_deauth_frames"] += 1
        else:
            self.stats["total_disassoc_frames"] += 1
        
        self.stats["last_event_time"] = event.timestamp
        
        # Store event
        self.events.append(event)
        if len(self.events) > 10000:
            self.events = self.events[-5000:]  # Keep last 5000
        
        # Track frame rate (per BSSID + attacker)
        key = self._rate_key(event)
        q = self.frame_counts[key]
        q.append(event.timestamp)

        cutoff = datetime.now() - timedelta(seconds=60)
        while q and q[0] <= cutoff:
            q.popleft()
        
        # Check for attack patterns
        await self._analyze_attack_pattern(event, key)
        
        # Log to file if configured
        if self.log_file:
            await self._log_event(event)
        
        logger.debug(
            f"{event.frame_name} detected: src={event.source_mac} bssid={event.bssid} "
            f"ch={event.channel} rssi={event.rssi}"
        )

    def _rate_key(self, event: DeauthEvent) -> str:
        bssid = (event.bssid or "").upper() or "UNKNOWN_BSSID"
        src = (event.source_mac or "").upper() or "UNKNOWN_SRC"
        return f"{bssid}|{src}"
    
    async def _analyze_attack_pattern(self, event: DeauthEvent, key: str):
        """Analyze event for attack patterns"""
        now = datetime.now()
        
        # Calculate current rate
        q = self.frame_counts.get(key)
        if not q:
            return
        window_start = now - timedelta(seconds=self.BURST_WINDOW_SECONDS)
        recent_count = sum(1 for t in q if t > window_start)
        current_rate = recent_count / float(self.BURST_WINDOW_SECONDS)
        
        # Check if this looks like an attack
        is_attack = False
        severity = AttackSeverity.LOW
        
        if recent_count >= self.BURST_THRESHOLD:
            is_attack = True
            severity = AttackSeverity.HIGH
        elif current_rate >= self.DEAUTH_RATE_THRESHOLD:
            is_attack = True
            severity = AttackSeverity.MEDIUM
        
        if is_attack:
            await self._handle_attack_detected(event, key, severity, current_rate)
    
    async def _handle_attack_detected(
        self,
        event: DeauthEvent,
        key: str,
        severity: AttackSeverity,
        rate: float
    ):
        """Handle detection of an attack"""
        # Find or create attack session
        session_key = key
        
        if session_key in self.attack_sessions:
            session = self.attack_sessions[session_key]
            if session.is_active:
                # Update existing session
                session.frame_count += 1
                session.events.append(event)
                if event.channel not in session.channels_used:
                    session.channels_used.append(event.channel)

                # Escalate severity if needed
                if self._SEVERITY_RANK[severity] > self._SEVERITY_RANK[session.severity]:
                    session.severity = severity
                
                return  # Don't create new alert for same session
        
        # Create new attack session
        session_id = hashlib.md5(
            f"{key}{datetime.now().timestamp()}".encode()
        ).hexdigest()[:12]
        
        session = AttackSession(
            id=session_id,
            start_time=datetime.now(),
            target_bssid=event.bssid,
            target_clients=[],
            attacker_mac=event.source_mac,
            frame_count=1,
            channels_used=[event.channel],
            severity=severity,
            events=[event],
        )
        
        self.attack_sessions[session_key] = session
        self.stats["total_attacks_detected"] += 1
        
        # Generate alert
        await self._generate_alert(session, event, rate)
    
    async def _generate_alert(
        self,
        session: AttackSession,
        event: DeauthEvent,
        rate: float
    ):
        """Generate and dispatch an alert"""
        alert_id = hashlib.md5(
            f"alert_{session.id}_{datetime.now().timestamp()}".encode()
        ).hexdigest()[:12]
        
        title = f"Deauth/Disassoc Flood Detected on {session.target_bssid or 'unknown BSSID'}"
        description = (
            f"High-rate {event.frame_name.lower()} frames observed for BSSID {session.target_bssid or 'unknown'} "
            f"from source MAC {session.attacker_mac}. Rate: {rate:.1f} frames/sec. "
            f"Channel: {event.channel}."
        )
        
        alert = Alert(
            id=alert_id,
            timestamp=datetime.now(),
            severity=session.severity,
            title=title,
            description=description,
            attack_session_id=session.id,
            indicators={
                "attacker_mac": session.attacker_mac,
                "target_bssid": session.target_bssid,
                "frame_rate": round(rate, 2),
                "channel": event.channel,
                "frame_kind": event.frame_name,
                "device_timestamp_us": event.device_timestamp_us,
            }
        )
        
        self.alerts.append(alert)
        self.stats["total_alerts"] += 1
        
        # Log alert
        logger.warning(f"ALERT [{alert.severity.value.upper()}]: {alert.title}")
        
        # Call alert callback if configured
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    async def _session_cleanup_loop(self):
        """Periodically clean up inactive attack sessions"""
        while self.running:
            try:
                await asyncio.sleep(10)
                await self._cleanup_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")
    
    async def _cleanup_sessions(self):
        """Mark inactive sessions as ended"""
        now = datetime.now()
        timeout = timedelta(seconds=self.SESSION_TIMEOUT_SECONDS)
        
        for key, session in self.attack_sessions.items():
            if session.is_active:
                if session.events:
                    last_event_time = session.events[-1].timestamp
                    if now - last_event_time > timeout:
                        session.end_time = last_event_time
                        logger.info(
                            f"Attack session {session.id} ended - "
                            f"{session.frame_count} frames over {session.duration}"
                        )
    
    async def _log_event(self, event: DeauthEvent):
        """Log event to file"""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
    
    # ==================== Public API ====================
    
    def add_trusted_bssid(self, bssid: str):
        """Add a BSSID to the trusted list (reduces false positives)"""
        self.trusted_bssids.add(bssid.upper())
    
    def remove_trusted_bssid(self, bssid: str):
        """Remove a BSSID from the trusted list"""
        self.trusted_bssids.discard(bssid.upper())
    
    def get_status(self) -> dict:
        """Get current detector status"""
        uptime = None
        if self.stats["uptime_start"]:
            uptime = (datetime.now() - self.stats["uptime_start"]).total_seconds()
        
        return {
            "running": self.running,
            "connected": self.connected,
            "esp32_host": self.esp32_host,
            "last_poll": self.last_poll_time.isoformat() if self.last_poll_time else None,
            "uptime_seconds": uptime,
            "stats": {
                "total_deauth_frames": self.stats["total_deauth_frames"],
                "total_disassoc_frames": self.stats["total_disassoc_frames"],
                "total_attacks_detected": self.stats["total_attacks_detected"],
                "total_alerts": self.stats["total_alerts"],
                "active_sessions": sum(
                    1 for s in self.attack_sessions.values() if s.is_active
                ),
            }
        }
    
    def get_recent_events(self, limit: int = 100) -> List[dict]:
        """Get recent deauth/disassoc events"""
        return [e.to_dict() for e in self.events[-limit:]]
    
    def get_active_attacks(self) -> List[dict]:
        """Get currently active attack sessions"""
        return [
            s.to_dict() for s in self.attack_sessions.values()
            if s.is_active
        ]
    
    def get_all_attacks(self, limit: int = 50) -> List[dict]:
        """Get all attack sessions"""
        sessions = sorted(
            self.attack_sessions.values(),
            key=lambda s: s.start_time,
            reverse=True
        )
        return [s.to_dict() for s in sessions[:limit]]
    
    def get_alerts(self, unacknowledged_only: bool = False, limit: int = 100) -> List[dict]:
        """Get alerts"""
        alerts = self.alerts
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]
        return [a.to_dict() for a in alerts[-limit:]]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                return True
        return False
    
    def get_attack_summary(self) -> dict:
        """Get summary statistics of attacks"""
        if not self.attack_sessions:
            return {
                "total_attacks": 0,
                "active_attacks": 0,
                "most_targeted_bssids": [],
                "suspected_attackers": [],
            }
        
        # Count targets
        target_counts: Dict[str, int] = defaultdict(int)
        attacker_counts: Dict[str, int] = defaultdict(int)
        
        for session in self.attack_sessions.values():
            target_counts[session.target_bssid] += session.frame_count
            attacker_counts[session.attacker_mac] += session.frame_count
        
        # Sort by count
        top_targets = sorted(
            target_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        top_attackers = sorted(
            attacker_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        
        return {
            "total_attacks": len(self.attack_sessions),
            "active_attacks": sum(
                1 for s in self.attack_sessions.values() if s.is_active
            ),
            "total_frames": self.stats["total_deauth_frames"] + self.stats["total_disassoc_frames"],
            "most_targeted_bssids": [
                {"bssid": b, "frame_count": c} for b, c in top_targets
            ],
            "suspected_attackers": [
                {"mac": m, "frame_count": c} for m, c in top_attackers
            ],
        }


# ==================== CLI Interface ====================

async def main():
    """CLI entry point for standalone usage"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ESP32 Wireless IDS (Deauth/Disassoc flood detection)"
    )
    parser.add_argument(
        "--host", default="hydrasense.local",
        help="ESP32 hostname or IP"
    )
    parser.add_argument(
        "--port", type=int, default=80,
        help="ESP32 HTTP port"
    )
    parser.add_argument(
        "--interval", type=float, default=1.0,
        help="Polling interval in seconds"
    )
    parser.add_argument(
        "--no-auto-discover", action="store_true",
        help="Disable host auto-discovery (hydrasense.local, 192.168.4.1)"
    )
    parser.add_argument(
        "--log-file", default=None,
        help="File to log events to"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Alert callback for CLI
    def print_alert(alert: Alert):
        severity_colors = {
            AttackSeverity.INFO: "\033[36m",     # Cyan
            AttackSeverity.LOW: "\033[32m",      # Green
            AttackSeverity.MEDIUM: "\033[33m",   # Yellow
            AttackSeverity.HIGH: "\033[31m",     # Red
            AttackSeverity.CRITICAL: "\033[35m", # Magenta
        }
        reset = "\033[0m"
        color = severity_colors.get(alert.severity, "")
        
        print(f"\n{color}{'='*60}")
        print(f"🚨 ALERT: {alert.title}")
        print(f"Severity: {alert.severity.value.upper()}")
        print(f"Time: {alert.timestamp}")
        print(f"{'='*60}{reset}")
        print(alert.description)
        print(f"Indicators: {json.dumps(alert.indicators, indent=2)}")
        print()
    
    # Create and start detector
    detector = DeauthDetector(
        esp32_host=args.host,
        esp32_port=args.port,
        poll_interval=args.interval,
        auto_discover=not args.no_auto_discover,
        alert_callback=print_alert,
        log_file=args.log_file,
    )
    
    print("Starting wireless IDS detector...")
    print(f"ESP32 (initial): http://{args.host}:{args.port}")
    if not args.no_auto_discover:
        print("Auto-discovery: enabled (hydrasense.local, 192.168.4.1)")
    print(f"Press Ctrl+C to stop\n")
    
    if not await detector.start():
        print("Failed to start detector - check ESP32 connection")
        return
    
    try:
        # Run until interrupted
        while True:
            await asyncio.sleep(5)
            status = detector.get_status()
            if status["connected"]:
                stats = status["stats"]
                print(
                    f"\r📡 Connected | Deauth: {stats['total_deauth_frames']} | "
                    f"Disassoc: {stats['total_disassoc_frames']} | "
                    f"Attacks: {stats['total_attacks_detected']} | "
                    f"Active: {stats['active_sessions']}   ",
                    end="", flush=True
                )
            else:
                print("\r⚠️  Disconnected - reconnecting...", end="", flush=True)
    
    except KeyboardInterrupt:
        print("\n\nStopping...")
    
    finally:
        await detector.stop()
        
        # Print summary
        summary = detector.get_attack_summary()
        print("\n" + "="*60)
        print("SESSION SUMMARY")
        print("="*60)
        print(f"Total attacks detected: {summary['total_attacks']}")
        print(f"Total frames captured: {summary['total_frames']}")
        
        if summary['most_targeted_bssids']:
            print("\nMost targeted networks:")
            for t in summary['most_targeted_bssids'][:5]:
                print(f"  {t['bssid']}: {t['frame_count']} frames")
        
        if summary['suspected_attackers']:
            print("\nSuspected attacker MACs:")
            for a in summary['suspected_attackers'][:5]:
                print(f"  {a['mac']}: {a['frame_count']} frames")


if __name__ == "__main__":
    asyncio.run(main())
