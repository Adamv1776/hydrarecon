#!/usr/bin/env python3
"""
HydraRecon - Telemetry and Crash Reporting
═══════════════════════════════════════════════════════════════════════════════
Anonymous usage statistics and crash reporting for product improvement.
All telemetry is opt-in and respects user privacy.
═══════════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import json
import uuid
import hashlib
import platform
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import threading
import queue

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class TelemetryConfig:
    """Telemetry configuration"""
    
    # Remote endpoint (configure for your server)
    ENDPOINT = os.environ.get('HYDRARECON_TELEMETRY_URL', '')
    
    # Enable/disable flags
    ENABLED = os.environ.get('HYDRARECON_TELEMETRY', '0') == '1'
    CRASH_REPORTS = os.environ.get('HYDRARECON_CRASH_REPORTS', '1') == '1'
    
    # Local storage
    CONFIG_DIR = Path.home() / '.hydrarecon'
    TELEMETRY_FILE = CONFIG_DIR / 'telemetry.json'
    CRASH_QUEUE = CONFIG_DIR / 'crash_queue.json'


class AnonymousID:
    """Generate anonymous installation ID"""
    
    @staticmethod
    def get_or_create() -> str:
        """Get or create anonymous installation ID"""
        TelemetryConfig.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        if TelemetryConfig.TELEMETRY_FILE.exists():
            try:
                with open(TelemetryConfig.TELEMETRY_FILE) as f:
                    data = json.load(f)
                    if 'installation_id' in data:
                        return data['installation_id']
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Generate new anonymous ID
        # Based on hardware + random, not personally identifiable
        hardware_hash = hashlib.sha256(
            f"{platform.node()}{platform.machine()}".encode()
        ).hexdigest()[:16]
        
        random_part = uuid.uuid4().hex[:16]
        installation_id = f"hr_{hardware_hash}_{random_part}"
        
        # Save
        with open(TelemetryConfig.TELEMETRY_FILE, 'w') as f:
            json.dump({
                'installation_id': installation_id,
                'created': datetime.now().isoformat(),
                'telemetry_enabled': TelemetryConfig.ENABLED,
                'crash_reports_enabled': TelemetryConfig.CRASH_REPORTS,
            }, f, indent=2)
        
        return installation_id


class TelemetryEvent:
    """Represents a telemetry event"""
    
    def __init__(self, event_type: str, data: Dict[str, Any] = None):
        self.event_type = event_type
        self.data = data or {}
        self.timestamp = datetime.now().isoformat()
        self.installation_id = AnonymousID.get_or_create()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_type': self.event_type,
            'timestamp': self.timestamp,
            'installation_id': self.installation_id,
            'platform': {
                'os': platform.system(),
                'os_version': platform.release(),
                'python_version': platform.python_version(),
                'arch': platform.machine(),
            },
            'data': self.data
        }


class CrashReport:
    """Represents a crash report"""
    
    def __init__(self, exc_type, exc_value, exc_tb, context: str = ""):
        self.exc_type = exc_type.__name__ if exc_type else "Unknown"
        self.exc_value = str(exc_value) if exc_value else ""
        self.traceback = traceback.format_exception(exc_type, exc_value, exc_tb)
        self.context = context
        self.timestamp = datetime.now().isoformat()
        self.installation_id = AnonymousID.get_or_create()
    
    def to_dict(self) -> Dict[str, Any]:
        # Sanitize traceback - remove file paths that might contain usernames
        sanitized_tb = []
        for line in self.traceback:
            # Replace home directory paths
            line = line.replace(str(Path.home()), '~')
            sanitized_tb.append(line)
        
        return {
            'type': 'crash_report',
            'timestamp': self.timestamp,
            'installation_id': self.installation_id,
            'exception': {
                'type': self.exc_type,
                'message': self.exc_value[:500],  # Truncate long messages
                'traceback': sanitized_tb[-20:],  # Last 20 lines only
            },
            'context': self.context[:200],
            'platform': {
                'os': platform.system(),
                'os_version': platform.release(),
                'python_version': platform.python_version(),
            },
            'app_version': '1.0.0',
        }
    
    def save_locally(self):
        """Save crash report locally for later submission"""
        TelemetryConfig.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Load existing queue
        queue_data = []
        if TelemetryConfig.CRASH_QUEUE.exists():
            try:
                with open(TelemetryConfig.CRASH_QUEUE) as f:
                    queue_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        
        # Add new report (max 10 queued)
        queue_data.append(self.to_dict())
        queue_data = queue_data[-10:]
        
        with open(TelemetryConfig.CRASH_QUEUE, 'w') as f:
            json.dump(queue_data, f, indent=2)


class TelemetryClient:
    """Handles telemetry transmission"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._queue = queue.Queue()
        self._worker = None
        self._running = False
        self._initialized = True
    
    def start(self):
        """Start telemetry worker thread"""
        if not TelemetryConfig.ENABLED and not TelemetryConfig.CRASH_REPORTS:
            return
        
        if not REQUESTS_AVAILABLE:
            return
        
        self._running = True
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()
    
    def stop(self):
        """Stop telemetry worker"""
        self._running = False
        if self._worker:
            self._queue.put(None)  # Signal to stop
            self._worker.join(timeout=2)
    
    def track_event(self, event_type: str, data: Dict[str, Any] = None):
        """Track an event"""
        if not TelemetryConfig.ENABLED:
            return
        
        event = TelemetryEvent(event_type, data)
        self._queue.put(('event', event.to_dict()))
    
    def report_crash(self, exc_type, exc_value, exc_tb, context: str = ""):
        """Report a crash"""
        report = CrashReport(exc_type, exc_value, exc_tb, context)
        
        # Always save locally
        report.save_locally()
        
        # Submit if enabled
        if TelemetryConfig.CRASH_REPORTS:
            self._queue.put(('crash', report.to_dict()))
    
    def _worker_loop(self):
        """Background worker for sending telemetry"""
        while self._running:
            try:
                item = self._queue.get(timeout=1)
                if item is None:
                    break
                
                event_type, data = item
                self._send(event_type, data)
                
            except queue.Empty:
                continue
            except Exception:
                pass  # Silently fail - telemetry should never break the app
    
    def _send(self, event_type: str, data: Dict[str, Any]):
        """Send data to telemetry endpoint"""
        if not TelemetryConfig.ENDPOINT:
            return
        
        try:
            requests.post(
                TelemetryConfig.ENDPOINT,
                json={'type': event_type, 'payload': data},
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
        except Exception:
            pass  # Silently fail


# Convenience functions
_client: Optional[TelemetryClient] = None


def init_telemetry():
    """Initialize telemetry system"""
    global _client
    _client = TelemetryClient()
    _client.start()


def track(event_type: str, data: Dict[str, Any] = None):
    """Track an event"""
    if _client:
        _client.track_event(event_type, data)


def report_crash(exc_type, exc_value, exc_tb, context: str = ""):
    """Report a crash"""
    if _client:
        _client.report_crash(exc_type, exc_value, exc_tb, context)
    else:
        # Still save locally even if client not initialized
        CrashReport(exc_type, exc_value, exc_tb, context).save_locally()


def shutdown():
    """Shutdown telemetry"""
    if _client:
        _client.stop()


# Usage tracking events
class Events:
    """Standard telemetry events"""
    
    APP_START = 'app_start'
    APP_EXIT = 'app_exit'
    SCAN_START = 'scan_start'
    SCAN_COMPLETE = 'scan_complete'
    FEATURE_USED = 'feature_used'
    ERROR = 'error'


if __name__ == '__main__':
    # Test telemetry
    print("Testing telemetry system...")
    
    init_telemetry()
    
    track(Events.APP_START, {'version': '1.0.0'})
    track(Events.FEATURE_USED, {'feature': 'nmap_scan'})
    
    # Test crash report
    try:
        raise ValueError("Test error")
    except Exception:
        report_crash(*sys.exc_info(), context="test")
    
    shutdown()
    
    print("Telemetry test complete")
    print(f"Config dir: {TelemetryConfig.CONFIG_DIR}")
    print(f"Installation ID: {AnonymousID.get_or_create()}")
