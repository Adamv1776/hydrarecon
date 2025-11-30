#!/usr/bin/env python3
"""
HydraRecon Base Scanner
Abstract base class for all scanning modules.
"""

import asyncio
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, AsyncIterator
from queue import Queue
import uuid


class ScanStatus(Enum):
    """Scan status enumeration"""
    PENDING = auto()
    INITIALIZING = auto()
    RUNNING = auto()
    PAUSED = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


class ScanPriority(Enum):
    """Scan priority levels"""
    LOW = 1
    NORMAL = 5
    HIGH = 8
    CRITICAL = 10


@dataclass
class ScanResult:
    """Generic scan result container"""
    scan_id: str
    scan_type: str
    target: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    data: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_output: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanProgress:
    """Scan progress information"""
    scan_id: str
    current: int
    total: int
    percentage: float
    message: str
    stage: str = ""
    eta_seconds: Optional[int] = None


class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, config: Any, db: Any):
        """Initialize base scanner"""
        self.config = config
        self.db = db
        self.scan_id = str(uuid.uuid4())
        self.status = ScanStatus.PENDING
        self.progress = 0
        self.total_targets = 0
        self.current_target = 0
        self._cancel_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused by default
        
        # Callbacks
        self._progress_callbacks: List[Callable[[ScanProgress], None]] = []
        self._result_callbacks: List[Callable[[ScanResult], None]] = []
        self._error_callbacks: List[Callable[[str], None]] = []
    
    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Return scanner name"""
        pass
    
    @property
    @abstractmethod
    def scanner_type(self) -> str:
        """Return scanner type"""
        pass
    
    @abstractmethod
    async def scan(self, target: str, **options) -> ScanResult:
        """Execute scan on a single target"""
        pass
    
    @abstractmethod
    async def validate_target(self, target: str) -> bool:
        """Validate target before scanning"""
        pass
    
    def on_progress(self, callback: Callable[[ScanProgress], None]):
        """Register progress callback"""
        self._progress_callbacks.append(callback)
    
    def on_result(self, callback: Callable[[ScanResult], None]):
        """Register result callback"""
        self._result_callbacks.append(callback)
    
    def on_error(self, callback: Callable[[str], None]):
        """Register error callback"""
        self._error_callbacks.append(callback)
    
    def emit_progress(self, current: int, total: int, message: str, stage: str = ""):
        """Emit progress update"""
        progress = ScanProgress(
            scan_id=self.scan_id,
            current=current,
            total=total,
            percentage=(current / total * 100) if total > 0 else 0,
            message=message,
            stage=stage
        )
        for callback in self._progress_callbacks:
            try:
                callback(progress)
            except Exception:
                pass
    
    def emit_result(self, result: ScanResult):
        """Emit scan result"""
        for callback in self._result_callbacks:
            try:
                callback(result)
            except Exception:
                pass
    
    def emit_error(self, error: str):
        """Emit error"""
        for callback in self._error_callbacks:
            try:
                callback(error)
            except Exception:
                pass
    
    def cancel(self):
        """Cancel the scan"""
        self._cancel_event.set()
        self.status = ScanStatus.CANCELLED
    
    def pause(self):
        """Pause the scan"""
        self._pause_event.clear()
        self.status = ScanStatus.PAUSED
    
    def resume(self):
        """Resume the scan"""
        self._pause_event.set()
        self.status = ScanStatus.RUNNING
    
    def is_cancelled(self) -> bool:
        """Check if scan is cancelled"""
        return self._cancel_event.is_set()
    
    def wait_if_paused(self):
        """Wait if scan is paused"""
        self._pause_event.wait()
    
    async def scan_multiple(self, targets: List[str], **options) -> List[ScanResult]:
        """Scan multiple targets"""
        self.total_targets = len(targets)
        self.status = ScanStatus.RUNNING
        results = []
        
        for i, target in enumerate(targets):
            if self.is_cancelled():
                break
            
            self.wait_if_paused()
            self.current_target = i + 1
            
            self.emit_progress(
                i + 1, self.total_targets,
                f"Scanning {target}",
                stage="scanning"
            )
            
            try:
                result = await self.scan(target, **options)
                results.append(result)
                self.emit_result(result)
            except Exception as e:
                error_msg = f"Error scanning {target}: {str(e)}"
                self.emit_error(error_msg)
                results.append(ScanResult(
                    scan_id=self.scan_id,
                    scan_type=self.scanner_type,
                    target=target,
                    status=ScanStatus.FAILED,
                    started_at=datetime.now(),
                    errors=[error_msg]
                ))
        
        self.status = ScanStatus.COMPLETED if not self.is_cancelled() else ScanStatus.CANCELLED
        return results


class ScanQueue:
    """Queue manager for scans"""
    
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self._queue: Queue = Queue()
        self._active_scans: Dict[str, BaseScanner] = {}
        self._completed_scans: Dict[str, ScanResult] = {}
        self._lock = threading.Lock()
    
    def add_scan(self, scanner: BaseScanner, priority: ScanPriority = ScanPriority.NORMAL):
        """Add scan to queue"""
        self._queue.put((priority.value, scanner))
    
    def get_active_scans(self) -> List[BaseScanner]:
        """Get list of active scans"""
        with self._lock:
            return list(self._active_scans.values())
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanStatus]:
        """Get status of a scan"""
        with self._lock:
            if scan_id in self._active_scans:
                return self._active_scans[scan_id].status
            if scan_id in self._completed_scans:
                return self._completed_scans[scan_id].status
        return None
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a specific scan"""
        with self._lock:
            if scan_id in self._active_scans:
                self._active_scans[scan_id].cancel()
                return True
        return False
    
    def cancel_all(self):
        """Cancel all scans"""
        with self._lock:
            for scanner in self._active_scans.values():
                scanner.cancel()
