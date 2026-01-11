#!/usr/bin/env python3
"""
HydraRecon - Performance Optimization Module
═══════════════════════════════════════════════════════════════════════════════
Memory management, lazy loading, and performance monitoring for production.
═══════════════════════════════════════════════════════════════════════════════
"""

import gc
import sys
import time
import psutil
import threading
import functools
import weakref
from typing import Dict, Any, Optional, Callable, Type
from collections import OrderedDict
from datetime import datetime


class MemoryManager:
    """
    Production-grade memory management for large applications.
    Monitors memory usage and performs cleanup when thresholds are exceeded.
    """
    
    # Memory thresholds (MB)
    WARNING_THRESHOLD = 1024  # 1GB - start warning
    CLEANUP_THRESHOLD = 1536  # 1.5GB - trigger cleanup
    CRITICAL_THRESHOLD = 2048  # 2GB - aggressive cleanup
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._process = psutil.Process()
        self._caches: Dict[str, weakref.ref] = {}
        self._cleanup_callbacks: list = []
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._last_cleanup = time.time()
    
    def get_memory_mb(self) -> float:
        """Get current process memory usage in MB"""
        return self._process.memory_info().rss / (1024 * 1024)
    
    def get_memory_percent(self) -> float:
        """Get memory usage as percentage of system RAM"""
        return self._process.memory_percent()
    
    def register_cache(self, name: str, cache_obj):
        """Register a cache for cleanup during memory pressure"""
        self._caches[name] = weakref.ref(cache_obj)
    
    def register_cleanup_callback(self, callback: Callable):
        """Register a callback to run during memory cleanup"""
        self._cleanup_callbacks.append(callback)
    
    def cleanup(self, aggressive: bool = False):
        """
        Perform memory cleanup.
        
        Args:
            aggressive: If True, clear all caches. If False, partial cleanup.
        """
        # Clear registered caches
        for name, cache_ref in list(self._caches.items()):
            cache = cache_ref()
            if cache is None:
                del self._caches[name]
                continue
            
            if hasattr(cache, 'clear'):
                if aggressive:
                    cache.clear()
                elif hasattr(cache, 'trim'):
                    cache.trim()
        
        # Run cleanup callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback(aggressive)
            except Exception:
                pass
        
        # Force garbage collection
        gc.collect()
        
        self._last_cleanup = time.time()
    
    def start_monitoring(self, interval: float = 30.0):
        """Start background memory monitoring"""
        if self._running:
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop background memory monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
    
    def _monitor_loop(self, interval: float):
        """Background monitoring loop"""
        while self._running:
            memory_mb = self.get_memory_mb()
            
            if memory_mb > self.CRITICAL_THRESHOLD:
                print(f"⚠️  CRITICAL: Memory usage {memory_mb:.0f}MB - aggressive cleanup")
                self.cleanup(aggressive=True)
            elif memory_mb > self.CLEANUP_THRESHOLD:
                if time.time() - self._last_cleanup > 60:  # Max once per minute
                    print(f"⚠️  HIGH: Memory usage {memory_mb:.0f}MB - cleanup")
                    self.cleanup(aggressive=False)
            
            time.sleep(interval)


class LRUCache:
    """Thread-safe LRU cache with memory-aware eviction"""
    
    def __init__(self, maxsize: int = 128):
        self.maxsize = maxsize
        self._cache = OrderedDict()
        self._lock = threading.Lock()
    
    def get(self, key, default=None):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return default
    
    def put(self, key, value):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)
    
    def clear(self):
        with self._lock:
            self._cache.clear()
    
    def trim(self, keep: int = None):
        """Trim cache to specified size"""
        keep = keep or self.maxsize // 2
        with self._lock:
            while len(self._cache) > keep:
                self._cache.popitem(last=False)
    
    def __len__(self):
        return len(self._cache)
    
    def __contains__(self, key):
        return key in self._cache


class LazyLoader:
    """
    Lazy module loader that delays imports until first use.
    Significantly reduces startup time for large applications.
    """
    
    _loaded_modules: Dict[str, Any] = {}
    _load_times: Dict[str, float] = {}
    
    @classmethod
    def load(cls, module_name: str) -> Any:
        """Load a module lazily"""
        if module_name not in cls._loaded_modules:
            start = time.time()
            cls._loaded_modules[module_name] = __import__(module_name)
            cls._load_times[module_name] = time.time() - start
        
        return cls._loaded_modules[module_name]
    
    @classmethod
    def load_from(cls, module_name: str, attribute: str) -> Any:
        """Load an attribute from a module lazily"""
        module = cls.load(module_name)
        return getattr(module, attribute)
    
    @classmethod
    def get_load_times(cls) -> Dict[str, float]:
        """Get module load times for profiling"""
        return cls._load_times.copy()


def lazy_import(module_name: str, attribute: str = None):
    """
    Decorator for lazy importing.
    
    Usage:
        @lazy_import('heavy_module', 'HeavyClass')
        def get_heavy_class():
            pass
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if attribute:
                return LazyLoader.load_from(module_name, attribute)
            return LazyLoader.load(module_name)
        return wrapper
    return decorator


class PerformanceProfiler:
    """
    Simple performance profiler for identifying bottlenecks.
    """
    
    _timings: Dict[str, list] = {}
    _lock = threading.Lock()
    _enabled = True
    
    @classmethod
    def enable(cls):
        cls._enabled = True
    
    @classmethod
    def disable(cls):
        cls._enabled = False
    
    @classmethod
    def time(cls, name: str):
        """Context manager for timing code blocks"""
        return _TimingContext(name, cls)
    
    @classmethod
    def record(cls, name: str, duration: float):
        """Record a timing"""
        if not cls._enabled:
            return
        
        with cls._lock:
            if name not in cls._timings:
                cls._timings[name] = []
            cls._timings[name].append(duration)
            
            # Keep only last 100 timings
            if len(cls._timings[name]) > 100:
                cls._timings[name] = cls._timings[name][-100:]
    
    @classmethod
    def get_stats(cls) -> Dict[str, Dict[str, float]]:
        """Get timing statistics"""
        stats = {}
        
        with cls._lock:
            for name, timings in cls._timings.items():
                if timings:
                    stats[name] = {
                        'count': len(timings),
                        'total': sum(timings),
                        'avg': sum(timings) / len(timings),
                        'min': min(timings),
                        'max': max(timings),
                    }
        
        return stats
    
    @classmethod
    def clear(cls):
        """Clear all timings"""
        with cls._lock:
            cls._timings.clear()
    
    @classmethod
    def report(cls) -> str:
        """Generate a performance report"""
        stats = cls.get_stats()
        
        if not stats:
            return "No performance data collected"
        
        lines = ["Performance Report", "=" * 60]
        
        # Sort by total time descending
        sorted_stats = sorted(
            stats.items(),
            key=lambda x: x[1]['total'],
            reverse=True
        )
        
        for name, data in sorted_stats[:20]:  # Top 20
            lines.append(
                f"{name:40} "
                f"calls={data['count']:5} "
                f"total={data['total']:8.3f}s "
                f"avg={data['avg']*1000:7.2f}ms"
            )
        
        return "\n".join(lines)


class _TimingContext:
    """Context manager for timing code blocks"""
    
    def __init__(self, name: str, profiler: Type[PerformanceProfiler]):
        self.name = name
        self.profiler = profiler
        self.start = None
    
    def __enter__(self):
        self.start = time.perf_counter()
        return self
    
    def __exit__(self, *args):
        duration = time.perf_counter() - self.start
        self.profiler.record(self.name, duration)


def timed(name: str = None):
    """
    Decorator to time function execution.
    
    Usage:
        @timed("database_query")
        def query_database():
            pass
    """
    def decorator(func):
        timing_name = name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with PerformanceProfiler.time(timing_name):
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


class ObjectPool:
    """
    Object pool for expensive-to-create objects.
    Reduces GC pressure and improves performance.
    """
    
    def __init__(self, factory: Callable, max_size: int = 10):
        self._factory = factory
        self._max_size = max_size
        self._pool: list = []
        self._lock = threading.Lock()
    
    def acquire(self):
        """Get an object from the pool or create a new one"""
        with self._lock:
            if self._pool:
                return self._pool.pop()
        
        return self._factory()
    
    def release(self, obj):
        """Return an object to the pool"""
        with self._lock:
            if len(self._pool) < self._max_size:
                self._pool.append(obj)
    
    def clear(self):
        """Clear the pool"""
        with self._lock:
            self._pool.clear()


# Global instances
memory_manager = MemoryManager()


def init_performance():
    """Initialize performance monitoring"""
    memory_manager.start_monitoring()


def shutdown_performance():
    """Shutdown performance monitoring"""
    memory_manager.stop_monitoring()


if __name__ == '__main__':
    # Test performance module
    print("Testing performance module...")
    
    # Test memory manager
    mm = MemoryManager()
    print(f"Current memory: {mm.get_memory_mb():.1f} MB")
    print(f"Memory percent: {mm.get_memory_percent():.1f}%")
    
    # Test LRU cache
    cache = LRUCache(maxsize=5)
    for i in range(10):
        cache.put(f"key{i}", f"value{i}")
    print(f"Cache size: {len(cache)}")
    
    # Test profiler
    with PerformanceProfiler.time("test_operation"):
        time.sleep(0.1)
    
    @timed("decorated_function")
    def test_func():
        time.sleep(0.05)
    
    for _ in range(5):
        test_func()
    
    print("\n" + PerformanceProfiler.report())
    
    print("\nPerformance module test complete!")
