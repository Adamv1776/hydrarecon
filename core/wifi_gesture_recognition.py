"""
WiFi Gesture Recognition Engine - Contactless Hand Gesture Detection
=====================================================================

CUTTING-EDGE RESEARCH IMPLEMENTATION

Detects hand gestures through WiFi signal disturbances:
1. Swipe left/right/up/down
2. Push/pull (toward/away)
3. Circle (clockwise/counterclockwise)
4. Wave
5. Pinch/spread
6. Custom gesture learning

Theory:
- Hand movements cause Doppler shifts in WiFi signals
- Different gestures create unique time-frequency signatures
- CSI phase patterns encode gesture trajectories
- Machine learning classifies gesture patterns

Based on research:
- "WiGest: WiFi-based Gesture Recognition" (MobiCom 2015)
- "WiFinger: Talk to Your Smart Devices with Finger-grained Gesture" (UbiComp 2016)
- "Soli: Ubiquitous Gesture Sensing with Millimeter Wave Radar" (Google ATAP - adapted for WiFi)

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from scipy import signal
from scipy.fft import fft, fftfreq
from scipy.signal import butter, filtfilt, find_peaks, spectrogram, stft
from scipy.ndimage import gaussian_filter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Deque, Callable
from collections import deque
from enum import Enum, auto
import time
import threading
import json
import pickle
from pathlib import Path


class GestureType(Enum):
    """Recognized gesture types."""
    NONE = auto()
    SWIPE_LEFT = auto()
    SWIPE_RIGHT = auto()
    SWIPE_UP = auto()
    SWIPE_DOWN = auto()
    PUSH = auto()
    PULL = auto()
    CIRCLE_CW = auto()
    CIRCLE_CCW = auto()
    WAVE = auto()
    PINCH = auto()
    SPREAD = auto()
    TAP = auto()
    DOUBLE_TAP = auto()
    HOLD = auto()
    CUSTOM = auto()


@dataclass
class GestureEvent:
    """Detected gesture event."""
    timestamp: float
    gesture_type: GestureType
    confidence: float  # 0-1
    duration_ms: float
    velocity: float  # Relative speed
    direction: Tuple[float, float, float]  # 3D direction vector
    magnitude: float  # Movement magnitude
    custom_id: Optional[str] = None  # For custom gestures


@dataclass  
class GestureTemplate:
    """Template for gesture matching."""
    gesture_type: GestureType
    name: str
    doppler_signature: np.ndarray  # Time-frequency signature
    phase_pattern: np.ndarray  # Phase change pattern
    duration_range: Tuple[float, float]  # Expected duration in ms
    amplitude_profile: np.ndarray  # Amplitude envelope
    samples: int = 0  # Number of training samples


class DopplerExtractor:
    """Extract Doppler information from CSI data."""
    
    def __init__(self, sample_rate: float = 100, num_subcarriers: int = 52):
        self.sample_rate = sample_rate
        self.num_subcarriers = num_subcarriers
        
        # Doppler parameters
        self.wavelength = 0.125  # 2.4 GHz wavelength in meters
        self.max_velocity = 3.0  # Max expected velocity (m/s)
        
        # Spectrogram parameters
        self.nperseg = 64  # Window size for STFT
        self.noverlap = 56  # Overlap for time resolution
        
    def compute_doppler_spectrogram(self, phases: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute Doppler spectrogram from phase data.
        
        Phase rate of change is proportional to velocity:
        v = (λ / 4π) * (dφ/dt)
        """
        # Use weighted average across subcarriers
        weights = np.var(phases, axis=0)  # Weight by variance
        weights /= np.sum(weights) + 1e-10
        
        combined_phase = np.sum(phases * weights, axis=1)
        
        # Phase derivative -> Doppler frequency
        phase_diff = np.diff(combined_phase) * self.sample_rate
        
        # Short-time Fourier transform
        f, t, Sxx = stft(phase_diff, fs=self.sample_rate, 
                        nperseg=self.nperseg, noverlap=self.noverlap)
        
        # Convert to Doppler velocity
        doppler_vel = f * self.wavelength / (4 * np.pi)
        
        return doppler_vel, t, np.abs(Sxx)
    
    def extract_velocity_profile(self, phases: np.ndarray) -> np.ndarray:
        """Extract instantaneous velocity from phase."""
        # Combine subcarriers
        weights = np.var(phases, axis=0)
        weights /= np.sum(weights) + 1e-10
        combined = np.sum(phases * weights, axis=1)
        
        # Phase derivative
        velocity = np.diff(combined) * self.sample_rate * self.wavelength / (4 * np.pi)
        
        # Smooth
        velocity = gaussian_filter(velocity, sigma=2)
        
        return velocity


class GestureClassifier:
    """
    Classify gestures using multiple features.
    
    Uses a combination of:
    1. Doppler spectrogram matching
    2. Phase pattern correlation
    3. Temporal characteristics
    """
    
    def __init__(self):
        self.templates: Dict[GestureType, List[GestureTemplate]] = {}
        self._init_default_templates()
        
    def _init_default_templates(self):
        """Initialize default gesture templates."""
        # These are synthetic templates - in practice, train from real data
        
        # Swipe gestures have characteristic Doppler signature
        # Positive Doppler = toward receiver, negative = away
        
        t = np.linspace(0, 1, 100)
        
        # Swipe left: starts positive (toward antenna), ends negative
        swipe_left_doppler = np.outer(
            np.exp(-((t - 0.5) ** 2) / 0.05),  # Temporal envelope
            np.array([0.8, 0.3, -0.3, -0.8])  # Frequency progression
        )
        
        # Swipe right: opposite
        swipe_right_doppler = np.outer(
            np.exp(-((t - 0.5) ** 2) / 0.05),
            np.array([-0.8, -0.3, 0.3, 0.8])
        )
        
        # Push: sustained positive Doppler
        push_doppler = np.outer(
            np.exp(-((t - 0.3) ** 2) / 0.1) - np.exp(-((t - 0.7) ** 2) / 0.1),
            np.array([0.5, 0.8, 0.5, 0.2])
        )
        
        # Pull: sustained negative Doppler
        pull_doppler = -push_doppler
        
        # Circle: sinusoidal Doppler pattern
        circle_cw = np.outer(
            np.sin(2 * np.pi * t * 2),
            np.array([0.5, 0.6, 0.5, 0.4])
        )
        
        # Wave: multiple peaks
        wave_doppler = np.outer(
            np.sin(2 * np.pi * t * 4) * np.exp(-((t - 0.5) ** 2) / 0.2),
            np.array([0.6, 0.8, 0.6, 0.4])
        )
        
        self.templates[GestureType.SWIPE_LEFT] = [
            GestureTemplate(
                gesture_type=GestureType.SWIPE_LEFT,
                name="Swipe Left",
                doppler_signature=swipe_left_doppler,
                phase_pattern=np.cumsum(np.mean(swipe_left_doppler, axis=1)),
                duration_range=(200, 800),
                amplitude_profile=np.exp(-((t - 0.5) ** 2) / 0.1)
            )
        ]
        
        self.templates[GestureType.SWIPE_RIGHT] = [
            GestureTemplate(
                gesture_type=GestureType.SWIPE_RIGHT,
                name="Swipe Right",
                doppler_signature=swipe_right_doppler,
                phase_pattern=np.cumsum(np.mean(swipe_right_doppler, axis=1)),
                duration_range=(200, 800),
                amplitude_profile=np.exp(-((t - 0.5) ** 2) / 0.1)
            )
        ]
        
        self.templates[GestureType.PUSH] = [
            GestureTemplate(
                gesture_type=GestureType.PUSH,
                name="Push",
                doppler_signature=push_doppler,
                phase_pattern=np.cumsum(np.mean(push_doppler, axis=1)),
                duration_range=(300, 1000),
                amplitude_profile=np.exp(-((t - 0.5) ** 2) / 0.15)
            )
        ]
        
        self.templates[GestureType.PULL] = [
            GestureTemplate(
                gesture_type=GestureType.PULL,
                name="Pull",
                doppler_signature=pull_doppler,
                phase_pattern=np.cumsum(np.mean(pull_doppler, axis=1)),
                duration_range=(300, 1000),
                amplitude_profile=np.exp(-((t - 0.5) ** 2) / 0.15)
            )
        ]
        
        self.templates[GestureType.CIRCLE_CW] = [
            GestureTemplate(
                gesture_type=GestureType.CIRCLE_CW,
                name="Circle Clockwise",
                doppler_signature=circle_cw,
                phase_pattern=np.cumsum(np.mean(circle_cw, axis=1)),
                duration_range=(500, 1500),
                amplitude_profile=np.ones_like(t)
            )
        ]
        
        self.templates[GestureType.CIRCLE_CCW] = [
            GestureTemplate(
                gesture_type=GestureType.CIRCLE_CCW,
                name="Circle Counter-Clockwise",
                doppler_signature=-circle_cw,
                phase_pattern=np.cumsum(np.mean(-circle_cw, axis=1)),
                duration_range=(500, 1500),
                amplitude_profile=np.ones_like(t)
            )
        ]
        
        self.templates[GestureType.WAVE] = [
            GestureTemplate(
                gesture_type=GestureType.WAVE,
                name="Wave",
                doppler_signature=wave_doppler,
                phase_pattern=np.cumsum(np.mean(wave_doppler, axis=1)),
                duration_range=(800, 2000),
                amplitude_profile=np.exp(-((t - 0.5) ** 2) / 0.2)
            )
        ]
    
    def classify(self, doppler_spec: np.ndarray, duration_ms: float) -> Tuple[GestureType, float]:
        """
        Classify gesture from Doppler spectrogram.
        
        Returns (gesture_type, confidence)
        """
        best_match = GestureType.NONE
        best_score = 0.0
        
        for gesture_type, templates in self.templates.items():
            for template in templates:
                # Check duration
                if not (template.duration_range[0] <= duration_ms <= template.duration_range[1]):
                    continue
                
                # Resize spectrogram to match template
                resized = self._resize_spectrogram(doppler_spec, template.doppler_signature.shape)
                
                # Normalized cross-correlation
                score = self._correlate(resized, template.doppler_signature)
                
                if score > best_score:
                    best_score = score
                    best_match = gesture_type
        
        return best_match, best_score
    
    def _resize_spectrogram(self, spec: np.ndarray, target_shape: Tuple[int, int]) -> np.ndarray:
        """Resize spectrogram to target shape."""
        from scipy.ndimage import zoom
        
        factors = (target_shape[0] / spec.shape[0], target_shape[1] / spec.shape[1])
        return zoom(spec, factors, order=1)
    
    def _correlate(self, a: np.ndarray, b: np.ndarray) -> float:
        """Normalized cross-correlation."""
        a_norm = (a - np.mean(a)) / (np.std(a) + 1e-10)
        b_norm = (b - np.mean(b)) / (np.std(b) + 1e-10)
        
        correlation = np.mean(a_norm * b_norm)
        return float(np.clip((correlation + 1) / 2, 0, 1))  # Scale to 0-1
    
    def add_custom_template(self, name: str, doppler_spec: np.ndarray, 
                           duration_range: Tuple[float, float]) -> str:
        """Add a custom gesture template."""
        custom_id = f"custom_{len(self.templates.get(GestureType.CUSTOM, []))}"
        
        template = GestureTemplate(
            gesture_type=GestureType.CUSTOM,
            name=name,
            doppler_signature=doppler_spec,
            phase_pattern=np.cumsum(np.mean(doppler_spec, axis=1)),
            duration_range=duration_range,
            amplitude_profile=np.ones(doppler_spec.shape[0])
        )
        
        if GestureType.CUSTOM not in self.templates:
            self.templates[GestureType.CUSTOM] = []
        self.templates[GestureType.CUSTOM].append(template)
        
        return custom_id


class GestureRecognitionEngine:
    """
    Main gesture recognition engine.
    
    Processes CSI data streams and detects gestures in real-time.
    """
    
    # Detection parameters
    SAMPLE_RATE = 100  # Hz
    WINDOW_SIZE = 2.0  # seconds
    MIN_GESTURE_DURATION = 150  # ms
    MAX_GESTURE_DURATION = 3000  # ms
    DETECTION_THRESHOLD = 0.1  # Minimum energy for gesture detection
    CLASSIFICATION_THRESHOLD = 0.5  # Minimum confidence for classification
    
    def __init__(self, num_subcarriers: int = 52):
        self.num_subcarriers = num_subcarriers
        
        # CSI buffer
        self.buffer_size = int(self.WINDOW_SIZE * self.SAMPLE_RATE)
        self.phase_buffer: Deque[np.ndarray] = deque(maxlen=self.buffer_size)
        self.amplitude_buffer: Deque[np.ndarray] = deque(maxlen=self.buffer_size)
        self.timestamp_buffer: Deque[float] = deque(maxlen=self.buffer_size)
        
        # Components
        self.doppler_extractor = DopplerExtractor(self.SAMPLE_RATE, num_subcarriers)
        self.classifier = GestureClassifier()
        
        # State
        self.gesture_in_progress = False
        self.gesture_start_time = 0.0
        self.gesture_start_idx = 0
        self.baseline_energy = 0.0
        self.calibrated = False
        
        # Results
        self.gesture_history: Deque[GestureEvent] = deque(maxlen=100)
        
        # Callbacks
        self.on_gesture: Optional[Callable[[GestureEvent], None]] = None
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Phase tracking
        self.prev_phases = np.zeros(num_subcarriers)
        self.phase_offset = np.zeros(num_subcarriers)
    
    def add_csi_frame(self, amplitudes: List[float], phases: List[float], 
                      timestamp: float = None):
        """Add CSI frame to buffer."""
        if timestamp is None:
            timestamp = time.time()
        
        amp = np.array(amplitudes[:self.num_subcarriers])
        phase = np.array(phases[:self.num_subcarriers])
        
        # Phase unwrapping
        phase_diff = phase - self.prev_phases
        jumps = np.abs(phase_diff) > np.pi
        self.phase_offset[jumps & (phase_diff > 0)] -= 2 * np.pi
        self.phase_offset[jumps & (phase_diff < 0)] += 2 * np.pi
        self.prev_phases = phase.copy()
        
        unwrapped = phase + self.phase_offset
        
        with self._lock:
            self.phase_buffer.append(unwrapped)
            self.amplitude_buffer.append(amp)
            self.timestamp_buffer.append(timestamp)
            
            # Calibration
            if not self.calibrated and len(self.phase_buffer) >= self.buffer_size:
                self._calibrate()
    
    def _calibrate(self):
        """Calibrate baseline energy level."""
        phases = np.array(self.phase_buffer)
        
        # Baseline energy from phase variance
        velocity = np.diff(phases, axis=0)
        self.baseline_energy = np.mean(np.var(velocity, axis=0))
        
        self.calibrated = True
        print(f"[Gesture] Calibrated, baseline energy: {self.baseline_energy:.4f}")
    
    def process(self) -> Optional[GestureEvent]:
        """Process buffer and detect gestures."""
        with self._lock:
            if len(self.phase_buffer) < self.buffer_size // 2:
                return None
            
            if not self.calibrated:
                return None
            
            phases = np.array(self.phase_buffer)
            amplitudes = np.array(self.amplitude_buffer)
            timestamps = np.array(self.timestamp_buffer)
        
        now = time.time()
        
        # Compute current energy (motion indicator)
        velocity = np.diff(phases, axis=0)
        current_energy = np.mean(np.var(velocity[-20:], axis=0))
        
        # State machine for gesture detection
        if not self.gesture_in_progress:
            # Look for gesture start
            if current_energy > self.baseline_energy * 3:
                self.gesture_in_progress = True
                self.gesture_start_time = now
                self.gesture_start_idx = len(phases) - 20
                return None
        else:
            # Gesture in progress - check for end
            gesture_duration = (now - self.gesture_start_time) * 1000
            
            # End conditions:
            # 1. Energy dropped back to baseline
            # 2. Max duration exceeded
            energy_dropped = current_energy < self.baseline_energy * 2
            duration_exceeded = gesture_duration > self.MAX_GESTURE_DURATION
            
            if energy_dropped or duration_exceeded:
                self.gesture_in_progress = False
                
                # Check minimum duration
                if gesture_duration < self.MIN_GESTURE_DURATION:
                    return None
                
                # Extract gesture segment
                gesture_phases = phases[self.gesture_start_idx:]
                gesture_amps = amplitudes[self.gesture_start_idx:]
                
                # Classify gesture
                gesture_event = self._classify_gesture(
                    gesture_phases, gesture_amps, gesture_duration
                )
                
                if gesture_event and gesture_event.confidence >= self.CLASSIFICATION_THRESHOLD:
                    self.gesture_history.append(gesture_event)
                    
                    if self.on_gesture:
                        self.on_gesture(gesture_event)
                    
                    return gesture_event
        
        return None
    
    def _classify_gesture(self, phases: np.ndarray, amplitudes: np.ndarray,
                          duration_ms: float) -> Optional[GestureEvent]:
        """Classify the detected gesture segment."""
        
        # Compute Doppler spectrogram
        doppler_vel, t, Sxx = self.doppler_extractor.compute_doppler_spectrogram(phases)
        
        # Classify
        gesture_type, confidence = self.classifier.classify(Sxx.T, duration_ms)
        
        if gesture_type == GestureType.NONE:
            return None
        
        # Extract additional features
        velocity_profile = self.doppler_extractor.extract_velocity_profile(phases)
        
        # Estimate direction from velocity profile
        avg_velocity = np.mean(velocity_profile)
        velocity_std = np.std(velocity_profile)
        
        direction = (
            float(np.sign(avg_velocity)),  # X: toward/away
            float(np.mean(np.diff(velocity_profile))),  # Y: velocity change
            0.0  # Z: not easily determined from single antenna
        )
        
        return GestureEvent(
            timestamp=time.time(),
            gesture_type=gesture_type,
            confidence=confidence,
            duration_ms=duration_ms,
            velocity=float(np.abs(avg_velocity)),
            direction=direction,
            magnitude=float(velocity_std)
        )
    
    def train_custom_gesture(self, name: str, samples: List[Tuple[np.ndarray, float]]) -> str:
        """
        Train a custom gesture from sample data.
        
        Args:
            name: Name for the custom gesture
            samples: List of (phase_data, duration_ms) tuples
        
        Returns:
            Custom gesture ID
        """
        if len(samples) < 3:
            raise ValueError("Need at least 3 samples for custom gesture")
        
        # Compute average Doppler spectrogram
        spectrograms = []
        durations = []
        
        for phases, duration in samples:
            _, _, Sxx = self.doppler_extractor.compute_doppler_spectrogram(phases)
            spectrograms.append(Sxx.T)
            durations.append(duration)
        
        # Normalize and average
        target_shape = spectrograms[0].shape
        normalized = []
        for spec in spectrograms:
            resized = self.classifier._resize_spectrogram(spec, target_shape)
            normalized.append(resized / (np.max(resized) + 1e-10))
        
        avg_spectrogram = np.mean(normalized, axis=0)
        duration_range = (min(durations) * 0.8, max(durations) * 1.2)
        
        return self.classifier.add_custom_template(name, avg_spectrogram, duration_range)
    
    def get_gesture_stats(self) -> Dict:
        """Get statistics on detected gestures."""
        if not self.gesture_history:
            return {'total': 0}
        
        gesture_counts = {}
        for event in self.gesture_history:
            name = event.gesture_type.name
            gesture_counts[name] = gesture_counts.get(name, 0) + 1
        
        confidences = [e.confidence for e in self.gesture_history]
        
        return {
            'total': len(self.gesture_history),
            'by_type': gesture_counts,
            'avg_confidence': float(np.mean(confidences)),
            'min_confidence': float(np.min(confidences)),
            'max_confidence': float(np.max(confidences)),
            'calibrated': self.calibrated,
            'baseline_energy': self.baseline_energy,
        }


class GestureControlInterface:
    """
    High-level interface for gesture-based control.
    
    Maps gestures to actions and provides a simple API
    for gesture-controlled applications.
    """
    
    def __init__(self):
        self.engine = GestureRecognitionEngine()
        self.engine.on_gesture = self._on_gesture
        
        # Action mappings
        self.action_map: Dict[GestureType, Callable] = {}
        
        # Gesture history for combos
        self.recent_gestures: Deque[GestureEvent] = deque(maxlen=5)
        self.combo_timeout = 1.0  # seconds
        
        # Combo definitions
        self.combos: Dict[Tuple[GestureType, ...], Callable] = {}
    
    def map_gesture(self, gesture: GestureType, action: Callable):
        """Map a gesture to an action callback."""
        self.action_map[gesture] = action
    
    def map_combo(self, gestures: Tuple[GestureType, ...], action: Callable):
        """Map a gesture combo to an action."""
        self.combos[gestures] = action
    
    def _on_gesture(self, event: GestureEvent):
        """Handle detected gesture."""
        self.recent_gestures.append(event)
        
        # Check for combos first
        self._check_combos()
        
        # Then single gestures
        if event.gesture_type in self.action_map:
            self.action_map[event.gesture_type](event)
    
    def _check_combos(self):
        """Check for gesture combos."""
        if len(self.recent_gestures) < 2:
            return
        
        now = time.time()
        
        # Filter to recent gestures within timeout
        recent = [g for g in self.recent_gestures 
                  if now - g.timestamp < self.combo_timeout]
        
        for combo, action in self.combos.items():
            if len(recent) >= len(combo):
                # Check if recent gestures match combo
                recent_types = tuple(g.gesture_type for g in recent[-len(combo):])
                if recent_types == combo:
                    action(recent[-len(combo):])
                    self.recent_gestures.clear()  # Reset after combo
                    return
    
    def add_csi_frame(self, amplitudes: List[float], phases: List[float],
                      timestamp: float = None):
        """Add CSI frame."""
        self.engine.add_csi_frame(amplitudes, phases, timestamp)
    
    def process(self) -> Optional[GestureEvent]:
        """Process and return detected gesture."""
        return self.engine.process()


# Standalone testing
if __name__ == "__main__":
    print("=== WiFi Gesture Recognition Test ===\n")
    
    engine = GestureRecognitionEngine()
    
    def on_gesture(event: GestureEvent):
        print(f"🤚 GESTURE DETECTED: {event.gesture_type.name}")
        print(f"   Confidence: {event.confidence:.2f}")
        print(f"   Duration: {event.duration_ms:.0f}ms")
        print(f"   Velocity: {event.velocity:.3f}")
        print()
    
    engine.on_gesture = on_gesture
    
    # Simulate CSI data with a swipe gesture
    print("Simulating swipe right gesture...")
    
    t = 0
    dt = 1.0 / 100  # 100 Hz
    
    # First, calibration period (no motion)
    for _ in range(300):  # 3 seconds
        phases = np.random.randn(52) * 0.02
        amplitudes = 50 + np.random.randn(52) * 2
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        t += dt
    
    print("Calibration complete, performing gesture...")
    
    # Now perform a swipe gesture
    for i in range(50):  # 500ms gesture
        progress = i / 50.0
        
        # Swipe creates progressive phase shift
        # Simulating hand moving from left to right
        gesture_phase = -0.5 * np.sin(np.pi * progress)  # Doppler-like signature
        
        phases = np.random.randn(52) * 0.02 + gesture_phase
        amplitudes = 50 + np.random.randn(52) * 2 + 5 * np.exp(-((progress - 0.5) ** 2) / 0.1)
        
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        engine.process()
        t += dt
    
    # Return to baseline
    for _ in range(100):
        phases = np.random.randn(52) * 0.02
        amplitudes = 50 + np.random.randn(52) * 2
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        engine.process()
        t += dt
    
    print("\nGesture Statistics:", json.dumps(engine.get_gesture_stats(), indent=2))
