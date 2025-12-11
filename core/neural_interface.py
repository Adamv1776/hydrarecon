"""
Neural Interface System for HydraRecon

Advanced brain-computer interface concepts:
- EEG signal processing
- Focus/attention detection
- Mental command recognition
- Biometric authentication
- Stress level monitoring
- Cognitive load assessment
"""

import math
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum
from collections import deque

try:
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    QObject = object


class MentalState(Enum):
    """Detected mental states"""
    NEUTRAL = "neutral"
    FOCUSED = "focused"
    RELAXED = "relaxed"
    STRESSED = "stressed"
    FATIGUED = "fatigued"
    ALERT = "alert"
    MEDITATIVE = "meditative"


class MentalCommand(Enum):
    """Mental commands that can be detected"""
    NONE = "none"
    PUSH = "push"
    PULL = "pull"
    LIFT = "lift"
    DROP = "drop"
    LEFT = "left"
    RIGHT = "right"
    ROTATE_LEFT = "rotate_left"
    ROTATE_RIGHT = "rotate_right"
    DISAPPEAR = "disappear"


class BrainWave(Enum):
    """EEG frequency bands"""
    DELTA = "delta"      # 0.5-4 Hz - Deep sleep
    THETA = "theta"      # 4-8 Hz - Drowsiness, light sleep
    ALPHA = "alpha"      # 8-12 Hz - Relaxed, calm
    BETA = "beta"        # 12-30 Hz - Active thinking
    GAMMA = "gamma"      # 30-100 Hz - Higher mental activity


@dataclass
class EEGChannel:
    """Single EEG channel data"""
    name: str
    position: Tuple[float, float]  # 10-20 system coordinates
    
    # Raw signal buffer
    buffer: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    # Frequency band powers
    band_powers: Dict[BrainWave, float] = field(default_factory=dict)
    
    # Quality metrics
    signal_quality: float = 0.0
    impedance: float = 0.0


@dataclass
class BrainMetrics:
    """Computed brain metrics"""
    # Attention and meditation scores (0-100)
    attention: float = 0.0
    meditation: float = 0.0
    
    # Mental state
    state: MentalState = MentalState.NEUTRAL
    state_confidence: float = 0.0
    
    # Cognitive metrics
    cognitive_load: float = 0.0
    stress_level: float = 0.0
    fatigue_level: float = 0.0
    focus_duration: float = 0.0
    
    # Frequency band powers (averaged)
    band_powers: Dict[BrainWave, float] = field(default_factory=dict)
    
    # Raw data quality
    overall_quality: float = 0.0


@dataclass
class CommandResult:
    """Result of mental command detection"""
    command: MentalCommand
    power: float  # 0-1 strength
    confidence: float  # 0-1 confidence
    timestamp: float = 0.0


class SignalProcessor:
    """
    EEG Signal Processing Pipeline
    
    Processes raw EEG signals to extract features.
    """
    
    def __init__(self, sample_rate: int = 256):
        self.sample_rate = sample_rate
        
        # Filter coefficients
        self.notch_freq = 60.0  # Power line noise
        
        # Band definitions
        self.bands = {
            BrainWave.DELTA: (0.5, 4),
            BrainWave.THETA: (4, 8),
            BrainWave.ALPHA: (8, 12),
            BrainWave.BETA: (12, 30),
            BrainWave.GAMMA: (30, 100),
        }
    
    def process(self, data: np.ndarray) -> Dict[BrainWave, float]:
        """Process raw EEG data and extract band powers"""
        if len(data) < self.sample_rate:
            return {}
        
        # Remove DC offset
        data = data - np.mean(data)
        
        # Apply bandpass filter (simplified)
        filtered = self._bandpass_filter(data, 0.5, 100)
        
        # Calculate band powers using FFT
        band_powers = {}
        
        # FFT
        fft = np.fft.fft(filtered)
        freqs = np.fft.fftfreq(len(filtered), 1/self.sample_rate)
        power_spectrum = np.abs(fft) ** 2
        
        # Extract band powers
        for band, (low, high) in self.bands.items():
            mask = (freqs >= low) & (freqs < high)
            band_powers[band] = np.mean(power_spectrum[mask]) if np.any(mask) else 0
        
        # Normalize
        total_power = sum(band_powers.values())
        if total_power > 0:
            band_powers = {k: v / total_power for k, v in band_powers.items()}
        
        return band_powers
    
    def _bandpass_filter(self, data: np.ndarray, low: float, high: float) -> np.ndarray:
        """Simple bandpass filter (would use scipy in production)"""
        # Simplified - in production would use proper FIR/IIR filters
        return data
    
    def detect_artifacts(self, data: np.ndarray) -> bool:
        """Detect artifacts in EEG signal"""
        # Check for obvious artifacts
        if np.max(np.abs(data)) > 100:  # Amplitude too high
            return True
        
        if np.std(data) < 0.1:  # Flatline
            return True
        
        return False
    
    def calculate_quality(self, data: np.ndarray) -> float:
        """Calculate signal quality (0-1)"""
        if self.detect_artifacts(data):
            return 0.0
        
        # SNR estimation
        signal_power = np.var(data)
        
        # Estimate noise (high frequency content)
        noise = np.diff(data)
        noise_power = np.var(noise)
        
        if noise_power > 0:
            snr = signal_power / noise_power
            quality = min(1.0, snr / 10)
        else:
            quality = 1.0
        
        return quality


class StateClassifier:
    """
    Mental State Classifier
    
    Classifies mental states from EEG features.
    """
    
    def __init__(self):
        # Thresholds for state detection
        self.thresholds = {
            MentalState.FOCUSED: {BrainWave.BETA: 0.3, BrainWave.GAMMA: 0.1},
            MentalState.RELAXED: {BrainWave.ALPHA: 0.4},
            MentalState.MEDITATIVE: {BrainWave.THETA: 0.3, BrainWave.ALPHA: 0.3},
            MentalState.STRESSED: {BrainWave.BETA: 0.4, BrainWave.GAMMA: 0.2},
            MentalState.FATIGUED: {BrainWave.THETA: 0.4, BrainWave.DELTA: 0.2},
            MentalState.ALERT: {BrainWave.BETA: 0.35},
        }
    
    def classify(self, band_powers: Dict[BrainWave, float]) -> Tuple[MentalState, float]:
        """Classify mental state from band powers"""
        if not band_powers:
            return MentalState.NEUTRAL, 0.0
        
        best_state = MentalState.NEUTRAL
        best_confidence = 0.0
        
        for state, requirements in self.thresholds.items():
            matches = 0
            total = len(requirements)
            
            for band, threshold in requirements.items():
                if band in band_powers and band_powers[band] >= threshold:
                    matches += 1
            
            confidence = matches / total if total > 0 else 0
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_state = state
        
        return best_state, best_confidence
    
    def calculate_attention(self, band_powers: Dict[BrainWave, float]) -> float:
        """Calculate attention score (0-100)"""
        if not band_powers:
            return 50.0
        
        # Attention correlates with beta and gamma, inversely with theta
        beta = band_powers.get(BrainWave.BETA, 0)
        gamma = band_powers.get(BrainWave.GAMMA, 0)
        theta = band_powers.get(BrainWave.THETA, 0)
        
        attention = (beta * 40 + gamma * 30 - theta * 20 + 50)
        return max(0, min(100, attention))
    
    def calculate_meditation(self, band_powers: Dict[BrainWave, float]) -> float:
        """Calculate meditation score (0-100)"""
        if not band_powers:
            return 50.0
        
        # Meditation correlates with alpha and theta
        alpha = band_powers.get(BrainWave.ALPHA, 0)
        theta = band_powers.get(BrainWave.THETA, 0)
        beta = band_powers.get(BrainWave.BETA, 0)
        
        meditation = (alpha * 40 + theta * 30 - beta * 20 + 50)
        return max(0, min(100, meditation))
    
    def calculate_cognitive_load(self, band_powers: Dict[BrainWave, float]) -> float:
        """Calculate cognitive load (0-1)"""
        if not band_powers:
            return 0.5
        
        # Higher theta/alpha ratio indicates higher cognitive load
        theta = band_powers.get(BrainWave.THETA, 0)
        alpha = band_powers.get(BrainWave.ALPHA, 0.01)
        
        ratio = theta / alpha
        load = min(1.0, ratio / 2)
        
        return load


class CommandDetector:
    """
    Mental Command Detector
    
    Detects intentional mental commands from EEG patterns.
    """
    
    def __init__(self):
        # Command patterns (simplified)
        self.command_patterns = {
            MentalCommand.PUSH: {"asymmetry": "frontal_left", "intensity": 0.6},
            MentalCommand.PULL: {"asymmetry": "frontal_right", "intensity": 0.6},
            MentalCommand.LEFT: {"asymmetry": "left", "intensity": 0.5},
            MentalCommand.RIGHT: {"asymmetry": "right", "intensity": 0.5},
            MentalCommand.LIFT: {"asymmetry": "frontal", "intensity": 0.7},
            MentalCommand.DROP: {"asymmetry": "occipital", "intensity": 0.5},
        }
        
        # Training data
        self.trained = False
        self.user_patterns: Dict[MentalCommand, np.ndarray] = {}
    
    def train_command(self, command: MentalCommand, samples: List[np.ndarray]):
        """Train detector on user's mental command pattern"""
        if samples:
            # Average the samples to get user's pattern
            self.user_patterns[command] = np.mean(samples, axis=0)
            self.trained = True
    
    def detect(self, features: np.ndarray) -> CommandResult:
        """Detect mental command from features"""
        if not self.trained or not self.user_patterns:
            return CommandResult(MentalCommand.NONE, 0.0, 0.0)
        
        best_command = MentalCommand.NONE
        best_similarity = 0.0
        
        for command, pattern in self.user_patterns.items():
            if len(features) != len(pattern):
                continue
            
            # Cosine similarity
            dot = np.dot(features, pattern)
            norm = np.linalg.norm(features) * np.linalg.norm(pattern)
            
            if norm > 0:
                similarity = dot / norm
                
                if similarity > best_similarity and similarity > 0.7:
                    best_similarity = similarity
                    best_command = command
        
        return CommandResult(
            command=best_command,
            power=best_similarity,
            confidence=best_similarity * 0.9,
            timestamp=time.time()
        )


class NeuralInterface(QObject if PYQT_AVAILABLE else object):
    """
    Complete Neural Interface System
    
    Integrates EEG processing, state classification, and command detection.
    """
    
    if PYQT_AVAILABLE:
        metricsUpdated = pyqtSignal(object)
        stateChanged = pyqtSignal(object)
        commandDetected = pyqtSignal(object)
        connectionChanged = pyqtSignal(bool)
    
    def __init__(self):
        if PYQT_AVAILABLE:
            super().__init__()
        
        # Components
        self.signal_processor = SignalProcessor()
        self.state_classifier = StateClassifier()
        self.command_detector = CommandDetector()
        
        # Channels (10-20 system positions)
        self.channels: Dict[str, EEGChannel] = {}
        self._init_channels()
        
        # Current metrics
        self.metrics = BrainMetrics()
        
        # State
        self.is_connected = False
        self.is_streaming = False
        self.device_name = ""
        
        # History
        self.metrics_history: deque = deque(maxlen=1000)
        self.command_history: deque = deque(maxlen=100)
        
        # Focus tracking
        self._focus_start: Optional[float] = None
        self._last_state = MentalState.NEUTRAL
        
        # Callbacks
        self.on_metrics: Optional[Callable[[BrainMetrics], None]] = None
        self.on_command: Optional[Callable[[CommandResult], None]] = None
        
        # Update timer (simulation)
        if PYQT_AVAILABLE:
            self._update_timer = QTimer()
            self._update_timer.timeout.connect(self._simulate_update)
    
    def _init_channels(self):
        """Initialize standard 10-20 EEG channels"""
        positions = {
            "Fp1": (-0.3, 0.9), "Fp2": (0.3, 0.9),
            "F7": (-0.7, 0.5), "F3": (-0.4, 0.5), "Fz": (0, 0.5), "F4": (0.4, 0.5), "F8": (0.7, 0.5),
            "T3": (-0.9, 0), "C3": (-0.4, 0), "Cz": (0, 0), "C4": (0.4, 0), "T4": (0.9, 0),
            "T5": (-0.7, -0.5), "P3": (-0.4, -0.5), "Pz": (0, -0.5), "P4": (0.4, -0.5), "T6": (0.7, -0.5),
            "O1": (-0.3, -0.9), "O2": (0.3, -0.9),
        }
        
        for name, pos in positions.items():
            self.channels[name] = EEGChannel(name=name, position=pos)
    
    def connect_device(self, device_name: str = "Simulated") -> bool:
        """Connect to EEG device"""
        # In production, would connect to actual device
        self.device_name = device_name
        self.is_connected = True
        
        if PYQT_AVAILABLE:
            self.connectionChanged.emit(True)
        
        return True
    
    def disconnect_device(self):
        """Disconnect from device"""
        self.stop_streaming()
        self.is_connected = False
        self.device_name = ""
        
        if PYQT_AVAILABLE:
            self.connectionChanged.emit(False)
    
    def start_streaming(self):
        """Start data streaming"""
        if not self.is_connected:
            return False
        
        self.is_streaming = True
        
        # Start simulation
        if PYQT_AVAILABLE:
            self._update_timer.start(100)  # 10 Hz update
        
        return True
    
    def stop_streaming(self):
        """Stop data streaming"""
        self.is_streaming = False
        
        if PYQT_AVAILABLE and hasattr(self, '_update_timer'):
            self._update_timer.stop()
    
    def _simulate_update(self):
        """Simulate EEG data update"""
        if not self.is_streaming:
            return
        
        # Generate simulated band powers
        import random
        
        t = time.time()
        
        # Simulate natural variations
        band_powers = {
            BrainWave.DELTA: 0.1 + random.uniform(-0.02, 0.02),
            BrainWave.THETA: 0.15 + 0.05 * math.sin(t * 0.5) + random.uniform(-0.02, 0.02),
            BrainWave.ALPHA: 0.3 + 0.1 * math.sin(t * 0.3) + random.uniform(-0.03, 0.03),
            BrainWave.BETA: 0.25 + 0.08 * math.sin(t * 0.7) + random.uniform(-0.03, 0.03),
            BrainWave.GAMMA: 0.1 + 0.03 * math.sin(t * 1.2) + random.uniform(-0.01, 0.01),
        }
        
        # Normalize
        total = sum(band_powers.values())
        band_powers = {k: v / total for k, v in band_powers.items()}
        
        # Update channels with simulated data
        for channel in self.channels.values():
            channel.band_powers = band_powers.copy()
            channel.signal_quality = 0.8 + random.uniform(-0.1, 0.1)
        
        # Calculate metrics
        self._update_metrics(band_powers)
    
    def _update_metrics(self, band_powers: Dict[BrainWave, float]):
        """Update brain metrics from band powers"""
        # State classification
        state, confidence = self.state_classifier.classify(band_powers)
        
        # Attention and meditation
        attention = self.state_classifier.calculate_attention(band_powers)
        meditation = self.state_classifier.calculate_meditation(band_powers)
        
        # Cognitive metrics
        cognitive_load = self.state_classifier.calculate_cognitive_load(band_powers)
        
        # Stress estimation (high beta + low alpha)
        beta = band_powers.get(BrainWave.BETA, 0)
        alpha = band_powers.get(BrainWave.ALPHA, 0.01)
        stress = min(1.0, beta / (alpha + 0.1))
        
        # Focus duration tracking
        if state in [MentalState.FOCUSED, MentalState.ALERT]:
            if self._focus_start is None:
                self._focus_start = time.time()
            focus_duration = time.time() - self._focus_start
        else:
            self._focus_start = None
            focus_duration = 0.0
        
        # Update metrics
        self.metrics = BrainMetrics(
            attention=attention,
            meditation=meditation,
            state=state,
            state_confidence=confidence,
            cognitive_load=cognitive_load,
            stress_level=stress,
            fatigue_level=band_powers.get(BrainWave.THETA, 0) * 2,
            focus_duration=focus_duration,
            band_powers=band_powers,
            overall_quality=np.mean([c.signal_quality for c in self.channels.values()])
        )
        
        # Store history
        self.metrics_history.append(self.metrics)
        
        # Emit signals
        if PYQT_AVAILABLE:
            self.metricsUpdated.emit(self.metrics)
            
            if state != self._last_state:
                self.stateChanged.emit(state)
                self._last_state = state
        
        # Callbacks
        if self.on_metrics:
            self.on_metrics(self.metrics)
    
    def train_command(self, command: MentalCommand, duration: float = 5.0):
        """Train mental command (would collect samples)"""
        # In production, would collect EEG samples during training
        samples = [np.random.randn(10) for _ in range(10)]  # Simulated
        self.command_detector.train_command(command, samples)
    
    def get_focus_score(self) -> float:
        """Get current focus score (0-100)"""
        return self.metrics.attention
    
    def get_stress_level(self) -> float:
        """Get current stress level (0-1)"""
        return self.metrics.stress_level
    
    def is_user_focused(self, threshold: float = 60) -> bool:
        """Check if user is focused"""
        return self.metrics.attention >= threshold
    
    def is_user_stressed(self, threshold: float = 0.7) -> bool:
        """Check if user is stressed"""
        return self.metrics.stress_level >= threshold
    
    def get_attention_history(self, duration: float = 60) -> List[float]:
        """Get attention history for duration in seconds"""
        # Return last N samples
        n_samples = int(duration * 10)  # 10 Hz
        history = list(self.metrics_history)[-n_samples:]
        return [m.attention for m in history]
    
    def authenticate_user(self, reference_pattern: Optional[np.ndarray] = None) -> Tuple[bool, float]:
        """
        Biometric authentication using EEG patterns
        
        Returns (authenticated, confidence)
        """
        if not self.is_streaming:
            return False, 0.0
        
        # Would compare current pattern with reference
        # Simulated for now
        import random
        confidence = random.uniform(0.7, 0.95)
        authenticated = confidence > 0.8
        
        return authenticated, confidence
    
    def get_visualization_data(self) -> Dict[str, Any]:
        """Get data for visualization"""
        return {
            "channels": {
                name: {
                    "position": channel.position,
                    "quality": channel.signal_quality,
                    "band_powers": {
                        band.value: power 
                        for band, power in channel.band_powers.items()
                    }
                }
                for name, channel in self.channels.items()
            },
            "metrics": {
                "attention": self.metrics.attention,
                "meditation": self.metrics.meditation,
                "state": self.metrics.state.value,
                "cognitive_load": self.metrics.cognitive_load,
                "stress": self.metrics.stress_level,
                "focus_duration": self.metrics.focus_duration,
            },
            "band_powers": {
                band.value: power 
                for band, power in self.metrics.band_powers.items()
            }
        }


# Export all classes
__all__ = [
    'MentalState',
    'MentalCommand',
    'BrainWave',
    'EEGChannel',
    'BrainMetrics',
    'CommandResult',
    'SignalProcessor',
    'StateClassifier',
    'CommandDetector',
    'NeuralInterface'
]
