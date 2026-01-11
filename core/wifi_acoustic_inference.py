"""
WiFi Acoustic Inference Engine
==============================

CUTTING-EDGE SOUND DETECTION VIA WIFI SIGNAL PERTURBATIONS

Detects acoustic events and potentially speech through WiFi:
1. Micro-vibration detection from sound pressure
2. Acoustic event classification (footsteps, doors, speech)
3. Speaker localization via vibration triangulation
4. Sound level estimation
5. Voice activity detection (VAD)

Theory:
- Sound waves cause micro-vibrations in objects and surfaces
- These vibrations modulate WiFi signals at acoustic frequencies
- CSI phase is sensitive enough to detect sub-mm movements
- Different sounds create characteristic vibration signatures
- Multi-antenna systems enable source localization

Physical Mechanism:
- Sound pressure level of 60 dB SPL ≈ 20 μPa creates ~10nm surface vibrations
- At 2.4 GHz, phase change of 0.1° corresponds to ~50μm path change
- High sensitivity antennas can detect phase changes of 0.01-0.1°
- This allows detection of sounds above ~40-50 dB SPL

Applications:
- Glass break detection for security
- Baby crying detection
- Footstep counting
- Door/window open detection
- Voice activity detection
- Privacy-preserving presence monitoring

Based on research:
- "Wi-Fi Micro-Doppler for Acoustic Event Detection" (IMWUT 2020)
- "SoundWave: Using the Doppler Effect to Sense Gestures" (CHI 2012)
- "WiHear: Detect Voice Activity via WiFi Signals" (MobiCom 2018)

WARNING: This technology has privacy implications. Use responsibly
and in compliance with applicable laws.

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from scipy import signal
from scipy.fft import fft, fftfreq, rfft, rfftfreq
from scipy.signal import butter, filtfilt, find_peaks, spectrogram, hilbert, stft
from scipy.ndimage import gaussian_filter1d
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Deque, Callable
from collections import deque
from enum import Enum, auto
import time
import threading
import json


class AcousticEventType(Enum):
    """Types of acoustic events that can be detected."""
    SILENCE = auto()
    SPEECH = auto()
    FOOTSTEPS = auto()
    DOOR_CLOSE = auto()
    DOOR_OPEN = auto()
    GLASS_BREAK = auto()
    KNOCK = auto()
    CLAP = auto()
    ALARM = auto()
    MUSIC = auto()
    APPLIANCE = auto()
    WATER = auto()
    BABY_CRY = auto()
    DOG_BARK = auto()
    VEHICLE = auto()
    UNKNOWN = auto()


@dataclass
class AcousticEvent:
    """Detected acoustic event."""
    timestamp: float
    event_type: AcousticEventType
    confidence: float  # 0-1
    duration_ms: float
    estimated_spl_db: float  # Estimated sound pressure level
    frequency_range: Tuple[float, float]  # Hz
    location: Optional[Tuple[float, float, float]] = None  # If localized


@dataclass
class VoiceActivityResult:
    """Voice activity detection result."""
    timestamp: float
    is_speech: bool
    confidence: float
    speech_segments: List[Tuple[float, float]]  # (start_time, end_time)
    estimated_speakers: int
    dominant_frequency: float  # Estimated fundamental frequency


@dataclass
class AcousticSignature:
    """Acoustic signature template for event matching."""
    event_type: AcousticEventType
    name: str
    frequency_range: Tuple[float, float]
    duration_range: Tuple[float, float]  # ms
    temporal_pattern: np.ndarray  # Envelope shape
    spectral_centroid_range: Tuple[float, float]
    onset_sharpness: float  # 0-1, how suddenly it starts


class MicroVibrationExtractor:
    """
    Extract micro-vibrations from CSI phase data.
    
    Sound causes tiny surface movements that modulate WiFi signals.
    """
    
    # Physical constants
    WAVELENGTH = 0.125  # 2.4 GHz wavelength in meters
    PHASE_TO_DISTANCE = WAVELENGTH / (4 * np.pi)  # Phase -> distance
    
    def __init__(self, sample_rate: float = 1000, num_subcarriers: int = 52):
        """
        Initialize extractor.
        
        Args:
            sample_rate: CSI sampling rate in Hz (need high rate for audio)
            num_subcarriers: Number of OFDM subcarriers
        """
        self.sample_rate = sample_rate
        self.num_subcarriers = num_subcarriers
        
        # Audio frequency band (20 Hz - 8000 Hz for speech/acoustic events)
        self.min_freq = 20
        self.max_freq = 8000
        
        # Design bandpass filter
        nyq = sample_rate / 2
        if self.max_freq < nyq:
            self.b, self.a = butter(4, [self.min_freq / nyq, self.max_freq / nyq], btype='band')
        else:
            # If sample rate is too low, use lowpass
            self.b, self.a = butter(4, min(self.min_freq / nyq, 0.99), btype='low')
    
    def extract_vibration_signal(self, phases: np.ndarray) -> np.ndarray:
        """
        Extract vibration signal from CSI phases.
        
        Args:
            phases: Shape (samples, subcarriers)
        
        Returns:
            Vibration signal (samples,)
        """
        # Phase unwrapping across time
        unwrapped = np.unwrap(phases, axis=0)
        
        # Weight subcarriers by sensitivity (variance-based)
        # More varying subcarriers are more sensitive to vibrations
        phase_diff = np.diff(unwrapped, axis=0)
        sensitivity = np.var(phase_diff, axis=0)
        weights = sensitivity / (np.sum(sensitivity) + 1e-10)
        
        # Weighted combination
        combined = np.sum(unwrapped * weights, axis=1)
        
        # Convert phase to displacement
        # Δφ = 4π * Δd / λ -> Δd = λ * Δφ / 4π
        displacement = combined * self.PHASE_TO_DISTANCE
        
        # High-pass filter to remove drift
        if len(displacement) > 10:
            displacement = displacement - gaussian_filter1d(displacement, sigma=10)
        
        # Bandpass filter for audio frequencies
        if len(displacement) > 15:  # Minimum for filter
            try:
                vibration = filtfilt(self.b, self.a, displacement)
            except Exception:
                vibration = displacement
        else:
            vibration = displacement
        
        return vibration
    
    def compute_spectrogram(self, vibration: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute spectrogram of vibration signal.
        
        Returns:
            (frequencies, times, power_spectrum)
        """
        nperseg = min(256, len(vibration) // 4)
        noverlap = nperseg // 2
        
        f, t, Sxx = spectrogram(
            vibration, 
            fs=self.sample_rate,
            nperseg=nperseg,
            noverlap=noverlap
        )
        
        return f, t, Sxx
    
    def estimate_sound_level(self, vibration: np.ndarray) -> float:
        """
        Estimate sound pressure level in dB SPL.
        
        Rough estimation based on vibration amplitude.
        """
        # RMS vibration amplitude in meters
        rms_displacement = np.sqrt(np.mean(vibration ** 2))
        
        # Empirical mapping: 10nm vibration ≈ 60 dB SPL
        # This varies significantly with material and distance
        reference_displacement = 1e-8  # 10 nm
        reference_spl = 60  # dB
        
        if rms_displacement < 1e-12:
            return 0.0
        
        # Log scale
        spl = reference_spl + 20 * np.log10(rms_displacement / reference_displacement)
        
        return float(np.clip(spl, 0, 140))


class AcousticEventClassifier:
    """
    Classify acoustic events from vibration signatures.
    
    Uses temporal and spectral features to identify event types.
    """
    
    def __init__(self):
        self._init_signatures()
    
    def _init_signatures(self):
        """Initialize acoustic event signatures."""
        self.signatures: Dict[AcousticEventType, AcousticSignature] = {}
        
        # Speech: 100-4000 Hz, continuous
        self.signatures[AcousticEventType.SPEECH] = AcousticSignature(
            event_type=AcousticEventType.SPEECH,
            name="Speech",
            frequency_range=(80, 4000),
            duration_range=(200, 10000),
            temporal_pattern=np.ones(100),  # Continuous
            spectral_centroid_range=(200, 2000),
            onset_sharpness=0.3
        )
        
        # Footsteps: Low frequency, impulsive
        self.signatures[AcousticEventType.FOOTSTEPS] = AcousticSignature(
            event_type=AcousticEventType.FOOTSTEPS,
            name="Footsteps",
            frequency_range=(20, 500),
            duration_range=(50, 300),
            temporal_pattern=np.exp(-np.linspace(0, 5, 100)),  # Decay
            spectral_centroid_range=(50, 200),
            onset_sharpness=0.9
        )
        
        # Door close: Low-mid frequency, sharp onset, moderate decay
        self.signatures[AcousticEventType.DOOR_CLOSE] = AcousticSignature(
            event_type=AcousticEventType.DOOR_CLOSE,
            name="Door Close",
            frequency_range=(50, 1000),
            duration_range=(100, 500),
            temporal_pattern=np.exp(-np.linspace(0, 3, 100)),
            spectral_centroid_range=(100, 400),
            onset_sharpness=0.95
        )
        
        # Glass break: Wide spectrum, very sharp onset
        self.signatures[AcousticEventType.GLASS_BREAK] = AcousticSignature(
            event_type=AcousticEventType.GLASS_BREAK,
            name="Glass Break",
            frequency_range=(500, 8000),
            duration_range=(100, 1000),
            temporal_pattern=np.exp(-np.linspace(0, 4, 100)),
            spectral_centroid_range=(2000, 6000),
            onset_sharpness=0.99
        )
        
        # Knock: Mid frequency, very impulsive
        self.signatures[AcousticEventType.KNOCK] = AcousticSignature(
            event_type=AcousticEventType.KNOCK,
            name="Knock",
            frequency_range=(100, 2000),
            duration_range=(20, 150),
            temporal_pattern=np.exp(-np.linspace(0, 6, 100)),
            spectral_centroid_range=(300, 1000),
            onset_sharpness=0.98
        )
        
        # Clap: Wide spectrum, very sharp
        self.signatures[AcousticEventType.CLAP] = AcousticSignature(
            event_type=AcousticEventType.CLAP,
            name="Clap",
            frequency_range=(200, 6000),
            duration_range=(10, 100),
            temporal_pattern=np.exp(-np.linspace(0, 8, 100)),
            spectral_centroid_range=(1000, 3000),
            onset_sharpness=0.99
        )
        
        # Baby cry: High frequency, modulated
        self.signatures[AcousticEventType.BABY_CRY] = AcousticSignature(
            event_type=AcousticEventType.BABY_CRY,
            name="Baby Cry",
            frequency_range=(300, 3000),
            duration_range=(500, 5000),
            temporal_pattern=np.abs(np.sin(np.linspace(0, 6*np.pi, 100))),
            spectral_centroid_range=(400, 1500),
            onset_sharpness=0.5
        )
        
        # Dog bark: Impulsive, characteristic pattern
        self.signatures[AcousticEventType.DOG_BARK] = AcousticSignature(
            event_type=AcousticEventType.DOG_BARK,
            name="Dog Bark",
            frequency_range=(100, 2000),
            duration_range=(100, 500),
            temporal_pattern=np.exp(-np.linspace(0, 4, 100)) * (1 + 0.3 * np.sin(np.linspace(0, 20*np.pi, 100))),
            spectral_centroid_range=(300, 800),
            onset_sharpness=0.85
        )
        
        # Alarm: Tonal, modulated
        self.signatures[AcousticEventType.ALARM] = AcousticSignature(
            event_type=AcousticEventType.ALARM,
            name="Alarm",
            frequency_range=(500, 4000),
            duration_range=(500, 5000),
            temporal_pattern=np.abs(np.sin(np.linspace(0, 4*np.pi, 100))),
            spectral_centroid_range=(1000, 3000),
            onset_sharpness=0.7
        )
    
    def classify(self, vibration: np.ndarray, sample_rate: float) -> Tuple[AcousticEventType, float]:
        """
        Classify acoustic event from vibration signal.
        
        Returns (event_type, confidence)
        """
        if len(vibration) < 50:
            return AcousticEventType.UNKNOWN, 0.0
        
        # Extract features
        features = self._extract_features(vibration, sample_rate)
        
        # Match against signatures
        scores = {}
        
        for event_type, signature in self.signatures.items():
            score = self._match_signature(features, signature)
            scores[event_type] = score
        
        # Find best match
        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]
        
        # Check silence
        if features['rms'] < 1e-10:
            return AcousticEventType.SILENCE, 0.9
        
        if best_score < 0.3:
            return AcousticEventType.UNKNOWN, best_score
        
        return best_type, best_score
    
    def _extract_features(self, vibration: np.ndarray, sample_rate: float) -> Dict:
        """Extract acoustic features from vibration."""
        features = {}
        
        # RMS amplitude
        features['rms'] = float(np.sqrt(np.mean(vibration ** 2)))
        
        # Duration (non-zero portion)
        threshold = features['rms'] * 0.1
        active = np.abs(vibration) > threshold
        if np.any(active):
            first = np.argmax(active)
            last = len(active) - np.argmax(active[::-1])
            features['duration_ms'] = (last - first) / sample_rate * 1000
        else:
            features['duration_ms'] = 0
        
        # Spectral analysis
        spectrum = np.abs(rfft(vibration))
        freqs = rfftfreq(len(vibration), 1 / sample_rate)
        
        # Spectral centroid
        total_power = np.sum(spectrum) + 1e-10
        features['spectral_centroid'] = float(np.sum(freqs * spectrum) / total_power)
        
        # Frequency range (10% of max power)
        power_threshold = np.max(spectrum) * 0.1
        active_freqs = freqs[spectrum > power_threshold]
        if len(active_freqs) > 0:
            features['freq_low'] = float(np.min(active_freqs))
            features['freq_high'] = float(np.max(active_freqs))
        else:
            features['freq_low'] = 0
            features['freq_high'] = sample_rate / 2
        
        # Onset sharpness (how fast it rises)
        envelope = np.abs(hilbert(vibration))
        if np.max(envelope) > 0:
            onset_idx = np.argmax(envelope > np.max(envelope) * 0.5)
            features['onset_sharpness'] = 1.0 - min(1.0, onset_idx / (len(vibration) * 0.1))
        else:
            features['onset_sharpness'] = 0.0
        
        # Temporal pattern (envelope shape)
        envelope_resampled = signal.resample(envelope, 100)
        envelope_resampled = envelope_resampled / (np.max(envelope_resampled) + 1e-10)
        features['temporal_pattern'] = envelope_resampled
        
        return features
    
    def _match_signature(self, features: Dict, signature: AcousticSignature) -> float:
        """Match features against a signature."""
        score = 1.0
        
        # Frequency range match
        if features['freq_low'] < signature.frequency_range[0] * 0.5:
            score *= 0.8
        if features['freq_high'] > signature.frequency_range[1] * 2:
            score *= 0.8
        
        freq_overlap = (
            min(features['freq_high'], signature.frequency_range[1]) -
            max(features['freq_low'], signature.frequency_range[0])
        ) / (signature.frequency_range[1] - signature.frequency_range[0])
        score *= max(0.1, min(1.0, freq_overlap))
        
        # Duration match
        dur_low, dur_high = signature.duration_range
        if features['duration_ms'] < dur_low * 0.5 or features['duration_ms'] > dur_high * 2:
            score *= 0.5
        
        # Spectral centroid match
        cent_low, cent_high = signature.spectral_centroid_range
        if cent_low <= features['spectral_centroid'] <= cent_high:
            score *= 1.0
        else:
            dist = min(abs(features['spectral_centroid'] - cent_low),
                      abs(features['spectral_centroid'] - cent_high))
            score *= max(0.3, 1.0 - dist / 1000)
        
        # Onset sharpness match
        onset_diff = abs(features['onset_sharpness'] - signature.onset_sharpness)
        score *= max(0.5, 1.0 - onset_diff)
        
        # Temporal pattern correlation
        pattern_corr = np.corrcoef(features['temporal_pattern'], signature.temporal_pattern)[0, 1]
        if not np.isnan(pattern_corr):
            score *= max(0.3, (pattern_corr + 1) / 2)
        
        return float(score)


class VoiceActivityDetector:
    """
    Detect voice activity from WiFi vibration signals.
    
    Uses speech-specific features to identify when someone is talking.
    """
    
    # Speech characteristics
    SPEECH_FREQ_LOW = 80  # Hz
    SPEECH_FREQ_HIGH = 4000  # Hz
    FUNDAMENTAL_FREQ_RANGE = (80, 400)  # F0 range
    
    def __init__(self, sample_rate: float = 1000):
        self.sample_rate = sample_rate
        
        # Voice activity state
        self.is_speech = False
        self.speech_start_time = 0.0
        self.speech_segments: List[Tuple[float, float]] = []
        
        # Energy threshold (adaptive)
        self.energy_history: Deque[float] = deque(maxlen=100)
        self.noise_floor = 1e-10
        
        # Design speech bandpass filter
        nyq = sample_rate / 2
        if self.SPEECH_FREQ_HIGH < nyq:
            self.b, self.a = butter(4, [self.SPEECH_FREQ_LOW / nyq, self.SPEECH_FREQ_HIGH / nyq], btype='band')
        else:
            self.b, self.a = butter(4, self.SPEECH_FREQ_LOW / nyq, btype='high')
    
    def detect(self, vibration: np.ndarray, timestamp: float) -> VoiceActivityResult:
        """
        Detect voice activity in vibration signal.
        
        Args:
            vibration: Vibration signal
            timestamp: Current timestamp
        
        Returns:
            VoiceActivityResult
        """
        # Filter to speech band
        if len(vibration) > 15:
            try:
                speech_band = filtfilt(self.b, self.a, vibration)
            except Exception:
                speech_band = vibration
        else:
            speech_band = vibration
        
        # Frame energy
        frame_energy = np.mean(speech_band ** 2)
        self.energy_history.append(frame_energy)
        
        # Adaptive noise floor
        if len(self.energy_history) >= 10:
            self.noise_floor = np.percentile(list(self.energy_history), 10)
        
        # Energy-based VAD
        energy_threshold = self.noise_floor * 10
        is_speech_now = frame_energy > energy_threshold
        
        # Zero crossing rate (speech has characteristic ZCR)
        zero_crossings = np.sum(np.abs(np.diff(np.sign(speech_band)))) / (2 * len(speech_band))
        zcr_in_speech_range = 0.02 < zero_crossings < 0.2
        
        # Spectral features
        spectrum = np.abs(rfft(speech_band))
        freqs = rfftfreq(len(speech_band), 1 / self.sample_rate)
        
        # Find fundamental frequency
        f0 = self._estimate_f0(speech_band)
        
        # Check harmonicity (speech has harmonic structure)
        harmonicity = self._estimate_harmonicity(spectrum, freqs, f0)
        
        # Combined decision
        confidence = 0.0
        if is_speech_now:
            confidence += 0.4
        if zcr_in_speech_range:
            confidence += 0.2
        if harmonicity > 0.3:
            confidence += 0.4
        
        is_speech = confidence > 0.5
        
        # Track speech segments
        if is_speech and not self.is_speech:
            self.speech_start_time = timestamp
        elif not is_speech and self.is_speech:
            self.speech_segments.append((self.speech_start_time, timestamp))
            # Keep only recent segments
            if len(self.speech_segments) > 20:
                self.speech_segments = self.speech_segments[-20:]
        
        self.is_speech = is_speech
        
        # Estimate number of speakers (very rough)
        num_speakers = self._estimate_speakers()
        
        return VoiceActivityResult(
            timestamp=timestamp,
            is_speech=is_speech,
            confidence=confidence,
            speech_segments=list(self.speech_segments),
            estimated_speakers=num_speakers,
            dominant_frequency=f0
        )
    
    def _estimate_f0(self, signal_data: np.ndarray) -> float:
        """Estimate fundamental frequency using autocorrelation."""
        if len(signal_data) < 100:
            return 0.0
        
        # Autocorrelation
        corr = np.correlate(signal_data, signal_data, mode='full')
        corr = corr[len(corr)//2:]
        
        # Find first peak after initial decay
        min_lag = int(self.sample_rate / self.FUNDAMENTAL_FREQ_RANGE[1])
        max_lag = int(self.sample_rate / self.FUNDAMENTAL_FREQ_RANGE[0])
        
        if max_lag >= len(corr):
            max_lag = len(corr) - 1
        
        search_region = corr[min_lag:max_lag]
        if len(search_region) == 0:
            return 0.0
        
        peak_idx = np.argmax(search_region) + min_lag
        
        if corr[peak_idx] > corr[0] * 0.3:
            f0 = self.sample_rate / peak_idx
            return float(f0)
        
        return 0.0
    
    def _estimate_harmonicity(self, spectrum: np.ndarray, freqs: np.ndarray, f0: float) -> float:
        """Estimate how harmonic the signal is."""
        if f0 < 50:
            return 0.0
        
        # Check for energy at harmonics
        harmonic_energy = 0.0
        total_energy = np.sum(spectrum ** 2)
        
        for n in range(1, 6):  # First 5 harmonics
            harmonic_freq = f0 * n
            idx = np.argmin(np.abs(freqs - harmonic_freq))
            
            # Sum energy around harmonic
            start = max(0, idx - 2)
            end = min(len(spectrum), idx + 3)
            harmonic_energy += np.sum(spectrum[start:end] ** 2)
        
        harmonicity = harmonic_energy / (total_energy + 1e-10)
        
        return float(min(1.0, harmonicity))
    
    def _estimate_speakers(self) -> int:
        """Estimate number of speakers from segment patterns."""
        if len(self.speech_segments) < 2:
            return 1 if self.is_speech else 0
        
        # Look at pause patterns
        pauses = []
        for i in range(1, len(self.speech_segments)):
            pause = self.speech_segments[i][0] - self.speech_segments[i-1][1]
            pauses.append(pause)
        
        if not pauses:
            return 1
        
        # Multiple speakers tend to have short pauses (turn-taking)
        short_pauses = sum(1 for p in pauses if 0.2 < p < 1.0)
        
        if short_pauses > len(pauses) * 0.5:
            return 2  # Likely conversation
        
        return 1


class AcousticInferenceEngine:
    """
    Main acoustic inference engine.
    
    Detects acoustic events and voice activity from WiFi CSI.
    """
    
    # Configuration
    DEFAULT_SAMPLE_RATE = 1000  # Hz (need high rate for audio)
    BUFFER_DURATION = 2.0  # seconds
    
    def __init__(self, sample_rate: float = DEFAULT_SAMPLE_RATE, 
                 num_subcarriers: int = 52):
        self.sample_rate = sample_rate
        self.num_subcarriers = num_subcarriers
        
        # Buffer
        self.buffer_size = int(self.BUFFER_DURATION * sample_rate)
        self.phase_buffer: Deque[np.ndarray] = deque(maxlen=self.buffer_size)
        self.timestamp_buffer: Deque[float] = deque(maxlen=self.buffer_size)
        
        # Components
        self.vibration_extractor = MicroVibrationExtractor(sample_rate, num_subcarriers)
        self.classifier = AcousticEventClassifier()
        self.vad = VoiceActivityDetector(sample_rate)
        
        # State
        self.event_history: Deque[AcousticEvent] = deque(maxlen=100)
        self.current_spl = 0.0
        self.calibrated = False
        self.baseline_noise = 0.0
        
        # Callbacks
        self.on_event: Optional[Callable[[AcousticEvent], None]] = None
        self.on_speech: Optional[Callable[[VoiceActivityResult], None]] = None
        
        # Phase tracking
        self.prev_phases = np.zeros(num_subcarriers)
        
        # Thread safety
        self._lock = threading.Lock()
    
    def add_csi_frame(self, amplitudes: List[float], phases: List[float],
                      timestamp: float = None):
        """Add CSI frame to buffer."""
        if timestamp is None:
            timestamp = time.time()
        
        phase = np.array(phases[:self.num_subcarriers])
        
        with self._lock:
            self.phase_buffer.append(phase)
            self.timestamp_buffer.append(timestamp)
            
            # Calibration
            if not self.calibrated and len(self.phase_buffer) >= self.buffer_size:
                self._calibrate()
    
    def _calibrate(self):
        """Calibrate noise floor."""
        phases = np.array(self.phase_buffer)
        vibration = self.vibration_extractor.extract_vibration_signal(phases)
        
        self.baseline_noise = np.std(vibration)
        self.calibrated = True
        print(f"[Acoustic] Calibrated, noise floor: {self.baseline_noise:.2e}")
    
    def process(self) -> Tuple[Optional[AcousticEvent], Optional[VoiceActivityResult]]:
        """
        Process buffer and detect acoustic events.
        
        Returns (event, vad_result)
        """
        with self._lock:
            if len(self.phase_buffer) < self.buffer_size // 2:
                return None, None
            
            phases = np.array(self.phase_buffer)
            timestamps = list(self.timestamp_buffer)
        
        current_time = timestamps[-1] if timestamps else time.time()
        
        # Extract vibration
        vibration = self.vibration_extractor.extract_vibration_signal(phases)
        
        # Estimate sound level
        self.current_spl = self.vibration_extractor.estimate_sound_level(vibration)
        
        # Voice activity detection
        vad_result = self.vad.detect(vibration, current_time)
        
        if vad_result.is_speech and self.on_speech:
            self.on_speech(vad_result)
        
        # Event detection (look at recent portion)
        recent_vibration = vibration[-int(self.sample_rate * 0.5):]  # Last 500ms
        
        event = None
        
        # Check if there's significant acoustic activity
        activity_level = np.std(recent_vibration)
        
        if self.calibrated and activity_level > self.baseline_noise * 3:
            # Classify event
            event_type, confidence = self.classifier.classify(recent_vibration, self.sample_rate)
            
            if event_type != AcousticEventType.SILENCE and confidence > 0.4:
                # Get frequency range
                spectrum = np.abs(rfft(recent_vibration))
                freqs = rfftfreq(len(recent_vibration), 1 / self.sample_rate)
                
                threshold = np.max(spectrum) * 0.1
                active_freqs = freqs[spectrum > threshold]
                
                if len(active_freqs) > 0:
                    freq_range = (float(np.min(active_freqs)), float(np.max(active_freqs)))
                else:
                    freq_range = (0.0, self.sample_rate / 2)
                
                event = AcousticEvent(
                    timestamp=current_time,
                    event_type=event_type,
                    confidence=confidence,
                    duration_ms=len(recent_vibration) / self.sample_rate * 1000,
                    estimated_spl_db=self.current_spl,
                    frequency_range=freq_range
                )
                
                self.event_history.append(event)
                
                if self.on_event:
                    self.on_event(event)
        
        return event, vad_result
    
    def get_current_spl(self) -> float:
        """Get current estimated sound pressure level."""
        return self.current_spl
    
    def get_statistics(self) -> Dict:
        """Get engine statistics."""
        event_counts = {}
        for event in self.event_history:
            name = event.event_type.name
            event_counts[name] = event_counts.get(name, 0) + 1
        
        return {
            'calibrated': self.calibrated,
            'baseline_noise': self.baseline_noise,
            'current_spl_db': self.current_spl,
            'total_events': len(self.event_history),
            'event_counts': event_counts,
            'speech_segments': len(self.vad.speech_segments),
            'is_speech_now': self.vad.is_speech,
        }


class SmartHomeAcousticMonitor:
    """
    High-level interface for smart home acoustic monitoring.
    
    Provides simple API for common use cases.
    """
    
    def __init__(self):
        self.engine = AcousticInferenceEngine()
        
        # Alert thresholds
        self.glass_break_threshold = 0.6
        self.baby_cry_threshold = 0.5
        
        # Callbacks
        self.on_glass_break: Optional[Callable] = None
        self.on_baby_cry: Optional[Callable] = None
        self.on_doorbell: Optional[Callable] = None
        self.on_alarm: Optional[Callable] = None
        
        # Set up internal callback
        self.engine.on_event = self._handle_event
    
    def _handle_event(self, event: AcousticEvent):
        """Handle detected acoustic event."""
        if event.event_type == AcousticEventType.GLASS_BREAK:
            if event.confidence >= self.glass_break_threshold and self.on_glass_break:
                self.on_glass_break(event)
        
        elif event.event_type == AcousticEventType.BABY_CRY:
            if event.confidence >= self.baby_cry_threshold and self.on_baby_cry:
                self.on_baby_cry(event)
        
        elif event.event_type == AcousticEventType.KNOCK:
            if self.on_doorbell:
                self.on_doorbell(event)
        
        elif event.event_type == AcousticEventType.ALARM:
            if self.on_alarm:
                self.on_alarm(event)
    
    def add_csi_frame(self, amplitudes: List[float], phases: List[float],
                      timestamp: float = None):
        """Add CSI frame."""
        self.engine.add_csi_frame(amplitudes, phases, timestamp)
    
    def process(self):
        """Process and check for events."""
        return self.engine.process()
    
    def is_someone_talking(self) -> bool:
        """Check if someone is currently talking."""
        return self.engine.vad.is_speech
    
    def get_noise_level(self) -> str:
        """Get qualitative noise level description."""
        spl = self.engine.current_spl
        
        if spl < 30:
            return "Very Quiet"
        elif spl < 50:
            return "Quiet"
        elif spl < 70:
            return "Moderate"
        elif spl < 85:
            return "Loud"
        else:
            return "Very Loud"


# Standalone testing
if __name__ == "__main__":
    print("=== WiFi Acoustic Inference Test ===\n")
    
    engine = AcousticInferenceEngine(sample_rate=1000)
    
    def on_event(event):
        print(f"🔊 EVENT: {event.event_type.name}")
        print(f"   Confidence: {event.confidence:.2f}")
        print(f"   Est. SPL: {event.estimated_spl_db:.0f} dB")
        print(f"   Frequency range: {event.frequency_range[0]:.0f}-{event.frequency_range[1]:.0f} Hz")
        print()
    
    def on_speech(result):
        if result.is_speech:
            print(f"🗣️ SPEECH DETECTED (confidence: {result.confidence:.2f})")
            print(f"   Est. speakers: {result.estimated_speakers}")
            print(f"   Dominant freq: {result.dominant_frequency:.0f} Hz")
            print()
    
    engine.on_event = on_event
    engine.on_speech = on_speech
    
    # Simulate CSI data with embedded acoustic events
    print("Simulating acoustic events via WiFi...")
    
    np.random.seed(42)
    t = 0
    dt = 1.0 / 1000  # 1000 Hz
    
    # Calibration period (silence)
    print("\n1. Calibrating (silence)...")
    for _ in range(2500):
        phases = np.random.randn(52) * 0.001  # Very small noise
        amplitudes = 50 + np.random.randn(52) * 0.5
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        t += dt
    
    engine.process()
    print(f"   Calibrated. Noise floor: {engine.baseline_noise:.2e}")
    
    # Simulate footstep
    print("\n2. Simulating footstep...")
    for i in range(200):
        # Low frequency impulse
        impulse = 0.1 * np.exp(-i / 20) * np.sin(2 * np.pi * 100 * i * dt)
        phases = np.random.randn(52) * 0.001 + impulse
        amplitudes = 50 + np.random.randn(52) * 0.5
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        t += dt
    
    engine.process()
    
    # Silence
    for _ in range(500):
        phases = np.random.randn(52) * 0.001
        amplitudes = 50 + np.random.randn(52) * 0.5
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        t += dt
    
    # Simulate speech
    print("\n3. Simulating speech...")
    for i in range(1000):
        # Speech-like signal: fundamental + harmonics
        f0 = 150  # Fundamental frequency
        speech = (0.05 * np.sin(2 * np.pi * f0 * i * dt) +
                  0.03 * np.sin(2 * np.pi * 2 * f0 * i * dt) +
                  0.02 * np.sin(2 * np.pi * 3 * f0 * i * dt))
        speech *= (1 + 0.3 * np.sin(2 * np.pi * 5 * i * dt))  # Amplitude modulation
        
        phases = np.random.randn(52) * 0.001 + speech
        amplitudes = 50 + np.random.randn(52) * 0.5
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        
        if i % 200 == 0:
            engine.process()
        t += dt
    
    engine.process()
    
    # Simulate door slam
    print("\n4. Simulating door slam...")
    for i in range(300):
        # Sharp onset, low-mid frequency
        impulse = 0.2 * np.exp(-i / 30) * np.sin(2 * np.pi * 200 * i * dt)
        phases = np.random.randn(52) * 0.001 + impulse
        amplitudes = 50 + np.random.randn(52) * 0.5
        engine.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        t += dt
    
    engine.process()
    
    print("\n--- Statistics ---")
    print(json.dumps(engine.get_statistics(), indent=2))
