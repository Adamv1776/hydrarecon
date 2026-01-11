"""
WiFi Gait Analysis & Person Identification Engine
=================================================

CUTTING-EDGE BIOMETRIC IDENTIFICATION VIA WIFI

Identifies individuals by their unique walking patterns detected through WiFi:
1. Gait cycle extraction from CSI variations
2. Biometric feature extraction (stride length, cadence, asymmetry)
3. Deep temporal pattern analysis
4. Multi-person gait database
5. Real-time identification with confidence scores

Theory:
- Walking creates periodic body movements that modulate WiFi signals
- Each person has a unique gait "fingerprint" determined by:
  * Limb lengths and proportions
  * Joint flexibility
  * Muscle strength patterns
  * Habitual posture
- CSI captures torso, arm, and leg movements at sub-wavelength precision

Based on research:
- "WiWho: WiFi-Based Person Identification in Smart Spaces" (IPSN 2016)
- "WiFi-ID: Human Identification Using WiFi Signal" (ICDCS 2016)
- "GaitWay: Monitoring and Recognizing Gait Speed Through CSI" (IMWUT 2019)

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from scipy import signal
from scipy.fft import fft, fftfreq, rfft, rfftfreq
from scipy.signal import butter, filtfilt, find_peaks, hilbert
from scipy.spatial.distance import cosine, euclidean
from scipy.ndimage import gaussian_filter1d
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Deque, Set
from collections import deque
from enum import Enum, auto
import time
import threading
import json
import pickle
import hashlib
from pathlib import Path
import sqlite3


@dataclass
class GaitCycle:
    """Single gait cycle (one complete step sequence)."""
    timestamp: float
    duration_ms: float  # One complete cycle
    step_count: int
    
    # Phase patterns for each subcarrier
    phase_pattern: np.ndarray  # Shape: (samples, subcarriers)
    amplitude_pattern: np.ndarray
    
    # Extracted features
    stride_frequency: float  # Hz (typically 0.8-1.2 Hz walking)
    stride_regularity: float  # 0-1, how regular the gait is
    amplitude_variance: float
    phase_variance: float
    
    # Spectral features
    dominant_frequencies: List[float]
    spectral_entropy: float


@dataclass
class GaitBiometrics:
    """Biometric signature extracted from gait."""
    # Temporal features
    avg_stride_frequency: float
    stride_frequency_std: float
    avg_cycle_duration: float
    cycle_duration_std: float
    
    # Regularity features
    stride_regularity: float
    left_right_asymmetry: float
    temporal_consistency: float
    
    # Spectral features
    primary_harmonic_ratio: float
    spectral_flatness: float
    frequency_distribution: np.ndarray  # Histogram of dominant frequencies
    
    # CSI pattern features
    subcarrier_correlation_matrix: np.ndarray
    phase_coherence: float
    amplitude_modulation_depth: float
    
    # Deep features (from autoencoder)
    latent_representation: np.ndarray
    
    def to_vector(self) -> np.ndarray:
        """Convert to feature vector for comparison."""
        features = [
            self.avg_stride_frequency,
            self.stride_frequency_std,
            self.avg_cycle_duration,
            self.cycle_duration_std,
            self.stride_regularity,
            self.left_right_asymmetry,
            self.temporal_consistency,
            self.primary_harmonic_ratio,
            self.spectral_flatness,
            self.phase_coherence,
            self.amplitude_modulation_depth,
        ]
        
        # Add flattened arrays
        features.extend(self.frequency_distribution.tolist())
        
        # Flatten correlation matrix (upper triangle only)
        n = self.subcarrier_correlation_matrix.shape[0]
        for i in range(n):
            for j in range(i + 1, n):
                features.append(self.subcarrier_correlation_matrix[i, j])
        
        # Add latent representation
        features.extend(self.latent_representation.tolist())
        
        return np.array(features)


@dataclass
class PersonProfile:
    """Person profile with gait signature."""
    person_id: str
    name: str
    created_at: float
    last_seen: float
    
    # Gait signature
    gait_signature: GaitBiometrics
    
    # Multiple samples for robustness
    sample_count: int
    confidence: float
    
    # Historical feature vectors for adaptive learning
    historical_vectors: List[np.ndarray] = field(default_factory=list)


@dataclass 
class IdentificationResult:
    """Result of person identification."""
    timestamp: float
    person_id: Optional[str]
    person_name: Optional[str]
    confidence: float
    match_scores: Dict[str, float]  # All candidate scores
    gait_cycle: GaitCycle
    is_new_person: bool


class GaitCycleExtractor:
    """Extract gait cycles from CSI data."""
    
    # Walking frequency range
    MIN_STRIDE_FREQ = 0.5  # Hz (very slow walking)
    MAX_STRIDE_FREQ = 2.5  # Hz (fast walking/jogging)
    
    def __init__(self, sample_rate: float = 100, num_subcarriers: int = 52):
        self.sample_rate = sample_rate
        self.num_subcarriers = num_subcarriers
        
        # Bandpass filter for walking frequencies
        nyq = sample_rate / 2
        low = self.MIN_STRIDE_FREQ / nyq
        high = self.MAX_STRIDE_FREQ / nyq
        self.b, self.a = butter(4, [low, high], btype='band')
    
    def extract_cycles(self, phases: np.ndarray, amplitudes: np.ndarray,
                      timestamps: np.ndarray) -> List[GaitCycle]:
        """
        Extract individual gait cycles from CSI data.
        
        Uses peak detection on filtered signal to find heel strikes.
        """
        cycles = []
        
        # Combine subcarriers with variance weighting
        phase_var = np.var(phases, axis=0)
        weights = phase_var / (np.sum(phase_var) + 1e-10)
        combined_phase = np.sum(phases * weights, axis=1)
        
        # Bandpass filter
        filtered = filtfilt(self.b, self.a, combined_phase)
        
        # Hilbert transform to get envelope
        analytic = hilbert(filtered)
        envelope = np.abs(analytic)
        
        # Find peaks (heel strikes)
        min_samples = int(self.sample_rate / self.MAX_STRIDE_FREQ)
        peaks, properties = find_peaks(
            envelope,
            distance=min_samples,
            height=np.std(envelope) * 0.5,
            prominence=np.std(envelope) * 0.3
        )
        
        if len(peaks) < 2:
            return cycles
        
        # Extract cycles between consecutive peaks
        for i in range(len(peaks) - 1):
            start = peaks[i]
            end = peaks[i + 1]
            
            if end - start < 10:  # Too short
                continue
            
            duration_ms = (end - start) / self.sample_rate * 1000
            
            # Extract patterns
            phase_pattern = phases[start:end]
            amp_pattern = amplitudes[start:end]
            
            # Compute features
            stride_freq = 1.0 / (duration_ms / 1000)
            
            # Regularity from autocorrelation
            autocorr = np.correlate(filtered[start:end], filtered[start:end], mode='full')
            autocorr = autocorr[len(autocorr)//2:]
            regularity = float(np.max(autocorr[min_samples:]) / (autocorr[0] + 1e-10))
            
            # Spectral features
            fft_result = np.abs(rfft(filtered[start:end]))
            freqs = rfftfreq(end - start, 1.0 / self.sample_rate)
            
            dominant_freqs = freqs[np.argsort(fft_result)[-5:]].tolist()
            
            # Spectral entropy
            fft_norm = fft_result / (np.sum(fft_result) + 1e-10)
            spectral_entropy = -np.sum(fft_norm * np.log(fft_norm + 1e-10))
            
            cycle = GaitCycle(
                timestamp=timestamps[start],
                duration_ms=duration_ms,
                step_count=1,
                phase_pattern=phase_pattern,
                amplitude_pattern=amp_pattern,
                stride_frequency=stride_freq,
                stride_regularity=regularity,
                amplitude_variance=float(np.var(amp_pattern)),
                phase_variance=float(np.var(phase_pattern)),
                dominant_frequencies=dominant_freqs,
                spectral_entropy=float(spectral_entropy)
            )
            
            cycles.append(cycle)
        
        return cycles


class GaitFeatureExtractor:
    """Extract biometric features from gait cycles."""
    
    # Latent space dimension
    LATENT_DIM = 32
    
    def __init__(self, num_subcarriers: int = 52):
        self.num_subcarriers = num_subcarriers
        
        # Simple autoencoder weights (in practice, train these)
        np.random.seed(42)  # Reproducibility
        self.encoder_w1 = np.random.randn(num_subcarriers, 64) * 0.1
        self.encoder_w2 = np.random.randn(64, self.LATENT_DIM) * 0.1
    
    def extract_biometrics(self, cycles: List[GaitCycle]) -> Optional[GaitBiometrics]:
        """Extract biometric signature from multiple gait cycles."""
        if len(cycles) < 3:
            return None
        
        # Temporal features
        frequencies = [c.stride_frequency for c in cycles]
        durations = [c.duration_ms for c in cycles]
        
        avg_stride_freq = np.mean(frequencies)
        stride_freq_std = np.std(frequencies)
        avg_cycle_duration = np.mean(durations)
        cycle_duration_std = np.std(durations)
        
        # Regularity features
        stride_regularity = np.mean([c.stride_regularity for c in cycles])
        
        # Left-right asymmetry (from alternating cycles)
        if len(cycles) >= 4:
            even_durations = [c.duration_ms for c in cycles[::2]]
            odd_durations = [c.duration_ms for c in cycles[1::2]]
            asymmetry = abs(np.mean(even_durations) - np.mean(odd_durations)) / avg_cycle_duration
        else:
            asymmetry = 0.0
        
        # Temporal consistency (how consistent are successive cycles)
        duration_diffs = np.abs(np.diff(durations))
        temporal_consistency = 1.0 - (np.mean(duration_diffs) / (avg_cycle_duration + 1e-10))
        temporal_consistency = max(0.0, min(1.0, temporal_consistency))
        
        # Spectral features
        all_freqs = []
        for c in cycles:
            all_freqs.extend(c.dominant_frequencies)
        
        # Frequency distribution histogram
        freq_hist, _ = np.histogram(all_freqs, bins=10, range=(0.5, 2.5))
        frequency_distribution = freq_hist / (np.sum(freq_hist) + 1e-10)
        
        # Primary harmonic ratio (how much energy in fundamental vs harmonics)
        fundamental_energy = np.sum(frequency_distribution[:3])
        harmonic_energy = np.sum(frequency_distribution[3:])
        primary_harmonic_ratio = fundamental_energy / (harmonic_energy + 1e-10)
        
        # Spectral flatness
        spectral_flatness = np.mean([c.spectral_entropy for c in cycles])
        
        # CSI pattern features
        # Stack all patterns
        all_phases = []
        for c in cycles:
            # Resample to fixed length
            resampled = signal.resample(c.phase_pattern, 50, axis=0)
            all_phases.append(resampled)
        
        stacked = np.array(all_phases)  # (n_cycles, 50, n_subcarriers)
        
        # Subcarrier correlation matrix (averaged)
        corr_matrices = []
        for pattern in stacked:
            corr = np.corrcoef(pattern.T)
            corr_matrices.append(corr)
        
        avg_corr = np.mean(corr_matrices, axis=0)
        
        # Reduce dimensionality for storage
        downsampled_corr = avg_corr[::4, ::4]  # 13x13 from 52x52
        
        # Phase coherence
        phase_coherence = np.mean(np.abs(avg_corr))
        
        # Amplitude modulation depth
        amp_vars = [c.amplitude_variance for c in cycles]
        amplitude_modulation_depth = np.mean(amp_vars)
        
        # Latent representation via simple encoder
        avg_pattern = np.mean(stacked, axis=(0, 1))  # Average pattern
        
        # Encode
        h1 = np.tanh(avg_pattern @ self.encoder_w1)
        latent = np.tanh(h1 @ self.encoder_w2)
        
        return GaitBiometrics(
            avg_stride_frequency=float(avg_stride_freq),
            stride_frequency_std=float(stride_freq_std),
            avg_cycle_duration=float(avg_cycle_duration),
            cycle_duration_std=float(cycle_duration_std),
            stride_regularity=float(stride_regularity),
            left_right_asymmetry=float(asymmetry),
            temporal_consistency=float(temporal_consistency),
            primary_harmonic_ratio=float(primary_harmonic_ratio),
            spectral_flatness=float(spectral_flatness),
            frequency_distribution=frequency_distribution,
            subcarrier_correlation_matrix=downsampled_corr,
            phase_coherence=float(phase_coherence),
            amplitude_modulation_depth=float(amplitude_modulation_depth),
            latent_representation=latent
        )


class PersonDatabase:
    """Persistent database for person profiles."""
    
    def __init__(self, db_path: str = "gait_identities.db"):
        self.db_path = db_path
        self._init_database()
        self._lock = threading.Lock()
    
    def _init_database(self):
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS persons (
                person_id TEXT PRIMARY KEY,
                name TEXT,
                created_at REAL,
                last_seen REAL,
                sample_count INTEGER,
                confidence REAL,
                gait_signature BLOB,
                historical_vectors BLOB
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                person_id TEXT,
                confidence REAL,
                match_scores TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_person(self, profile: PersonProfile):
        """Add or update person profile."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            gait_blob = pickle.dumps(profile.gait_signature)
            hist_blob = pickle.dumps(profile.historical_vectors)
            
            cursor.execute("""
                INSERT OR REPLACE INTO persons 
                (person_id, name, created_at, last_seen, sample_count, 
                 confidence, gait_signature, historical_vectors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.person_id,
                profile.name,
                profile.created_at,
                profile.last_seen,
                profile.sample_count,
                profile.confidence,
                gait_blob,
                hist_blob
            ))
            
            conn.commit()
            conn.close()
    
    def get_person(self, person_id: str) -> Optional[PersonProfile]:
        """Get person by ID."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM persons WHERE person_id = ?", (person_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return self._row_to_profile(row)
            return None
    
    def get_all_persons(self) -> List[PersonProfile]:
        """Get all persons."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM persons")
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_profile(row) for row in rows]
    
    def _row_to_profile(self, row) -> PersonProfile:
        """Convert database row to PersonProfile."""
        return PersonProfile(
            person_id=row[0],
            name=row[1],
            created_at=row[2],
            last_seen=row[3],
            sample_count=row[4],
            confidence=row[5],
            gait_signature=pickle.loads(row[6]),
            historical_vectors=pickle.loads(row[7]) if row[7] else []
        )
    
    def log_identification(self, result: IdentificationResult):
        """Log identification event."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO identifications 
                (timestamp, person_id, confidence, match_scores)
                VALUES (?, ?, ?, ?)
            """, (
                result.timestamp,
                result.person_id,
                result.confidence,
                json.dumps(result.match_scores)
            ))
            
            conn.commit()
            conn.close()


class GaitIdentificationEngine:
    """
    Main gait-based person identification engine.
    
    Processes CSI data to identify individuals by their unique
    walking patterns.
    """
    
    # Configuration
    SAMPLE_RATE = 100  # Hz
    WINDOW_SIZE = 10.0  # seconds (need multiple gait cycles)
    MIN_CYCLES = 3  # Minimum cycles for identification
    IDENTIFICATION_THRESHOLD = 0.70  # Minimum confidence to identify
    NEW_PERSON_THRESHOLD = 0.40  # Below this, consider new person
    
    def __init__(self, num_subcarriers: int = 52, db_path: str = "gait_identities.db"):
        self.num_subcarriers = num_subcarriers
        
        # Buffers
        self.buffer_size = int(self.WINDOW_SIZE * self.SAMPLE_RATE)
        self.phase_buffer: Deque[np.ndarray] = deque(maxlen=self.buffer_size)
        self.amplitude_buffer: Deque[np.ndarray] = deque(maxlen=self.buffer_size)
        self.timestamp_buffer: Deque[float] = deque(maxlen=self.buffer_size)
        
        # Components
        self.cycle_extractor = GaitCycleExtractor(self.SAMPLE_RATE, num_subcarriers)
        self.feature_extractor = GaitFeatureExtractor(num_subcarriers)
        self.database = PersonDatabase(db_path)
        
        # Cached profiles for fast matching
        self._profile_cache: Dict[str, PersonProfile] = {}
        self._reload_cache()
        
        # State
        self.is_walking = False
        self.walk_start_time = 0.0
        
        # Phase tracking
        self.prev_phases = np.zeros(num_subcarriers)
        self.phase_offset = np.zeros(num_subcarriers)
        
        # Thread safety
        self._lock = threading.Lock()
    
    def _reload_cache(self):
        """Reload profile cache from database."""
        profiles = self.database.get_all_persons()
        self._profile_cache = {p.person_id: p for p in profiles}
    
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
    
    def process(self) -> Optional[IdentificationResult]:
        """Process buffer and attempt identification."""
        with self._lock:
            if len(self.phase_buffer) < self.buffer_size:
                return None
            
            phases = np.array(self.phase_buffer)
            amplitudes = np.array(self.amplitude_buffer)
            timestamps = np.array(self.timestamp_buffer)
        
        # Extract gait cycles
        cycles = self.cycle_extractor.extract_cycles(phases, amplitudes, timestamps)
        
        if len(cycles) < self.MIN_CYCLES:
            return None
        
        # Extract biometrics
        biometrics = self.feature_extractor.extract_biometrics(cycles)
        
        if biometrics is None:
            return None
        
        # Match against known profiles
        query_vector = biometrics.to_vector()
        
        match_scores = {}
        best_match = None
        best_score = 0.0
        
        for person_id, profile in self._profile_cache.items():
            score = self._compute_similarity(query_vector, profile.gait_signature.to_vector())
            match_scores[person_id] = score
            
            if score > best_score:
                best_score = score
                best_match = profile
        
        # Determine result
        if best_score >= self.IDENTIFICATION_THRESHOLD:
            # Identified existing person
            result = IdentificationResult(
                timestamp=time.time(),
                person_id=best_match.person_id,
                person_name=best_match.name,
                confidence=best_score,
                match_scores=match_scores,
                gait_cycle=cycles[-1],
                is_new_person=False
            )
            
            # Update profile with new sample
            self._update_profile(best_match, biometrics, query_vector)
            
        elif best_score < self.NEW_PERSON_THRESHOLD or not self._profile_cache:
            # New person
            result = IdentificationResult(
                timestamp=time.time(),
                person_id=None,
                person_name=None,
                confidence=1.0 - best_score if best_score > 0 else 1.0,
                match_scores=match_scores,
                gait_cycle=cycles[-1],
                is_new_person=True
            )
        else:
            # Uncertain - don't commit to identification
            result = IdentificationResult(
                timestamp=time.time(),
                person_id=None,
                person_name=None,
                confidence=best_score,
                match_scores=match_scores,
                gait_cycle=cycles[-1],
                is_new_person=False
            )
        
        # Log
        self.database.log_identification(result)
        
        return result
    
    def _compute_similarity(self, v1: np.ndarray, v2: np.ndarray) -> float:
        """Compute similarity between two feature vectors."""
        # Combine multiple distance metrics
        
        # Cosine similarity
        cosine_sim = 1.0 - cosine(v1, v2)
        
        # Normalized Euclidean (scaled to 0-1)
        euclidean_dist = euclidean(v1, v2)
        euclidean_sim = 1.0 / (1.0 + euclidean_dist / len(v1))
        
        # Correlation
        correlation = np.corrcoef(v1, v2)[0, 1]
        corr_sim = (correlation + 1) / 2
        
        # Weighted combination
        similarity = 0.4 * cosine_sim + 0.3 * euclidean_sim + 0.3 * corr_sim
        
        return float(np.clip(similarity, 0, 1))
    
    def _update_profile(self, profile: PersonProfile, biometrics: GaitBiometrics,
                       feature_vector: np.ndarray):
        """Update profile with new sample."""
        profile.last_seen = time.time()
        profile.sample_count += 1
        
        # Add to historical vectors
        profile.historical_vectors.append(feature_vector)
        
        # Keep only recent vectors
        if len(profile.historical_vectors) > 20:
            profile.historical_vectors = profile.historical_vectors[-20:]
        
        # Update signature with moving average
        alpha = 0.1  # Learning rate
        old_vector = profile.gait_signature.to_vector()
        new_vector = alpha * feature_vector + (1 - alpha) * old_vector
        
        # Reconstruct biometrics from vector (simplified)
        profile.gait_signature.avg_stride_frequency = new_vector[0]
        profile.gait_signature.stride_frequency_std = new_vector[1]
        profile.gait_signature.avg_cycle_duration = new_vector[2]
        profile.gait_signature.cycle_duration_std = new_vector[3]
        profile.gait_signature.stride_regularity = new_vector[4]
        profile.gait_signature.left_right_asymmetry = new_vector[5]
        profile.gait_signature.temporal_consistency = new_vector[6]
        
        # Update confidence based on consistency
        recent_vectors = np.array(profile.historical_vectors[-5:])
        if len(recent_vectors) >= 3:
            consistency = 1.0 - np.mean(np.std(recent_vectors, axis=0))
            profile.confidence = float(np.clip(consistency, 0.5, 0.99))
        
        # Save to database
        self.database.add_person(profile)
        self._profile_cache[profile.person_id] = profile
    
    def enroll_person(self, name: str, cycles: List[GaitCycle] = None) -> str:
        """
        Enroll a new person.
        
        If cycles provided, use them. Otherwise use current buffer.
        """
        if cycles is None:
            with self._lock:
                phases = np.array(self.phase_buffer)
                amplitudes = np.array(self.amplitude_buffer)
                timestamps = np.array(self.timestamp_buffer)
            
            cycles = self.cycle_extractor.extract_cycles(phases, amplitudes, timestamps)
        
        if len(cycles) < self.MIN_CYCLES:
            raise ValueError(f"Need at least {self.MIN_CYCLES} gait cycles for enrollment")
        
        biometrics = self.feature_extractor.extract_biometrics(cycles)
        
        if biometrics is None:
            raise ValueError("Failed to extract biometrics from gait cycles")
        
        # Generate unique ID
        timestamp = time.time()
        person_id = hashlib.sha256(f"{name}{timestamp}".encode()).hexdigest()[:16]
        
        profile = PersonProfile(
            person_id=person_id,
            name=name,
            created_at=timestamp,
            last_seen=timestamp,
            gait_signature=biometrics,
            sample_count=1,
            confidence=0.7,  # Initial confidence
            historical_vectors=[biometrics.to_vector()]
        )
        
        self.database.add_person(profile)
        self._profile_cache[person_id] = profile
        
        return person_id
    
    def get_all_persons(self) -> List[Dict]:
        """Get all enrolled persons."""
        return [
            {
                'person_id': p.person_id,
                'name': p.name,
                'created_at': p.created_at,
                'last_seen': p.last_seen,
                'sample_count': p.sample_count,
                'confidence': p.confidence,
                'avg_stride_frequency': p.gait_signature.avg_stride_frequency,
                'stride_regularity': p.gait_signature.stride_regularity,
            }
            for p in self._profile_cache.values()
        ]
    
    def get_statistics(self) -> Dict:
        """Get engine statistics."""
        return {
            'enrolled_persons': len(self._profile_cache),
            'buffer_fill': len(self.phase_buffer) / self.buffer_size,
            'persons': self.get_all_persons()
        }


class RealtimeGaitMonitor:
    """
    Real-time gait monitoring with presence detection.
    
    Automatically detects when someone is walking and
    attempts identification.
    """
    
    def __init__(self, num_subcarriers: int = 52):
        self.engine = GaitIdentificationEngine(num_subcarriers)
        
        # Walking detection
        self.energy_history: Deque[float] = deque(maxlen=100)
        self.walking_threshold = 0.0
        self.is_walking = False
        self.walk_start_time = 0.0
        self.min_walk_duration = 5.0  # seconds
        
        # Callbacks
        self.on_identification: Optional[callable] = None
        self.on_walk_start: Optional[callable] = None
        self.on_walk_end: Optional[callable] = None
        
        # Calibration
        self.calibrated = False
        self.calibration_samples = 0
    
    def add_csi_frame(self, amplitudes: List[float], phases: List[float],
                      timestamp: float = None):
        """Add CSI frame and detect walking."""
        if timestamp is None:
            timestamp = time.time()
        
        self.engine.add_csi_frame(amplitudes, phases, timestamp)
        
        # Compute motion energy
        if len(self.engine.phase_buffer) >= 2:
            phases = np.array(list(self.engine.phase_buffer)[-10:])
            velocity = np.diff(phases, axis=0)
            energy = float(np.mean(np.var(velocity, axis=0)))
            self.energy_history.append(energy)
        
        # Calibration
        if not self.calibrated:
            self.calibration_samples += 1
            if self.calibration_samples >= 300:  # 3 seconds at 100 Hz
                self.walking_threshold = np.mean(self.energy_history) * 3
                self.calibrated = True
            return
        
        # Walking detection
        current_energy = np.mean(list(self.energy_history)[-10:])
        
        if not self.is_walking and current_energy > self.walking_threshold:
            self.is_walking = True
            self.walk_start_time = timestamp
            if self.on_walk_start:
                self.on_walk_start()
        
        elif self.is_walking and current_energy < self.walking_threshold * 0.5:
            walk_duration = timestamp - self.walk_start_time
            self.is_walking = False
            
            if walk_duration >= self.min_walk_duration:
                if self.on_walk_end:
                    self.on_walk_end(walk_duration)
    
    def process(self) -> Optional[IdentificationResult]:
        """Process and identify if walking detected."""
        if not self.is_walking:
            return None
        
        walk_duration = time.time() - self.walk_start_time
        if walk_duration < self.min_walk_duration:
            return None
        
        result = self.engine.process()
        
        if result and self.on_identification:
            self.on_identification(result)
        
        return result


# Standalone testing
if __name__ == "__main__":
    print("=== WiFi Gait Identification Test ===\n")
    
    engine = GaitIdentificationEngine()
    
    # Simulate walking data for two different people
    def simulate_gait(person_seed: int, num_seconds: float = 15.0) -> List[Tuple[float, List[float], List[float]]]:
        """Simulate gait CSI data for a person."""
        np.random.seed(person_seed)
        
        sample_rate = 100
        num_samples = int(num_seconds * sample_rate)
        
        # Person-specific gait parameters
        stride_freq = 0.8 + np.random.rand() * 0.4  # 0.8-1.2 Hz
        asymmetry = np.random.rand() * 0.1  # Up to 10% asymmetry
        phase_offset = np.random.rand() * np.pi
        
        data = []
        for i in range(num_samples):
            t = i / sample_rate
            
            # Gait-induced phase modulation
            base_phase = (
                0.5 * np.sin(2 * np.pi * stride_freq * t + phase_offset) +  # Main stride
                0.2 * np.sin(4 * np.pi * stride_freq * t) +  # First harmonic
                0.1 * np.sin(6 * np.pi * stride_freq * t) +  # Second harmonic
                asymmetry * np.sin(np.pi * stride_freq * t)  # Asymmetry component
            )
            
            phases = []
            amplitudes = []
            
            for j in range(52):
                # Subcarrier-specific variations
                sc_phase = base_phase * (1 + 0.1 * np.sin(j * 0.2))
                sc_phase += np.random.randn() * 0.05  # Noise
                phases.append(sc_phase)
                
                amp = 50 + 5 * np.sin(2 * np.pi * stride_freq * t) + np.random.randn() * 2
                amplitudes.append(amp)
            
            data.append((t, amplitudes, phases))
        
        return data
    
    # Enroll Person 1
    print("Enrolling Person 1 (Alice)...")
    data1 = simulate_gait(person_seed=42)
    for t, amp, phase in data1:
        engine.add_csi_frame(amp, phase, t)
    
    person1_id = engine.enroll_person("Alice")
    print(f"  Enrolled with ID: {person1_id}")
    
    # Clear buffer and enroll Person 2
    engine.phase_buffer.clear()
    engine.amplitude_buffer.clear()
    engine.timestamp_buffer.clear()
    
    print("\nEnrolling Person 2 (Bob)...")
    data2 = simulate_gait(person_seed=123)
    for t, amp, phase in data2:
        engine.add_csi_frame(amp, phase, t)
    
    person2_id = engine.enroll_person("Bob")
    print(f"  Enrolled with ID: {person2_id}")
    
    # Now test identification
    print("\n--- Testing Identification ---")
    
    # Test with Alice's gait pattern
    engine.phase_buffer.clear()
    engine.amplitude_buffer.clear()
    engine.timestamp_buffer.clear()
    
    print("\nSimulating Alice walking...")
    data_test = simulate_gait(person_seed=42)  # Same seed as Alice
    for t, amp, phase in data_test:
        engine.add_csi_frame(amp, phase, t)
    
    result = engine.process()
    if result:
        if result.person_id:
            print(f"✓ Identified: {result.person_name} (confidence: {result.confidence:.2f})")
        elif result.is_new_person:
            print(f"? New person detected (confidence: {result.confidence:.2f})")
        else:
            print(f"? Uncertain match (best: {result.confidence:.2f})")
    
    # Test with Bob's gait pattern
    engine.phase_buffer.clear()
    engine.amplitude_buffer.clear()
    engine.timestamp_buffer.clear()
    
    print("\nSimulating Bob walking...")
    data_test = simulate_gait(person_seed=123)  # Same seed as Bob
    for t, amp, phase in data_test:
        engine.add_csi_frame(amp, phase, t)
    
    result = engine.process()
    if result:
        if result.person_id:
            print(f"✓ Identified: {result.person_name} (confidence: {result.confidence:.2f})")
        elif result.is_new_person:
            print(f"? New person detected (confidence: {result.confidence:.2f})")
        else:
            print(f"? Uncertain match (best: {result.confidence:.2f})")
    
    # Test with unknown person
    engine.phase_buffer.clear()
    engine.amplitude_buffer.clear()
    engine.timestamp_buffer.clear()
    
    print("\nSimulating unknown person walking...")
    data_test = simulate_gait(person_seed=999)  # Different seed
    for t, amp, phase in data_test:
        engine.add_csi_frame(amp, phase, t)
    
    result = engine.process()
    if result:
        if result.person_id:
            print(f"✓ Identified: {result.person_name} (confidence: {result.confidence:.2f})")
        elif result.is_new_person:
            print(f"? New person detected (confidence: {result.confidence:.2f})")
        else:
            print(f"? Uncertain match (best score: {max(result.match_scores.values()) if result.match_scores else 0:.2f})")
    
    print("\n--- Statistics ---")
    print(json.dumps(engine.get_statistics(), indent=2))
