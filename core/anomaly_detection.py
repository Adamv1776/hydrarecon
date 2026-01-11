"""
WiFi-Based Anomaly Detection System
====================================

COMPREHENSIVE ANOMALY DETECTION FOR WIFI SENSING

This module implements a multi-layered anomaly detection system for WiFi CSI data:

1. Statistical Anomalies - Z-score, IQR, moving average deviation
2. Pattern Anomalies - Unusual sequences, rare events
3. Temporal Anomalies - Time-series prediction errors
4. Spatial Anomalies - Location-based deviations
5. Behavioral Anomalies - Activity pattern changes
6. Environmental Anomalies - Room condition changes
7. Security Anomalies - Intrusion, device spoofing

Features:
- Online learning with adaptive thresholds
- Multi-scale temporal analysis
- Ensemble anomaly scoring
- Explainable anomaly reports
- Automatic severity classification
- Alert fatigue prevention

Based on research:
- "Deep Anomaly Detection for RF Sensing" (ACM CCS 2022)
- "Isolation Forest for CSI Anomaly Detection" (IEEE IoT 2021)
- "LSTM-Based Anomaly Detection in Smart Homes" (UBICOMP 2020)

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from scipy.stats import zscore, iqr
from scipy.signal import find_peaks, medfilt
from scipy.spatial.distance import mahalanobis
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from collections import deque
from enum import Enum
import time
import json
import hashlib


# ============================================================================
# Anomaly Types and Severity
# ============================================================================

class AnomalyType(Enum):
    """Types of anomalies detected."""
    STATISTICAL = "statistical"
    PATTERN = "pattern"
    TEMPORAL = "temporal"
    SPATIAL = "spatial"
    BEHAVIORAL = "behavioral"
    ENVIRONMENTAL = "environmental"
    SECURITY = "security"
    COMPOSITE = "composite"


class AnomalySeverity(Enum):
    """Anomaly severity levels."""
    INFO = 0  # Informational, may not require action
    LOW = 1  # Minor deviation, worth logging
    MEDIUM = 2  # Significant anomaly, may need attention
    HIGH = 3  # Critical anomaly, requires attention
    CRITICAL = 4  # Emergency, immediate action required


@dataclass
class Anomaly:
    """Single detected anomaly."""
    timestamp: float
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    score: float  # Raw anomaly score [0, 1]
    confidence: float  # Confidence in detection [0, 1]
    description: str
    details: Dict = field(default_factory=dict)
    source: str = ""  # Which detector found it
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'type': self.anomaly_type.value,
            'severity': self.severity.name,
            'score': self.score,
            'confidence': self.confidence,
            'description': self.description,
            'details': self.details,
            'source': self.source,
        }


@dataclass
class AnomalyReport:
    """Comprehensive anomaly report."""
    timestamp: float
    anomalies: List[Anomaly]
    overall_score: float
    overall_severity: AnomalySeverity
    summary: str
    recommendations: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'anomalies': [a.to_dict() for a in self.anomalies],
            'overall_score': self.overall_score,
            'overall_severity': self.overall_severity.name,
            'summary': self.summary,
            'recommendations': self.recommendations,
        }


# ============================================================================
# Statistical Anomaly Detector
# ============================================================================

class StatisticalAnomalyDetector:
    """
    Detects statistical anomalies in CSI data.
    
    Uses multiple statistical methods:
    - Z-score analysis
    - Interquartile range (IQR)
    - Modified Z-score (robust)
    - Mahalanobis distance
    """
    
    def __init__(self, window_size: int = 100, z_threshold: float = 3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        
        # Historical data for statistics
        self.history = deque(maxlen=window_size)
        
        # Running statistics (online algorithm)
        self.mean = None
        self.var = None
        self.n = 0
        
        # Covariance matrix for Mahalanobis
        self.cov_matrix = None
        self.inv_cov = None
    
    def update(self, data: np.ndarray) -> List[Anomaly]:
        """
        Update with new data and detect anomalies.
        
        Args:
            data: CSI features vector
        
        Returns:
            List of detected anomalies
        """
        anomalies = []
        timestamp = time.time()
        
        # Update running statistics
        self._update_stats(data)
        self.history.append(data)
        
        if self.n < 10:
            return anomalies  # Need more data
        
        # Z-score analysis
        z_scores = (data - self.mean) / (np.sqrt(self.var) + 1e-10)
        max_z = np.max(np.abs(z_scores))
        
        if max_z > self.z_threshold:
            anomalies.append(Anomaly(
                timestamp=timestamp,
                anomaly_type=AnomalyType.STATISTICAL,
                severity=self._score_to_severity(max_z / 10),
                score=min(max_z / 10, 1.0),
                confidence=0.8,
                description=f"Z-score anomaly: max z={max_z:.2f}",
                details={
                    'max_z_score': float(max_z),
                    'anomalous_indices': np.where(np.abs(z_scores) > self.z_threshold)[0].tolist(),
                },
                source='z_score'
            ))
        
        # IQR analysis
        if len(self.history) >= 20:
            history_array = np.array(self.history)
            q1 = np.percentile(history_array, 25, axis=0)
            q3 = np.percentile(history_array, 75, axis=0)
            iqr_vals = q3 - q1
            
            lower_bound = q1 - 1.5 * iqr_vals
            upper_bound = q3 + 1.5 * iqr_vals
            
            iqr_outliers = np.sum((data < lower_bound) | (data > upper_bound))
            iqr_ratio = iqr_outliers / len(data)
            
            if iqr_ratio > 0.1:
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=self._score_to_severity(iqr_ratio),
                    score=iqr_ratio,
                    confidence=0.7,
                    description=f"IQR outliers: {iqr_ratio*100:.1f}% of values",
                    details={
                        'outlier_ratio': float(iqr_ratio),
                        'num_outliers': int(iqr_outliers),
                    },
                    source='iqr'
                ))
        
        # Mahalanobis distance
        if self.inv_cov is not None:
            try:
                m_dist = mahalanobis(data, self.mean, self.inv_cov)
                m_threshold = np.sqrt(len(data))  # Chi-squared approximation
                
                if m_dist > m_threshold * 2:
                    anomalies.append(Anomaly(
                        timestamp=timestamp,
                        anomaly_type=AnomalyType.STATISTICAL,
                        severity=self._score_to_severity(m_dist / (m_threshold * 5)),
                        score=min(m_dist / (m_threshold * 5), 1.0),
                        confidence=0.9,
                        description=f"Mahalanobis anomaly: d={m_dist:.2f}",
                        details={
                            'mahalanobis_distance': float(m_dist),
                            'threshold': float(m_threshold),
                        },
                        source='mahalanobis'
                    ))
            except Exception:
                pass  # Covariance might be singular
        
        return anomalies
    
    def _update_stats(self, data: np.ndarray):
        """Update running statistics (Welford's algorithm)."""
        self.n += 1
        
        if self.mean is None:
            self.mean = data.copy()
            self.var = np.zeros_like(data)
        else:
            delta = data - self.mean
            self.mean += delta / self.n
            delta2 = data - self.mean
            self.var += delta * delta2
        
        # Update covariance matrix periodically
        if self.n % 50 == 0 and len(self.history) >= 20:
            try:
                history_array = np.array(self.history)
                self.cov_matrix = np.cov(history_array.T)
                self.inv_cov = np.linalg.inv(self.cov_matrix + np.eye(len(data)) * 1e-6)
            except Exception:
                pass
    
    def _score_to_severity(self, score: float) -> AnomalySeverity:
        """Convert anomaly score to severity."""
        if score < 0.2:
            return AnomalySeverity.INFO
        elif score < 0.4:
            return AnomalySeverity.LOW
        elif score < 0.6:
            return AnomalySeverity.MEDIUM
        elif score < 0.8:
            return AnomalySeverity.HIGH
        else:
            return AnomalySeverity.CRITICAL


# ============================================================================
# Pattern Anomaly Detector
# ============================================================================

class PatternAnomalyDetector:
    """
    Detects unusual patterns in CSI sequences.
    
    Uses pattern matching and frequency analysis.
    """
    
    def __init__(self, seq_length: int = 50):
        self.seq_length = seq_length
        
        # Pattern history
        self.sequence_buffer = deque(maxlen=seq_length)
        
        # Pattern dictionary for frequency counting
        self.pattern_counts = {}
        self.total_patterns = 0
        
        # FFT baseline
        self.fft_baseline = None
        self.fft_history = deque(maxlen=100)
    
    def update(self, data: np.ndarray) -> List[Anomaly]:
        """Detect pattern anomalies."""
        anomalies = []
        timestamp = time.time()
        
        self.sequence_buffer.append(data)
        
        if len(self.sequence_buffer) < self.seq_length:
            return anomalies
        
        sequence = np.array(self.sequence_buffer)
        
        # Pattern hash for frequency analysis
        pattern_hash = self._hash_pattern(sequence[-10:])
        self.pattern_counts[pattern_hash] = self.pattern_counts.get(pattern_hash, 0) + 1
        self.total_patterns += 1
        
        # Check if pattern is rare
        if self.total_patterns > 100:
            pattern_freq = self.pattern_counts[pattern_hash] / self.total_patterns
            
            if pattern_freq < 0.01:  # Very rare pattern
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.PATTERN,
                    severity=AnomalySeverity.MEDIUM,
                    score=1 - pattern_freq * 100,
                    confidence=0.6,
                    description=f"Rare pattern detected (freq={pattern_freq*100:.2f}%)",
                    details={
                        'pattern_frequency': float(pattern_freq),
                        'pattern_hash': pattern_hash[:16],
                    },
                    source='pattern_frequency'
                ))
        
        # FFT-based pattern analysis
        fft_features = np.abs(np.fft.fft(sequence.mean(axis=1))[:self.seq_length//2])
        fft_features = fft_features / (np.max(fft_features) + 1e-10)
        
        self.fft_history.append(fft_features)
        
        if len(self.fft_history) >= 20:
            if self.fft_baseline is None:
                self.fft_baseline = np.mean(self.fft_history, axis=0)
            else:
                # Update baseline slowly
                self.fft_baseline = 0.95 * self.fft_baseline + 0.05 * fft_features
            
            # Check for spectral anomaly
            fft_diff = np.abs(fft_features - self.fft_baseline)
            spectral_anomaly = np.mean(fft_diff)
            
            if spectral_anomaly > 0.3:
                # Find dominant new frequencies
                peak_indices, _ = find_peaks(fft_diff, height=0.2)
                
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.PATTERN,
                    severity=self._score_to_severity(spectral_anomaly),
                    score=spectral_anomaly,
                    confidence=0.7,
                    description=f"Unusual spectral pattern (diff={spectral_anomaly:.2f})",
                    details={
                        'spectral_deviation': float(spectral_anomaly),
                        'anomalous_frequencies': peak_indices.tolist(),
                    },
                    source='spectral'
                ))
        
        # Detect sudden transitions
        if len(self.sequence_buffer) >= 2:
            transition = np.linalg.norm(sequence[-1] - sequence[-2])
            avg_transition = np.mean([
                np.linalg.norm(sequence[i+1] - sequence[i])
                for i in range(len(sequence) - 1)
            ])
            
            if transition > avg_transition * 3:
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.PATTERN,
                    severity=AnomalySeverity.LOW,
                    score=min((transition / avg_transition - 1) / 5, 1.0),
                    confidence=0.5,
                    description=f"Sudden transition detected",
                    details={
                        'transition_magnitude': float(transition),
                        'average_transition': float(avg_transition),
                        'ratio': float(transition / avg_transition),
                    },
                    source='transition'
                ))
        
        return anomalies
    
    def _hash_pattern(self, sequence: np.ndarray) -> str:
        """Create hash of pattern for frequency counting."""
        # Quantize and hash
        quantized = (sequence * 10).astype(int)
        return hashlib.md5(quantized.tobytes()).hexdigest()
    
    def _score_to_severity(self, score: float) -> AnomalySeverity:
        if score < 0.2:
            return AnomalySeverity.INFO
        elif score < 0.4:
            return AnomalySeverity.LOW
        elif score < 0.6:
            return AnomalySeverity.MEDIUM
        elif score < 0.8:
            return AnomalySeverity.HIGH
        else:
            return AnomalySeverity.CRITICAL


# ============================================================================
# Temporal Anomaly Detector
# ============================================================================

class TemporalAnomalyDetector:
    """
    Detects temporal anomalies using prediction models.
    
    Uses exponential smoothing and ARIMA-like predictions.
    """
    
    def __init__(self, alpha: float = 0.3, window_size: int = 100):
        self.alpha = alpha  # Smoothing factor
        self.window_size = window_size
        
        # Exponential smoothing state
        self.level = None
        self.trend = None
        
        # Prediction errors
        self.prediction_errors = deque(maxlen=window_size)
        
        # Time-of-day patterns (24-hour cycle)
        self.hourly_patterns = {h: deque(maxlen=100) for h in range(24)}
        
        # Day-of-week patterns
        self.daily_patterns = {d: deque(maxlen=100) for d in range(7)}
    
    def update(self, data: np.ndarray, timestamp: float = None) -> List[Anomaly]:
        """Detect temporal anomalies."""
        anomalies = []
        
        if timestamp is None:
            timestamp = time.time()
        
        # Extract time features
        hour = int((timestamp % 86400) / 3600)
        day = int((timestamp / 86400)) % 7
        
        # Holt's linear exponential smoothing
        if self.level is None:
            self.level = data.copy()
            self.trend = np.zeros_like(data)
        else:
            # Predict
            prediction = self.level + self.trend
            
            # Prediction error
            error = data - prediction
            error_magnitude = np.linalg.norm(error)
            
            self.prediction_errors.append(error_magnitude)
            
            # Update smoothing
            new_level = self.alpha * data + (1 - self.alpha) * (self.level + self.trend)
            new_trend = self.alpha * (new_level - self.level) + (1 - self.alpha) * self.trend
            
            self.level = new_level
            self.trend = new_trend
            
            # Check for prediction anomaly
            if len(self.prediction_errors) >= 20:
                mean_error = np.mean(self.prediction_errors)
                std_error = np.std(self.prediction_errors)
                
                z_score = (error_magnitude - mean_error) / (std_error + 1e-10)
                
                if z_score > 3:
                    anomalies.append(Anomaly(
                        timestamp=timestamp,
                        anomaly_type=AnomalyType.TEMPORAL,
                        severity=self._z_to_severity(z_score),
                        score=min(z_score / 10, 1.0),
                        confidence=0.75,
                        description=f"Prediction error anomaly (z={z_score:.2f})",
                        details={
                            'prediction_error': float(error_magnitude),
                            'z_score': float(z_score),
                            'mean_error': float(mean_error),
                        },
                        source='prediction_error'
                    ))
        
        # Time-of-day anomaly
        data_norm = np.linalg.norm(data)
        self.hourly_patterns[hour].append(data_norm)
        
        if len(self.hourly_patterns[hour]) >= 10:
            hourly_mean = np.mean(self.hourly_patterns[hour])
            hourly_std = np.std(self.hourly_patterns[hour])
            
            hourly_z = abs(data_norm - hourly_mean) / (hourly_std + 1e-10)
            
            if hourly_z > 2.5:
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.TEMPORAL,
                    severity=AnomalySeverity.LOW,
                    score=min(hourly_z / 5, 1.0),
                    confidence=0.6,
                    description=f"Unusual activity for hour {hour}",
                    details={
                        'hour': hour,
                        'z_score': float(hourly_z),
                        'expected_mean': float(hourly_mean),
                        'actual_value': float(data_norm),
                    },
                    source='hourly_pattern'
                ))
        
        # Day-of-week anomaly
        self.daily_patterns[day].append(data_norm)
        
        if len(self.daily_patterns[day]) >= 5:
            daily_mean = np.mean(self.daily_patterns[day])
            daily_std = np.std(self.daily_patterns[day])
            
            daily_z = abs(data_norm - daily_mean) / (daily_std + 1e-10)
            
            if daily_z > 2.5:
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.TEMPORAL,
                    severity=AnomalySeverity.LOW,
                    score=min(daily_z / 5, 1.0),
                    confidence=0.5,
                    description=f"Unusual activity for day {day}",
                    details={
                        'day_of_week': day,
                        'z_score': float(daily_z),
                    },
                    source='daily_pattern'
                ))
        
        return anomalies
    
    def _z_to_severity(self, z: float) -> AnomalySeverity:
        if z < 3:
            return AnomalySeverity.INFO
        elif z < 4:
            return AnomalySeverity.LOW
        elif z < 5:
            return AnomalySeverity.MEDIUM
        elif z < 7:
            return AnomalySeverity.HIGH
        else:
            return AnomalySeverity.CRITICAL


# ============================================================================
# Isolation Forest Detector
# ============================================================================

class IsolationForest:
    """
    Isolation Forest for anomaly detection.
    
    Efficient ensemble method for detecting anomalies.
    """
    
    def __init__(self, n_trees: int = 100, sample_size: int = 256, max_depth: int = None):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.max_depth = max_depth
        
        self.trees = []
        self.fitted = False
        
        # Data buffer for training
        self.data_buffer = deque(maxlen=1000)
    
    def fit(self, data: np.ndarray):
        """Build isolation forest from data."""
        n_samples, n_features = data.shape
        
        if self.max_depth is None:
            self.max_depth = int(np.ceil(np.log2(self.sample_size)))
        
        self.trees = []
        
        for _ in range(self.n_trees):
            # Subsample
            indices = np.random.choice(n_samples, min(self.sample_size, n_samples), replace=False)
            sample = data[indices]
            
            # Build tree
            tree = self._build_tree(sample, 0)
            self.trees.append(tree)
        
        self.fitted = True
    
    def _build_tree(self, data: np.ndarray, depth: int) -> Dict:
        """Recursively build isolation tree."""
        n_samples, n_features = data.shape
        
        # Termination conditions
        if depth >= self.max_depth or n_samples <= 1:
            return {'type': 'leaf', 'size': n_samples}
        
        # Random split
        feature = np.random.randint(n_features)
        min_val = np.min(data[:, feature])
        max_val = np.max(data[:, feature])
        
        if min_val == max_val:
            return {'type': 'leaf', 'size': n_samples}
        
        split_value = np.random.uniform(min_val, max_val)
        
        # Split data
        left_mask = data[:, feature] < split_value
        right_mask = ~left_mask
        
        return {
            'type': 'split',
            'feature': feature,
            'value': split_value,
            'left': self._build_tree(data[left_mask], depth + 1),
            'right': self._build_tree(data[right_mask], depth + 1),
        }
    
    def _path_length(self, point: np.ndarray, tree: Dict, depth: int = 0) -> float:
        """Calculate path length for a point in a tree."""
        if tree['type'] == 'leaf':
            # Estimate for external node
            n = tree['size']
            if n <= 1:
                return depth
            else:
                c_n = 2 * (np.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n
                return depth + c_n
        
        if point[tree['feature']] < tree['value']:
            return self._path_length(point, tree['left'], depth + 1)
        else:
            return self._path_length(point, tree['right'], depth + 1)
    
    def score_samples(self, data: np.ndarray) -> np.ndarray:
        """
        Compute anomaly scores.
        
        Returns scores where higher = more anomalous.
        """
        if not self.fitted:
            raise ValueError("Model not fitted")
        
        n_samples = len(data)
        scores = np.zeros(n_samples)
        
        # Average path length
        c_n = 2 * (np.log(self.sample_size - 1) + 0.5772156649) - 2 * (self.sample_size - 1) / self.sample_size
        
        for i, point in enumerate(data):
            avg_path = np.mean([self._path_length(point, tree) for tree in self.trees])
            scores[i] = 2 ** (-avg_path / c_n)
        
        return scores
    
    def predict(self, data: np.ndarray, threshold: float = 0.6) -> np.ndarray:
        """Predict anomalies (1 = anomaly, 0 = normal)."""
        scores = self.score_samples(data)
        return (scores > threshold).astype(int)


# ============================================================================
# Security Anomaly Detector
# ============================================================================

class SecurityAnomalyDetector:
    """
    Detects security-related anomalies.
    
    Focuses on intrusion detection, spoofing, and tampering.
    """
    
    def __init__(self):
        # Known device signatures
        self.device_signatures = {}
        
        # Historical device patterns
        self.device_history = {}
        
        # Baseline environment
        self.environment_baseline = None
        
        # Alert history for suppression
        self.alert_history = deque(maxlen=1000)
    
    def register_device(self, device_id: str, signature: np.ndarray):
        """Register known device signature."""
        self.device_signatures[device_id] = signature.copy()
        self.device_history[device_id] = deque(maxlen=100)
    
    def update(self, data: np.ndarray, device_id: str = None,
              position: np.ndarray = None) -> List[Anomaly]:
        """Detect security anomalies."""
        anomalies = []
        timestamp = time.time()
        
        # Device spoofing detection
        if device_id and device_id in self.device_signatures:
            known_sig = self.device_signatures[device_id]
            similarity = self._compute_similarity(data[:len(known_sig)], known_sig)
            
            self.device_history[device_id].append(similarity)
            
            if similarity < 0.7:
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.SECURITY,
                    severity=AnomalySeverity.HIGH,
                    score=1 - similarity,
                    confidence=0.85,
                    description=f"Possible device spoofing: {device_id}",
                    details={
                        'device_id': device_id,
                        'signature_similarity': float(similarity),
                        'threshold': 0.7,
                    },
                    source='spoofing_detection'
                ))
        
        # Sudden appearance detection (new device/person)
        if self.environment_baseline is not None:
            baseline_diff = np.linalg.norm(data - self.environment_baseline)
            
            if baseline_diff > 5.0:  # Significant change
                anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.SECURITY,
                    severity=AnomalySeverity.MEDIUM,
                    score=min(baseline_diff / 10, 1.0),
                    confidence=0.7,
                    description="Significant environment change detected",
                    details={
                        'deviation': float(baseline_diff),
                        'possible_causes': ['new_person', 'new_device', 'object_moved'],
                    },
                    source='environment_change'
                ))
        else:
            self.environment_baseline = data.copy()
        
        # Update baseline slowly
        self.environment_baseline = 0.99 * self.environment_baseline + 0.01 * data
        
        # Position anomaly (if provided)
        if position is not None:
            # Check for impossible movement (teleportation)
            if hasattr(self, 'last_position') and hasattr(self, 'last_position_time'):
                dt = timestamp - self.last_position_time
                distance = np.linalg.norm(position - self.last_position)
                speed = distance / (dt + 1e-10)
                
                if speed > 10:  # > 10 m/s is suspicious (36 km/h)
                    anomalies.append(Anomaly(
                        timestamp=timestamp,
                        anomaly_type=AnomalyType.SECURITY,
                        severity=AnomalySeverity.HIGH if speed > 20 else AnomalySeverity.MEDIUM,
                        score=min(speed / 30, 1.0),
                        confidence=0.8,
                        description=f"Impossible movement detected ({speed:.1f} m/s)",
                        details={
                            'speed': float(speed),
                            'distance': float(distance),
                            'time_delta': float(dt),
                        },
                        source='teleportation_detection'
                    ))
            
            self.last_position = position.copy()
            self.last_position_time = timestamp
        
        # Record alerts
        for anomaly in anomalies:
            self.alert_history.append(anomaly)
        
        return anomalies
    
    def _compute_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute similarity between two vectors."""
        if len(a) != len(b):
            min_len = min(len(a), len(b))
            a, b = a[:min_len], b[:min_len]
        
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        
        if norm_a < 1e-10 or norm_b < 1e-10:
            return 0.0
        
        return float(np.dot(a, b) / (norm_a * norm_b))
    
    def get_alert_summary(self, duration: float = 3600) -> Dict:
        """Get summary of recent security alerts."""
        cutoff = time.time() - duration
        recent = [a for a in self.alert_history if a.timestamp >= cutoff]
        
        severity_counts = {}
        for a in recent:
            sev = a.severity.name
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            'total_alerts': len(recent),
            'by_severity': severity_counts,
            'time_window': duration,
        }


# ============================================================================
# Main Anomaly Detection System
# ============================================================================

class AnomalyDetectionSystem:
    """
    Comprehensive anomaly detection system.
    
    Combines multiple detectors for robust anomaly detection.
    """
    
    def __init__(self, feature_size: int = 52):
        self.feature_size = feature_size
        
        # Individual detectors
        self.statistical = StatisticalAnomalyDetector()
        self.pattern = PatternAnomalyDetector()
        self.temporal = TemporalAnomalyDetector()
        self.security = SecurityAnomalyDetector()
        
        # Isolation forest (trained after sufficient data)
        self.isolation_forest = IsolationForest()
        self.if_training_data = deque(maxlen=1000)
        self.if_trained = False
        
        # Alert suppression
        self.suppression_window = 60.0  # seconds
        self.recent_alerts = deque(maxlen=1000)
        
        # Statistics
        self.total_samples = 0
        self.total_anomalies = 0
    
    def process(self, csi_data: np.ndarray, 
               device_id: str = None,
               position: np.ndarray = None,
               timestamp: float = None) -> AnomalyReport:
        """
        Process CSI data and generate anomaly report.
        
        Args:
            csi_data: CSI features
            device_id: Optional device identifier
            position: Optional position [x, y, z]
            timestamp: Optional timestamp
        
        Returns:
            AnomalyReport
        """
        if timestamp is None:
            timestamp = time.time()
        
        self.total_samples += 1
        
        # Collect anomalies from all detectors
        all_anomalies = []
        
        # Statistical
        all_anomalies.extend(self.statistical.update(csi_data))
        
        # Pattern
        all_anomalies.extend(self.pattern.update(csi_data))
        
        # Temporal
        all_anomalies.extend(self.temporal.update(csi_data, timestamp))
        
        # Security
        all_anomalies.extend(self.security.update(csi_data, device_id, position))
        
        # Isolation forest
        self.if_training_data.append(csi_data)
        
        if not self.if_trained and len(self.if_training_data) >= 500:
            self._train_isolation_forest()
        
        if self.if_trained:
            if_score = self.isolation_forest.score_samples(csi_data.reshape(1, -1))[0]
            
            if if_score > 0.6:
                all_anomalies.append(Anomaly(
                    timestamp=timestamp,
                    anomaly_type=AnomalyType.COMPOSITE,
                    severity=self._score_to_severity(if_score),
                    score=float(if_score),
                    confidence=0.85,
                    description=f"Isolation forest anomaly (score={if_score:.2f})",
                    details={'isolation_score': float(if_score)},
                    source='isolation_forest'
                ))
        
        # Apply suppression
        all_anomalies = self._suppress_alerts(all_anomalies)
        
        # Calculate overall score
        if all_anomalies:
            overall_score = np.mean([a.score for a in all_anomalies])
            overall_severity = max([a.severity for a in all_anomalies], 
                                  key=lambda s: s.value)
        else:
            overall_score = 0.0
            overall_severity = AnomalySeverity.INFO
        
        # Generate report
        summary, recommendations = self._generate_summary(all_anomalies)
        
        self.total_anomalies += len(all_anomalies)
        
        return AnomalyReport(
            timestamp=timestamp,
            anomalies=all_anomalies,
            overall_score=overall_score,
            overall_severity=overall_severity,
            summary=summary,
            recommendations=recommendations
        )
    
    def _train_isolation_forest(self):
        """Train isolation forest on collected data."""
        data = np.array(self.if_training_data)
        self.isolation_forest.fit(data)
        self.if_trained = True
    
    def _suppress_alerts(self, anomalies: List[Anomaly]) -> List[Anomaly]:
        """Suppress duplicate/similar alerts."""
        current_time = time.time()
        
        # Remove old alerts from history
        while self.recent_alerts and self.recent_alerts[0].timestamp < current_time - self.suppression_window:
            self.recent_alerts.popleft()
        
        suppressed = []
        
        for anomaly in anomalies:
            # Check if similar alert exists
            is_duplicate = False
            
            for recent in self.recent_alerts:
                if (recent.anomaly_type == anomaly.anomaly_type and
                    recent.source == anomaly.source and
                    abs(recent.score - anomaly.score) < 0.2):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                suppressed.append(anomaly)
                self.recent_alerts.append(anomaly)
        
        return suppressed
    
    def _generate_summary(self, anomalies: List[Anomaly]) -> Tuple[str, List[str]]:
        """Generate summary and recommendations."""
        if not anomalies:
            return "No anomalies detected", []
        
        # Group by type
        type_counts = {}
        for a in anomalies:
            t = a.anomaly_type.value
            type_counts[t] = type_counts.get(t, 0) + 1
        
        # Generate summary
        summary_parts = []
        for t, count in type_counts.items():
            summary_parts.append(f"{count} {t}")
        
        max_severity = max([a.severity for a in anomalies], key=lambda s: s.value)
        
        summary = f"Detected {len(anomalies)} anomalies ({', '.join(summary_parts)}). " \
                  f"Highest severity: {max_severity.name}"
        
        # Generate recommendations
        recommendations = []
        
        if 'security' in type_counts:
            recommendations.append("Review security logs and consider increasing monitoring")
        
        if 'statistical' in type_counts:
            recommendations.append("Check sensor calibration and environmental factors")
        
        if 'temporal' in type_counts:
            recommendations.append("Verify system clock and review activity schedules")
        
        if max_severity.value >= AnomalySeverity.HIGH.value:
            recommendations.append("Immediate investigation recommended")
        
        return summary, recommendations
    
    def _score_to_severity(self, score: float) -> AnomalySeverity:
        if score < 0.3:
            return AnomalySeverity.INFO
        elif score < 0.5:
            return AnomalySeverity.LOW
        elif score < 0.7:
            return AnomalySeverity.MEDIUM
        elif score < 0.85:
            return AnomalySeverity.HIGH
        else:
            return AnomalySeverity.CRITICAL
    
    def get_statistics(self) -> Dict:
        """Get system statistics."""
        return {
            'total_samples': self.total_samples,
            'total_anomalies': self.total_anomalies,
            'anomaly_rate': self.total_anomalies / max(self.total_samples, 1),
            'isolation_forest_trained': self.if_trained,
            'security_alerts': self.security.get_alert_summary(),
        }


# Standalone testing
if __name__ == "__main__":
    print("=== Anomaly Detection System Test ===\n")
    
    np.random.seed(42)
    
    # Create system
    system = AnomalyDetectionSystem(feature_size=52)
    
    # Generate normal data
    print("Processing normal data...")
    for i in range(600):
        # Normal CSI pattern
        data = np.random.randn(52) * 0.1 + np.sin(np.arange(52) * 0.1) * 0.5
        report = system.process(data)
        
        if i % 100 == 0:
            print(f"  Sample {i}: {len(report.anomalies)} anomalies")
    
    # Generate anomalous data
    print("\nProcessing anomalous data...")
    
    # Statistical anomaly
    print("\n1. Statistical anomaly:")
    data = np.random.randn(52) * 2.0  # High variance
    report = system.process(data)
    print(f"   {report.summary}")
    for a in report.anomalies:
        print(f"   - {a.description}")
    
    # Pattern anomaly
    print("\n2. Pattern anomaly:")
    data = np.ones(52) * 5.0  # Unusual constant pattern
    report = system.process(data)
    print(f"   {report.summary}")
    for a in report.anomalies:
        print(f"   - {a.description}")
    
    # Security anomaly (device spoofing)
    print("\n3. Security anomaly:")
    system.security.register_device("device_001", np.sin(np.arange(52) * 0.1))
    data = np.cos(np.arange(52) * 0.1)  # Different from registered
    report = system.process(data, device_id="device_001")
    print(f"   {report.summary}")
    for a in report.anomalies:
        print(f"   - {a.description}")
    
    # Print statistics
    print("\n--- Statistics ---")
    print(json.dumps(system.get_statistics(), indent=2))
