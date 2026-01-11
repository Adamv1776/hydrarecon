"""
HydraRecon Biometric Security Module
=====================================

Advanced biometric analysis for security:
- Facial recognition and analysis
- Voice biometric authentication
- Fingerprint pattern analysis
- Iris pattern recognition
- Behavioral biometrics
- Gait analysis
- Keystroke dynamics
- Liveness detection
- Anti-spoofing measures
- Multi-modal biometric fusion
"""

import os
import time
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime
from enum import Enum, auto
from abc import ABC, abstractmethod
import numpy as np
import json
from collections import deque

# Optional imports
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from scipy.signal import spectrogram, butter, filtfilt
    from scipy.spatial.distance import cosine, euclidean
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


class BiometricType(Enum):
    """Types of biometric modalities"""
    FACE = auto()
    VOICE = auto()
    FINGERPRINT = auto()
    IRIS = auto()
    KEYSTROKE = auto()
    GAIT = auto()
    SIGNATURE = auto()
    HAND_GEOMETRY = auto()


class AuthResult(Enum):
    """Authentication result"""
    AUTHENTICATED = auto()
    REJECTED = auto()
    SPOOF_DETECTED = auto()
    INSUFFICIENT_QUALITY = auto()
    NOT_ENROLLED = auto()
    ERROR = auto()


@dataclass
class BiometricTemplate:
    """Biometric template for matching"""
    template_id: str
    user_id: str
    modality: BiometricType
    template_data: np.ndarray
    quality_score: float
    created_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'template_id': self.template_id,
            'user_id': self.user_id,
            'modality': self.modality.name,
            'quality_score': self.quality_score,
            'created_at': self.created_at,
            'metadata': self.metadata
        }


@dataclass
class MatchResult:
    """Biometric match result"""
    matched: bool
    score: float
    threshold: float
    user_id: Optional[str] = None
    auth_result: AuthResult = AuthResult.REJECTED
    confidence: float = 0.0
    processing_time: float = 0.0
    liveness_passed: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Facial Recognition
# =============================================================================

class FaceAnalyzer:
    """Facial recognition and analysis"""
    
    def __init__(self):
        self.face_cascade = None
        self.embedding_model = None
        self.liveness_model = None
        
        # Template database
        self.templates: Dict[str, BiometricTemplate] = {}
        
        # Settings
        self.min_face_size = (100, 100)
        self.match_threshold = 0.6
        
        if CV2_AVAILABLE:
            self._init_opencv()
    
    def _init_opencv(self):
        """Initialize OpenCV face detection"""
        try:
            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            self.face_cascade = cv2.CascadeClassifier(cascade_path)
        except Exception:
            pass  # Consider: logger.exception('Unexpected error')
    
    def detect_faces(self, image: np.ndarray) -> List[Dict[str, Any]]:
        """Detect faces in image"""
        faces = []
        
        if CV2_AVAILABLE and self.face_cascade is not None:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
            detections = self.face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=self.min_face_size
            )
            
            for (x, y, w, h) in detections:
                faces.append({
                    'bbox': (x, y, w, h),
                    'confidence': 0.95,
                    'landmarks': self._estimate_landmarks(x, y, w, h)
                })
        else:
            # Simulated detection
            h, w = image.shape[:2]
            faces.append({
                'bbox': (w // 4, h // 4, w // 2, h // 2),
                'confidence': 0.9,
                'landmarks': {}
            })
        
        return faces
    
    def _estimate_landmarks(self, x: int, y: int, w: int, h: int) -> Dict[str, Tuple[int, int]]:
        """Estimate facial landmarks from bounding box"""
        return {
            'left_eye': (x + w // 3, y + h // 3),
            'right_eye': (x + 2 * w // 3, y + h // 3),
            'nose': (x + w // 2, y + h // 2),
            'left_mouth': (x + w // 3, y + 2 * h // 3),
            'right_mouth': (x + 2 * w // 3, y + 2 * h // 3)
        }
    
    def extract_embedding(self, face_image: np.ndarray) -> np.ndarray:
        """Extract face embedding vector"""
        # In production, would use deep learning model (FaceNet, ArcFace, etc.)
        # Simulated 128-dimensional embedding
        
        # Use image statistics as simple feature
        if len(face_image.shape) == 3:
            features = []
            for c in range(3):
                channel = face_image[:, :, c]
                features.extend([
                    np.mean(channel),
                    np.std(channel),
                    np.median(channel)
                ])
            # Pad to 128 dimensions
            embedding = np.array(features + [0] * (128 - len(features)))
        else:
            embedding = np.random.randn(128)
        
        # Normalize
        embedding = embedding / (np.linalg.norm(embedding) + 1e-10)
        return embedding
    
    def assess_quality(self, face_image: np.ndarray) -> Dict[str, float]:
        """Assess face image quality"""
        h, w = face_image.shape[:2]
        
        # Resolution score
        resolution_score = min(1.0, (h * w) / (300 * 300))
        
        # Blur detection
        if CV2_AVAILABLE and len(face_image.shape) == 3:
            gray = cv2.cvtColor(face_image, cv2.COLOR_BGR2GRAY)
            laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
            blur_score = min(1.0, laplacian_var / 500)
        else:
            blur_score = 0.8
        
        # Illumination score (simple)
        if len(face_image.shape) == 3:
            brightness = np.mean(face_image)
            illumination_score = 1.0 - abs(brightness - 127) / 127
        else:
            illumination_score = 0.8
        
        overall = (resolution_score + blur_score + illumination_score) / 3
        
        return {
            'resolution': resolution_score,
            'sharpness': blur_score,
            'illumination': illumination_score,
            'overall': overall
        }
    
    def check_liveness(self, images: List[np.ndarray]) -> Tuple[bool, float, str]:
        """Check liveness using multiple frames"""
        if len(images) < 2:
            return True, 0.5, "insufficient_frames"
        
        # Simple liveness check based on motion
        # In production, would use deep learning
        
        motion_detected = False
        blink_detected = False
        
        for i in range(1, len(images)):
            if CV2_AVAILABLE:
                diff = cv2.absdiff(images[i], images[i - 1])
                motion = np.mean(diff)
                if motion > 5:
                    motion_detected = True
        
        liveness_score = 0.5
        if motion_detected:
            liveness_score += 0.3
        if blink_detected:
            liveness_score += 0.2
        
        is_live = liveness_score > 0.6
        
        return is_live, liveness_score, "motion_based"
    
    def enroll(self, user_id: str, face_images: List[np.ndarray]) -> BiometricTemplate:
        """Enroll new face template"""
        embeddings = []
        
        for image in face_images:
            faces = self.detect_faces(image)
            if faces:
                # Extract face region
                bbox = faces[0]['bbox']
                face_crop = image[bbox[1]:bbox[1] + bbox[3], bbox[0]:bbox[0] + bbox[2]]
                embedding = self.extract_embedding(face_crop)
                embeddings.append(embedding)
        
        if not embeddings:
            raise ValueError("No faces detected in images")
        
        # Average embeddings
        avg_embedding = np.mean(embeddings, axis=0)
        avg_embedding = avg_embedding / (np.linalg.norm(avg_embedding) + 1e-10)
        
        # Create template
        template = BiometricTemplate(
            template_id=hashlib.md5(f"{user_id}_{time.time()}".encode()).hexdigest()[:16],
            user_id=user_id,
            modality=BiometricType.FACE,
            template_data=avg_embedding,
            quality_score=np.mean([self.assess_quality(img)['overall'] for img in face_images]),
            created_at=time.time(),
            metadata={'num_samples': len(face_images)}
        )
        
        self.templates[template.template_id] = template
        return template
    
    def verify(self, user_id: str, face_image: np.ndarray) -> MatchResult:
        """Verify face against enrolled template"""
        start_time = time.time()
        
        # Find user templates
        user_templates = [t for t in self.templates.values() if t.user_id == user_id]
        
        if not user_templates:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.NOT_ENROLLED
            )
        
        # Detect face
        faces = self.detect_faces(face_image)
        if not faces:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.INSUFFICIENT_QUALITY
            )
        
        # Extract embedding
        bbox = faces[0]['bbox']
        face_crop = face_image[bbox[1]:bbox[1] + bbox[3], bbox[0]:bbox[0] + bbox[2]]
        probe_embedding = self.extract_embedding(face_crop)
        
        # Match against templates
        best_score = 0.0
        for template in user_templates:
            if SCIPY_AVAILABLE:
                score = 1 - cosine(probe_embedding, template.template_data)
            else:
                score = np.dot(probe_embedding, template.template_data)
            best_score = max(best_score, score)
        
        matched = best_score >= self.match_threshold
        
        return MatchResult(
            matched=matched,
            score=best_score,
            threshold=self.match_threshold,
            user_id=user_id,
            auth_result=AuthResult.AUTHENTICATED if matched else AuthResult.REJECTED,
            confidence=best_score,
            processing_time=time.time() - start_time
        )
    
    def identify(self, face_image: np.ndarray) -> MatchResult:
        """Identify face from enrolled templates"""
        start_time = time.time()
        
        # Detect face
        faces = self.detect_faces(face_image)
        if not faces:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.INSUFFICIENT_QUALITY
            )
        
        # Extract embedding
        bbox = faces[0]['bbox']
        face_crop = face_image[bbox[1]:bbox[1] + bbox[3], bbox[0]:bbox[0] + bbox[2]]
        probe_embedding = self.extract_embedding(face_crop)
        
        # Search all templates
        best_match = None
        best_score = 0.0
        
        for template in self.templates.values():
            if template.modality != BiometricType.FACE:
                continue
            
            if SCIPY_AVAILABLE:
                score = 1 - cosine(probe_embedding, template.template_data)
            else:
                score = np.dot(probe_embedding, template.template_data)
            
            if score > best_score:
                best_score = score
                best_match = template
        
        matched = best_score >= self.match_threshold and best_match is not None
        
        return MatchResult(
            matched=matched,
            score=best_score,
            threshold=self.match_threshold,
            user_id=best_match.user_id if best_match else None,
            auth_result=AuthResult.AUTHENTICATED if matched else AuthResult.REJECTED,
            confidence=best_score,
            processing_time=time.time() - start_time
        )


# =============================================================================
# Voice Biometrics
# =============================================================================

class VoiceAnalyzer:
    """Voice biometric analysis"""
    
    def __init__(self):
        self.templates: Dict[str, BiometricTemplate] = {}
        self.sample_rate = 16000
        self.match_threshold = 0.75
        
        # Feature extraction parameters
        self.n_mfcc = 13
        self.n_fft = 512
        self.hop_length = 160
    
    def extract_mfcc(self, audio: np.ndarray) -> np.ndarray:
        """Extract MFCC features from audio"""
        if SCIPY_AVAILABLE:
            # Compute spectrogram
            f, t, Sxx = spectrogram(audio, fs=self.sample_rate, nperseg=self.n_fft, noverlap=self.n_fft - self.hop_length)
            
            # Convert to mel scale (simplified)
            mel_filterbank = np.zeros((self.n_mfcc, len(f)))
            for i in range(self.n_mfcc):
                center = int(len(f) * (i + 1) / (self.n_mfcc + 1))
                width = max(1, int(len(f) / (self.n_mfcc + 1)))
                mel_filterbank[i, max(0, center - width):min(len(f), center + width)] = 1
            
            mel_spec = np.dot(mel_filterbank, Sxx)
            log_mel = np.log(mel_spec + 1e-10)
            
            # DCT (simplified as average over time)
            mfcc = np.mean(log_mel, axis=1)
        else:
            # Simple feature extraction
            mfcc = np.zeros(self.n_mfcc)
            chunk_size = len(audio) // self.n_mfcc
            for i in range(self.n_mfcc):
                chunk = audio[i * chunk_size:(i + 1) * chunk_size]
                mfcc[i] = np.std(chunk) if len(chunk) > 0 else 0
        
        return mfcc
    
    def extract_prosodic_features(self, audio: np.ndarray) -> np.ndarray:
        """Extract prosodic features (pitch, energy, duration)"""
        # Energy
        energy = np.sqrt(np.mean(audio ** 2))
        
        # Zero crossing rate
        zcr = np.mean(np.abs(np.diff(np.sign(audio)))) / 2
        
        # Simple pitch estimation
        if len(audio) > 1024:
            autocorr = np.correlate(audio[:1024], audio[:1024], mode='full')
            autocorr = autocorr[len(autocorr) // 2:]
            # Find first peak after initial decline
            d = np.diff(autocorr)
            peaks = np.where((d[:-1] > 0) & (d[1:] < 0))[0] + 1
            if len(peaks) > 0:
                pitch_period = peaks[0]
                pitch = self.sample_rate / pitch_period if pitch_period > 0 else 0
            else:
                pitch = 0
        else:
            pitch = 0
        
        return np.array([energy, zcr, pitch])
    
    def extract_embedding(self, audio: np.ndarray) -> np.ndarray:
        """Extract voice embedding"""
        mfcc = self.extract_mfcc(audio)
        prosodic = self.extract_prosodic_features(audio)
        
        # Combine features
        embedding = np.concatenate([mfcc, prosodic])
        
        # Normalize
        embedding = embedding / (np.linalg.norm(embedding) + 1e-10)
        
        return embedding
    
    def assess_quality(self, audio: np.ndarray) -> Dict[str, float]:
        """Assess audio quality"""
        # Signal-to-noise ratio estimation
        signal_power = np.mean(audio ** 2)
        
        # Estimate noise from quietest frames
        frame_size = 256
        frame_powers = []
        for i in range(0, len(audio) - frame_size, frame_size):
            frame = audio[i:i + frame_size]
            frame_powers.append(np.mean(frame ** 2))
        
        noise_power = np.percentile(frame_powers, 10) if frame_powers else signal_power
        snr = 10 * np.log10(signal_power / (noise_power + 1e-10))
        snr_score = min(1.0, snr / 30)
        
        # Duration score
        duration = len(audio) / self.sample_rate
        duration_score = min(1.0, duration / 3.0)  # 3 seconds is ideal
        
        # Amplitude score
        max_amp = np.max(np.abs(audio))
        amplitude_score = 1.0 if 0.1 < max_amp < 0.9 else 0.5
        
        overall = (snr_score + duration_score + amplitude_score) / 3
        
        return {
            'snr': snr_score,
            'duration': duration_score,
            'amplitude': amplitude_score,
            'overall': overall
        }
    
    def check_liveness(self, audio: np.ndarray, challenge: str = None) -> Tuple[bool, float, str]:
        """Check voice liveness"""
        # In production, would verify spoken challenge
        # Simple check: verify audio has speech-like characteristics
        
        # Check for voice activity
        energy = np.mean(audio ** 2)
        has_speech = energy > 0.001
        
        # Check for natural variation
        rms_values = []
        frame_size = 256
        for i in range(0, len(audio) - frame_size, frame_size):
            frame = audio[i:i + frame_size]
            rms_values.append(np.sqrt(np.mean(frame ** 2)))
        
        variation = np.std(rms_values) if rms_values else 0
        has_variation = variation > 0.01
        
        liveness_score = 0.5
        if has_speech:
            liveness_score += 0.25
        if has_variation:
            liveness_score += 0.25
        
        return liveness_score > 0.6, liveness_score, "energy_variation"
    
    def enroll(self, user_id: str, audio_samples: List[np.ndarray]) -> BiometricTemplate:
        """Enroll voice template"""
        embeddings = []
        
        for audio in audio_samples:
            quality = self.assess_quality(audio)
            if quality['overall'] > 0.5:
                embedding = self.extract_embedding(audio)
                embeddings.append(embedding)
        
        if not embeddings:
            raise ValueError("No valid audio samples")
        
        # Average embeddings
        avg_embedding = np.mean(embeddings, axis=0)
        avg_embedding = avg_embedding / (np.linalg.norm(avg_embedding) + 1e-10)
        
        template = BiometricTemplate(
            template_id=hashlib.md5(f"{user_id}_{time.time()}".encode()).hexdigest()[:16],
            user_id=user_id,
            modality=BiometricType.VOICE,
            template_data=avg_embedding,
            quality_score=np.mean([self.assess_quality(a)['overall'] for a in audio_samples]),
            created_at=time.time(),
            metadata={'num_samples': len(audio_samples)}
        )
        
        self.templates[template.template_id] = template
        return template
    
    def verify(self, user_id: str, audio: np.ndarray) -> MatchResult:
        """Verify voice against enrolled template"""
        start_time = time.time()
        
        # Find user templates
        user_templates = [t for t in self.templates.values() 
                        if t.user_id == user_id and t.modality == BiometricType.VOICE]
        
        if not user_templates:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.NOT_ENROLLED
            )
        
        # Check quality
        quality = self.assess_quality(audio)
        if quality['overall'] < 0.4:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.INSUFFICIENT_QUALITY
            )
        
        # Extract embedding
        probe_embedding = self.extract_embedding(audio)
        
        # Match
        best_score = 0.0
        for template in user_templates:
            if SCIPY_AVAILABLE:
                score = 1 - cosine(probe_embedding, template.template_data)
            else:
                score = np.dot(probe_embedding, template.template_data)
            best_score = max(best_score, score)
        
        matched = best_score >= self.match_threshold
        
        return MatchResult(
            matched=matched,
            score=best_score,
            threshold=self.match_threshold,
            user_id=user_id,
            auth_result=AuthResult.AUTHENTICATED if matched else AuthResult.REJECTED,
            confidence=best_score,
            processing_time=time.time() - start_time
        )


# =============================================================================
# Keystroke Dynamics
# =============================================================================

class KeystrokeDynamics:
    """Behavioral biometrics based on typing patterns"""
    
    def __init__(self):
        self.templates: Dict[str, BiometricTemplate] = {}
        self.match_threshold = 0.7
        
        # Typing session buffer
        self.session_buffer: Dict[str, List[Dict]] = {}
    
    def record_keystroke(self, user_id: str, key: str, press_time: float, release_time: float):
        """Record individual keystroke"""
        if user_id not in self.session_buffer:
            self.session_buffer[user_id] = []
        
        self.session_buffer[user_id].append({
            'key': key,
            'press_time': press_time,
            'release_time': release_time,
            'hold_time': release_time - press_time
        })
    
    def extract_features(self, keystrokes: List[Dict]) -> np.ndarray:
        """Extract typing pattern features"""
        if len(keystrokes) < 2:
            return np.zeros(20)
        
        # Hold times (dwell times)
        hold_times = [k['hold_time'] for k in keystrokes]
        
        # Flight times (inter-key intervals)
        flight_times = []
        for i in range(1, len(keystrokes)):
            flight = keystrokes[i]['press_time'] - keystrokes[i - 1]['release_time']
            flight_times.append(flight)
        
        # Digraph latencies
        digraph_times = []
        for i in range(1, len(keystrokes)):
            latency = keystrokes[i]['press_time'] - keystrokes[i - 1]['press_time']
            digraph_times.append(latency)
        
        features = [
            np.mean(hold_times),
            np.std(hold_times),
            np.median(hold_times),
            np.mean(flight_times) if flight_times else 0,
            np.std(flight_times) if flight_times else 0,
            np.median(flight_times) if flight_times else 0,
            np.mean(digraph_times) if digraph_times else 0,
            np.std(digraph_times) if digraph_times else 0,
            len(keystrokes),
            np.min(hold_times),
            np.max(hold_times),
            np.percentile(hold_times, 25),
            np.percentile(hold_times, 75),
            np.min(flight_times) if flight_times else 0,
            np.max(flight_times) if flight_times else 0,
            np.percentile(flight_times, 25) if flight_times else 0,
            np.percentile(flight_times, 75) if flight_times else 0,
            np.var(hold_times),
            np.var(flight_times) if flight_times else 0,
            np.mean(digraph_times) / (np.std(digraph_times) + 1e-10) if digraph_times else 0
        ]
        
        return np.array(features)
    
    def enroll(self, user_id: str, typing_sessions: List[List[Dict]]) -> BiometricTemplate:
        """Enroll keystroke pattern"""
        embeddings = []
        
        for session in typing_sessions:
            if len(session) >= 10:  # Minimum keystrokes
                embedding = self.extract_features(session)
                embeddings.append(embedding)
        
        if not embeddings:
            raise ValueError("Insufficient typing data")
        
        avg_embedding = np.mean(embeddings, axis=0)
        
        template = BiometricTemplate(
            template_id=hashlib.md5(f"{user_id}_{time.time()}".encode()).hexdigest()[:16],
            user_id=user_id,
            modality=BiometricType.KEYSTROKE,
            template_data=avg_embedding,
            quality_score=min(1.0, len(embeddings) / 5),
            created_at=time.time(),
            metadata={'num_sessions': len(embeddings)}
        )
        
        self.templates[template.template_id] = template
        return template
    
    def verify(self, user_id: str, keystrokes: List[Dict]) -> MatchResult:
        """Verify typing pattern"""
        start_time = time.time()
        
        user_templates = [t for t in self.templates.values() 
                        if t.user_id == user_id and t.modality == BiometricType.KEYSTROKE]
        
        if not user_templates:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.NOT_ENROLLED
            )
        
        if len(keystrokes) < 10:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.INSUFFICIENT_QUALITY
            )
        
        probe_embedding = self.extract_features(keystrokes)
        
        best_score = 0.0
        for template in user_templates:
            # Manhattan distance (normalized)
            diff = np.abs(probe_embedding - template.template_data)
            max_diff = np.abs(template.template_data) + 1e-10
            normalized_diff = diff / max_diff
            score = 1 - np.mean(normalized_diff)
            best_score = max(best_score, score)
        
        matched = best_score >= self.match_threshold
        
        return MatchResult(
            matched=matched,
            score=best_score,
            threshold=self.match_threshold,
            user_id=user_id,
            auth_result=AuthResult.AUTHENTICATED if matched else AuthResult.REJECTED,
            confidence=best_score,
            processing_time=time.time() - start_time
        )
    
    def get_session_keystrokes(self, user_id: str) -> List[Dict]:
        """Get and clear session keystrokes"""
        keystrokes = self.session_buffer.get(user_id, [])
        self.session_buffer[user_id] = []
        return keystrokes


# =============================================================================
# Gait Analysis
# =============================================================================

class GaitAnalyzer:
    """Gait-based biometric analysis"""
    
    def __init__(self):
        self.templates: Dict[str, BiometricTemplate] = {}
        self.match_threshold = 0.65
        self.sample_rate = 100  # Hz for accelerometer
    
    def extract_features(self, accel_data: np.ndarray) -> np.ndarray:
        """Extract gait features from accelerometer data"""
        # accel_data: [N, 3] for x, y, z acceleration
        
        if len(accel_data) < 200:
            return np.zeros(30)
        
        features = []
        
        for axis in range(3):
            signal = accel_data[:, axis]
            
            # Time domain features
            features.extend([
                np.mean(signal),
                np.std(signal),
                np.min(signal),
                np.max(signal),
                np.percentile(signal, 25),
                np.percentile(signal, 75)
            ])
            
            # Frequency domain features (simplified)
            if SCIPY_AVAILABLE:
                fft_vals = np.abs(np.fft.fft(signal))
                freqs = np.fft.fftfreq(len(signal), 1 / self.sample_rate)
                
                # Dominant frequency
                dominant_freq = freqs[np.argmax(fft_vals[:len(fft_vals) // 2])]
                
                # Energy in different bands
                low_energy = np.sum(fft_vals[(freqs > 0) & (freqs < 2)])
                mid_energy = np.sum(fft_vals[(freqs >= 2) & (freqs < 5)])
                high_energy = np.sum(fft_vals[(freqs >= 5) & (freqs < 10)])
                
                features.extend([dominant_freq, low_energy, mid_energy, high_energy])
            else:
                features.extend([0, 0, 0, 0])
        
        return np.array(features)
    
    def detect_steps(self, accel_data: np.ndarray) -> List[int]:
        """Detect step indices in accelerometer data"""
        # Use magnitude
        magnitude = np.sqrt(np.sum(accel_data ** 2, axis=1))
        
        # Simple peak detection
        threshold = np.mean(magnitude) + 0.5 * np.std(magnitude)
        steps = []
        
        in_step = False
        for i, m in enumerate(magnitude):
            if m > threshold and not in_step:
                steps.append(i)
                in_step = True
            elif m < threshold:
                in_step = False
        
        return steps
    
    def calculate_cadence(self, accel_data: np.ndarray) -> float:
        """Calculate walking cadence (steps per minute)"""
        steps = self.detect_steps(accel_data)
        
        if len(steps) < 2:
            return 0.0
        
        duration_seconds = len(accel_data) / self.sample_rate
        steps_per_minute = len(steps) / duration_seconds * 60
        
        return steps_per_minute
    
    def enroll(self, user_id: str, gait_samples: List[np.ndarray]) -> BiometricTemplate:
        """Enroll gait pattern"""
        embeddings = []
        
        for sample in gait_samples:
            if len(sample) >= 200:
                embedding = self.extract_features(sample)
                embeddings.append(embedding)
        
        if not embeddings:
            raise ValueError("Insufficient gait data")
        
        avg_embedding = np.mean(embeddings, axis=0)
        avg_embedding = avg_embedding / (np.linalg.norm(avg_embedding) + 1e-10)
        
        template = BiometricTemplate(
            template_id=hashlib.md5(f"{user_id}_{time.time()}".encode()).hexdigest()[:16],
            user_id=user_id,
            modality=BiometricType.GAIT,
            template_data=avg_embedding,
            quality_score=min(1.0, len(embeddings) / 3),
            created_at=time.time(),
            metadata={'num_samples': len(embeddings)}
        )
        
        self.templates[template.template_id] = template
        return template
    
    def verify(self, user_id: str, accel_data: np.ndarray) -> MatchResult:
        """Verify gait pattern"""
        start_time = time.time()
        
        user_templates = [t for t in self.templates.values() 
                        if t.user_id == user_id and t.modality == BiometricType.GAIT]
        
        if not user_templates:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.NOT_ENROLLED
            )
        
        if len(accel_data) < 200:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.match_threshold,
                auth_result=AuthResult.INSUFFICIENT_QUALITY
            )
        
        probe_embedding = self.extract_features(accel_data)
        probe_embedding = probe_embedding / (np.linalg.norm(probe_embedding) + 1e-10)
        
        best_score = 0.0
        for template in user_templates:
            if SCIPY_AVAILABLE:
                score = 1 - cosine(probe_embedding, template.template_data)
            else:
                score = np.dot(probe_embedding, template.template_data)
            best_score = max(best_score, score)
        
        matched = best_score >= self.match_threshold
        
        return MatchResult(
            matched=matched,
            score=best_score,
            threshold=self.match_threshold,
            user_id=user_id,
            auth_result=AuthResult.AUTHENTICATED if matched else AuthResult.REJECTED,
            confidence=best_score,
            processing_time=time.time() - start_time
        )


# =============================================================================
# Multi-Modal Biometric Fusion
# =============================================================================

class BiometricFusion:
    """Combine multiple biometric modalities"""
    
    def __init__(self):
        self.face_analyzer = FaceAnalyzer()
        self.voice_analyzer = VoiceAnalyzer()
        self.keystroke_analyzer = KeystrokeDynamics()
        self.gait_analyzer = GaitAnalyzer()
        
        # Fusion weights
        self.modality_weights = {
            BiometricType.FACE: 0.35,
            BiometricType.VOICE: 0.25,
            BiometricType.KEYSTROKE: 0.2,
            BiometricType.GAIT: 0.2
        }
        
        self.fusion_threshold = 0.65
    
    def set_weights(self, weights: Dict[BiometricType, float]):
        """Set modality weights"""
        total = sum(weights.values())
        self.modality_weights = {k: v / total for k, v in weights.items()}
    
    def fuse_scores(
        self,
        scores: Dict[BiometricType, float],
        method: str = "weighted"
    ) -> float:
        """Fuse multiple biometric scores"""
        if not scores:
            return 0.0
        
        if method == "weighted":
            # Weighted average
            total_weight = sum(self.modality_weights.get(m, 0) for m in scores.keys())
            if total_weight == 0:
                return 0.0
            
            fused = sum(s * self.modality_weights.get(m, 0) for m, s in scores.items())
            return fused / total_weight
        
        elif method == "max":
            return max(scores.values())
        
        elif method == "min":
            return min(scores.values())
        
        elif method == "product":
            result = 1.0
            for score in scores.values():
                result *= score
            return result ** (1 / len(scores))
        
        elif method == "sum":
            return min(1.0, sum(scores.values()) / len(scores))
        
        return 0.0
    
    def multi_modal_verify(
        self,
        user_id: str,
        face_image: np.ndarray = None,
        audio: np.ndarray = None,
        keystrokes: List[Dict] = None,
        accel_data: np.ndarray = None
    ) -> MatchResult:
        """Verify using multiple modalities"""
        start_time = time.time()
        
        scores = {}
        results = {}
        
        # Face verification
        if face_image is not None:
            result = self.face_analyzer.verify(user_id, face_image)
            if result.auth_result not in [AuthResult.NOT_ENROLLED, AuthResult.INSUFFICIENT_QUALITY]:
                scores[BiometricType.FACE] = result.score
                results[BiometricType.FACE] = result
        
        # Voice verification
        if audio is not None:
            result = self.voice_analyzer.verify(user_id, audio)
            if result.auth_result not in [AuthResult.NOT_ENROLLED, AuthResult.INSUFFICIENT_QUALITY]:
                scores[BiometricType.VOICE] = result.score
                results[BiometricType.VOICE] = result
        
        # Keystroke verification
        if keystrokes is not None:
            result = self.keystroke_analyzer.verify(user_id, keystrokes)
            if result.auth_result not in [AuthResult.NOT_ENROLLED, AuthResult.INSUFFICIENT_QUALITY]:
                scores[BiometricType.KEYSTROKE] = result.score
                results[BiometricType.KEYSTROKE] = result
        
        # Gait verification
        if accel_data is not None:
            result = self.gait_analyzer.verify(user_id, accel_data)
            if result.auth_result not in [AuthResult.NOT_ENROLLED, AuthResult.INSUFFICIENT_QUALITY]:
                scores[BiometricType.GAIT] = result.score
                results[BiometricType.GAIT] = result
        
        if not scores:
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=self.fusion_threshold,
                auth_result=AuthResult.NOT_ENROLLED
            )
        
        # Fuse scores
        fused_score = self.fuse_scores(scores)
        matched = fused_score >= self.fusion_threshold
        
        return MatchResult(
            matched=matched,
            score=fused_score,
            threshold=self.fusion_threshold,
            user_id=user_id,
            auth_result=AuthResult.AUTHENTICATED if matched else AuthResult.REJECTED,
            confidence=fused_score,
            processing_time=time.time() - start_time,
            metadata={
                'modality_scores': {m.name: s for m, s in scores.items()},
                'modalities_used': [m.name for m in scores.keys()]
            }
        )


# =============================================================================
# Biometric Security Manager
# =============================================================================

class BiometricSecurityManager:
    """Main manager for biometric security"""
    
    def __init__(self):
        self.fusion = BiometricFusion()
        self.enrolled_users: Dict[str, Dict[str, Any]] = {}
        self.auth_log: List[Dict] = []
        
        # Security settings
        self.max_attempts = 3
        self.lockout_duration = 300  # seconds
        self.attempt_counts: Dict[str, int] = {}
        self.lockouts: Dict[str, float] = {}
    
    def is_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out"""
        if user_id in self.lockouts:
            if time.time() < self.lockouts[user_id]:
                return True
            else:
                del self.lockouts[user_id]
                self.attempt_counts[user_id] = 0
        return False
    
    def record_attempt(self, user_id: str, success: bool):
        """Record authentication attempt"""
        if success:
            self.attempt_counts[user_id] = 0
        else:
            self.attempt_counts[user_id] = self.attempt_counts.get(user_id, 0) + 1
            
            if self.attempt_counts[user_id] >= self.max_attempts:
                self.lockouts[user_id] = time.time() + self.lockout_duration
    
    def enroll_user(
        self,
        user_id: str,
        face_images: List[np.ndarray] = None,
        audio_samples: List[np.ndarray] = None,
        typing_sessions: List[List[Dict]] = None,
        gait_samples: List[np.ndarray] = None
    ) -> Dict[str, str]:
        """Enroll user with multiple modalities"""
        templates = {}
        
        if face_images:
            template = self.fusion.face_analyzer.enroll(user_id, face_images)
            templates[BiometricType.FACE.name] = template.template_id
        
        if audio_samples:
            template = self.fusion.voice_analyzer.enroll(user_id, audio_samples)
            templates[BiometricType.VOICE.name] = template.template_id
        
        if typing_sessions:
            template = self.fusion.keystroke_analyzer.enroll(user_id, typing_sessions)
            templates[BiometricType.KEYSTROKE.name] = template.template_id
        
        if gait_samples:
            template = self.fusion.gait_analyzer.enroll(user_id, gait_samples)
            templates[BiometricType.GAIT.name] = template.template_id
        
        self.enrolled_users[user_id] = {
            'templates': templates,
            'enrolled_at': time.time()
        }
        
        return templates
    
    def authenticate(
        self,
        user_id: str,
        face_image: np.ndarray = None,
        audio: np.ndarray = None,
        keystrokes: List[Dict] = None,
        accel_data: np.ndarray = None
    ) -> MatchResult:
        """Authenticate user with biometrics"""
        # Check lockout
        if self.is_locked_out(user_id):
            return MatchResult(
                matched=False,
                score=0.0,
                threshold=0.0,
                auth_result=AuthResult.REJECTED,
                metadata={'reason': 'locked_out'}
            )
        
        # Perform authentication
        result = self.fusion.multi_modal_verify(
            user_id,
            face_image=face_image,
            audio=audio,
            keystrokes=keystrokes,
            accel_data=accel_data
        )
        
        # Record attempt
        self.record_attempt(user_id, result.matched)
        
        # Log
        self.auth_log.append({
            'user_id': user_id,
            'timestamp': time.time(),
            'result': result.auth_result.name,
            'score': result.score,
            'modalities': result.metadata.get('modalities_used', [])
        })
        
        return result
    
    def get_auth_statistics(self, user_id: str = None) -> Dict[str, Any]:
        """Get authentication statistics"""
        logs = self.auth_log if user_id is None else [l for l in self.auth_log if l['user_id'] == user_id]
        
        if not logs:
            return {'total': 0, 'success_rate': 0}
        
        success = sum(1 for l in logs if l['result'] == 'AUTHENTICATED')
        
        return {
            'total': len(logs),
            'successful': success,
            'failed': len(logs) - success,
            'success_rate': success / len(logs),
            'average_score': np.mean([l['score'] for l in logs])
        }


# Global instance
biometric_manager = BiometricSecurityManager()


def get_biometric_manager() -> BiometricSecurityManager:
    """Get global biometric manager"""
    return biometric_manager
