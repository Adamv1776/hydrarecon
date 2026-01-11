"""
Hydra Advanced Sensing Integration
==================================

INTEGRATION LAYER FOR ALL ADVANCED WIFI SENSING MODULES

This module provides seamless integration between the Hydra Tomographic Scanner
and all advanced WiFi sensing capabilities:

1. WiFi Vital Signs - Heart rate, respiration monitoring
2. Gesture Recognition - Doppler-based gesture detection  
3. Gait Identification - Biometric person identification
4. Predictive Movement - ML-based trajectory prediction
5. Material Tomography - Material identification
6. Acoustic Inference - Sound detection via WiFi
7. Neural CSI Processor - Deep learning feature extraction
8. Quantum Localization - Ultra-precise positioning
9. Anomaly Detection - Multi-modal anomaly detection
10. Environmental Digital Twin - 3D environment modeling

Features:
- Automatic module initialization and configuration
- Unified data pipeline from ESP32 sensors
- Cross-module data sharing
- Performance optimization
- Graceful degradation when modules unavailable
- Comprehensive logging and statistics

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from collections import deque
from enum import Enum
import threading
import time
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HydraIntegration")


# ============================================================================
# Import Advanced Modules
# ============================================================================

# Safe imports with fallbacks
def safe_import(module_name: str, class_name: str):
    """Safely import a class from a module."""
    try:
        module = __import__(f"core.{module_name}", fromlist=[class_name])
        return getattr(module, class_name)
    except ImportError as e:
        logger.warning(f"Could not import {class_name} from {module_name}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error importing {class_name}: {e}")
        return None


# Import all advanced modules
VitalSignsProcessor = safe_import("wifi_vital_signs", "VitalSignsProcessor")
MultiPersonVitalMonitor = safe_import("wifi_vital_signs", "MultiPersonVitalMonitor")
GestureRecognitionEngine = safe_import("wifi_gesture_recognition", "GestureRecognitionEngine")
GaitIdentificationSystem = safe_import("wifi_gait_identification", "GaitIdentificationSystem")
MovementPredictionEngine = safe_import("wifi_predictive_movement", "MovementPredictionEngine")
MaterialTomographyEngine = safe_import("wifi_material_tomography", "MaterialTomographyEngine")
AcousticInferenceEngine = safe_import("wifi_acoustic_inference", "AcousticInferenceEngine")
NeuralCSIProcessor = safe_import("neural_csi_processor", "NeuralCSIProcessor")
QuantumLocalizationEngine = safe_import("quantum_localization", "QuantumLocalizationEngine")
AnomalyDetectionSystem = safe_import("anomaly_detection", "AnomalyDetectionSystem")
EnvironmentalDigitalTwin = safe_import("environmental_digital_twin", "EnvironmentalDigitalTwin")
WifiSensingOrchestrator = safe_import("wifi_sensing_orchestrator", "WifiSensingOrchestrator")


# ============================================================================
# Integration Data Types
# ============================================================================

class IntegrationMode(Enum):
    """Operating modes for the integration layer."""
    MINIMAL = "minimal"  # Basic operation only
    STANDARD = "standard"  # Standard features
    ADVANCED = "advanced"  # All advanced features
    RESEARCH = "research"  # Full research mode with all modules
    CUSTOM = "custom"  # Custom configuration


@dataclass
class ModuleStatus:
    """Status of an individual module."""
    name: str
    enabled: bool = False
    loaded: bool = False
    healthy: bool = False
    last_update: float = 0.0
    error_count: int = 0
    process_time_ms: float = 0.0
    memory_mb: float = 0.0


@dataclass
class IntegrationConfig:
    """Configuration for the integration layer."""
    mode: IntegrationMode = IntegrationMode.STANDARD
    
    # Module enables
    enable_vital_signs: bool = True
    enable_gesture_recognition: bool = True
    enable_gait_identification: bool = True
    enable_predictive_movement: bool = True
    enable_material_tomography: bool = False  # Computationally expensive
    enable_acoustic_inference: bool = False  # Requires specific conditions
    enable_neural_processor: bool = True
    enable_quantum_localization: bool = True
    enable_anomaly_detection: bool = True
    enable_digital_twin: bool = True
    
    # Performance settings
    max_processing_time_ms: float = 100.0
    thread_count: int = 4
    buffer_size: int = 1000
    
    # Data settings
    num_subcarriers: int = 52
    sample_rate: float = 100.0  # Hz
    
    # Room dimensions
    room_bounds: np.ndarray = field(default_factory=lambda: np.array([
        [0, 10], [0, 10], [0, 3]
    ]))


@dataclass
class SensorReading:
    """Single sensor reading from ESP32."""
    timestamp: float
    sensor_id: str
    rssi: int
    csi_amplitude: np.ndarray
    csi_phase: np.ndarray
    device_mac: Optional[str] = None
    position: Optional[np.ndarray] = None


@dataclass
class IntegrationResult:
    """Results from the integration layer."""
    timestamp: float
    
    # Localization
    estimated_position: Optional[np.ndarray] = None
    position_uncertainty: float = 0.0
    
    # Vital signs
    heart_rate: Optional[float] = None
    respiration_rate: Optional[float] = None
    
    # Gesture
    detected_gesture: Optional[str] = None
    gesture_confidence: float = 0.0
    
    # Identification
    identified_person: Optional[str] = None
    identification_confidence: float = 0.0
    
    # Movement
    predicted_trajectory: Optional[np.ndarray] = None
    movement_intent: Optional[str] = None
    
    # Environment
    detected_materials: Dict[str, float] = field(default_factory=dict)
    acoustic_events: List[str] = field(default_factory=list)
    
    # Anomalies
    anomaly_score: float = 0.0
    anomalies: List[Dict] = field(default_factory=list)
    
    # Neural features
    neural_features: Optional[np.ndarray] = None
    
    # Processing info
    processing_time_ms: float = 0.0
    modules_used: List[str] = field(default_factory=list)


# ============================================================================
# Main Integration Class
# ============================================================================

class HydraAdvancedIntegration:
    """
    Main integration layer for all advanced WiFi sensing modules.
    
    Provides unified interface for the Hydra Tomographic Scanner
    to access all cutting-edge sensing capabilities.
    """
    
    def __init__(self, config: IntegrationConfig = None):
        if config is None:
            config = IntegrationConfig()
        self.config = config
        
        # Module instances
        self._modules: Dict[str, Any] = {}
        self._module_status: Dict[str, ModuleStatus] = {}
        
        # Data buffers
        self._csi_buffer = deque(maxlen=config.buffer_size)
        self._result_history = deque(maxlen=1000)
        
        # Threading
        self._lock = threading.RLock()
        self._running = False
        
        # Statistics
        self._stats = {
            'total_samples': 0,
            'total_results': 0,
            'avg_processing_time_ms': 0.0,
            'errors': 0,
        }
        
        # Callbacks
        self._callbacks: Dict[str, List[Callable]] = {
            'on_result': [],
            'on_anomaly': [],
            'on_gesture': [],
            'on_person_identified': [],
        }
        
        # Initialize modules based on mode
        self._initialize_modules()
    
    def _initialize_modules(self):
        """Initialize all enabled modules."""
        logger.info(f"Initializing Hydra Advanced Integration (mode: {self.config.mode.value})")
        
        # Set up based on mode
        if self.config.mode == IntegrationMode.MINIMAL:
            self._enable_minimal_modules()
        elif self.config.mode == IntegrationMode.STANDARD:
            self._enable_standard_modules()
        elif self.config.mode == IntegrationMode.ADVANCED:
            self._enable_advanced_modules()
        elif self.config.mode == IntegrationMode.RESEARCH:
            self._enable_all_modules()
        
        # Initialize each enabled module
        self._init_vital_signs()
        self._init_gesture_recognition()
        self._init_gait_identification()
        self._init_predictive_movement()
        self._init_material_tomography()
        self._init_acoustic_inference()
        self._init_neural_processor()
        self._init_quantum_localization()
        self._init_anomaly_detection()
        self._init_digital_twin()
        
        # Initialize orchestrator if available
        self._init_orchestrator()
        
        enabled = sum(1 for s in self._module_status.values() if s.enabled and s.loaded)
        logger.info(f"Initialized {enabled} advanced modules")
    
    def _enable_minimal_modules(self):
        """Enable minimal set of modules."""
        self.config.enable_vital_signs = False
        self.config.enable_gesture_recognition = False
        self.config.enable_gait_identification = False
        self.config.enable_predictive_movement = False
        self.config.enable_material_tomography = False
        self.config.enable_acoustic_inference = False
        self.config.enable_neural_processor = False
        self.config.enable_quantum_localization = True
        self.config.enable_anomaly_detection = True
        self.config.enable_digital_twin = False
    
    def _enable_standard_modules(self):
        """Enable standard set of modules."""
        self.config.enable_vital_signs = True
        self.config.enable_gesture_recognition = True
        self.config.enable_gait_identification = False
        self.config.enable_predictive_movement = True
        self.config.enable_material_tomography = False
        self.config.enable_acoustic_inference = False
        self.config.enable_neural_processor = True
        self.config.enable_quantum_localization = True
        self.config.enable_anomaly_detection = True
        self.config.enable_digital_twin = True
    
    def _enable_advanced_modules(self):
        """Enable advanced set of modules."""
        self.config.enable_vital_signs = True
        self.config.enable_gesture_recognition = True
        self.config.enable_gait_identification = True
        self.config.enable_predictive_movement = True
        self.config.enable_material_tomography = True
        self.config.enable_acoustic_inference = False
        self.config.enable_neural_processor = True
        self.config.enable_quantum_localization = True
        self.config.enable_anomaly_detection = True
        self.config.enable_digital_twin = True
    
    def _enable_all_modules(self):
        """Enable all modules for research mode."""
        self.config.enable_vital_signs = True
        self.config.enable_gesture_recognition = True
        self.config.enable_gait_identification = True
        self.config.enable_predictive_movement = True
        self.config.enable_material_tomography = True
        self.config.enable_acoustic_inference = True
        self.config.enable_neural_processor = True
        self.config.enable_quantum_localization = True
        self.config.enable_anomaly_detection = True
        self.config.enable_digital_twin = True
    
    def _init_vital_signs(self):
        """Initialize vital signs module."""
        status = ModuleStatus(name="vital_signs")
        
        if self.config.enable_vital_signs and VitalSignsProcessor:
            try:
                self._modules['vital_signs'] = VitalSignsProcessor(
                    num_subcarriers=self.config.num_subcarriers,
                    sample_rate=self.config.sample_rate
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Vital Signs Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Vital Signs Module failed: {e}")
                status.error_count = 1
        
        self._module_status['vital_signs'] = status
    
    def _init_gesture_recognition(self):
        """Initialize gesture recognition module."""
        status = ModuleStatus(name="gesture_recognition")
        
        if self.config.enable_gesture_recognition and GestureRecognitionEngine:
            try:
                self._modules['gesture_recognition'] = GestureRecognitionEngine(
                    sample_rate=self.config.sample_rate
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Gesture Recognition Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Gesture Recognition Module failed: {e}")
                status.error_count = 1
        
        self._module_status['gesture_recognition'] = status
    
    def _init_gait_identification(self):
        """Initialize gait identification module."""
        status = ModuleStatus(name="gait_identification")
        
        if self.config.enable_gait_identification and GaitIdentificationSystem:
            try:
                self._modules['gait_identification'] = GaitIdentificationSystem(
                    sample_rate=self.config.sample_rate
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Gait Identification Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Gait Identification Module failed: {e}")
                status.error_count = 1
        
        self._module_status['gait_identification'] = status
    
    def _init_predictive_movement(self):
        """Initialize predictive movement module."""
        status = ModuleStatus(name="predictive_movement")
        
        if self.config.enable_predictive_movement and MovementPredictionEngine:
            try:
                self._modules['predictive_movement'] = MovementPredictionEngine()
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Predictive Movement Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Predictive Movement Module failed: {e}")
                status.error_count = 1
        
        self._module_status['predictive_movement'] = status
    
    def _init_material_tomography(self):
        """Initialize material tomography module."""
        status = ModuleStatus(name="material_tomography")
        
        if self.config.enable_material_tomography and MaterialTomographyEngine:
            try:
                self._modules['material_tomography'] = MaterialTomographyEngine(
                    room_bounds=self.config.room_bounds
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Material Tomography Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Material Tomography Module failed: {e}")
                status.error_count = 1
        
        self._module_status['material_tomography'] = status
    
    def _init_acoustic_inference(self):
        """Initialize acoustic inference module."""
        status = ModuleStatus(name="acoustic_inference")
        
        if self.config.enable_acoustic_inference and AcousticInferenceEngine:
            try:
                self._modules['acoustic_inference'] = AcousticInferenceEngine(
                    sample_rate=self.config.sample_rate
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Acoustic Inference Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Acoustic Inference Module failed: {e}")
                status.error_count = 1
        
        self._module_status['acoustic_inference'] = status
    
    def _init_neural_processor(self):
        """Initialize neural CSI processor module."""
        status = ModuleStatus(name="neural_processor")
        
        if self.config.enable_neural_processor and NeuralCSIProcessor:
            try:
                self._modules['neural_processor'] = NeuralCSIProcessor(
                    num_subcarriers=self.config.num_subcarriers,
                    seq_len=100
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Neural CSI Processor loaded")
            except Exception as e:
                logger.error(f"  ✗ Neural CSI Processor failed: {e}")
                status.error_count = 1
        
        self._module_status['neural_processor'] = status
    
    def _init_quantum_localization(self):
        """Initialize quantum localization module."""
        status = ModuleStatus(name="quantum_localization")
        
        if self.config.enable_quantum_localization and QuantumLocalizationEngine:
            try:
                self._modules['quantum_localization'] = QuantumLocalizationEngine(
                    bounds=self.config.room_bounds,
                    feature_size=self.config.num_subcarriers
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Quantum Localization Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Quantum Localization Module failed: {e}")
                status.error_count = 1
        
        self._module_status['quantum_localization'] = status
    
    def _init_anomaly_detection(self):
        """Initialize anomaly detection module."""
        status = ModuleStatus(name="anomaly_detection")
        
        if self.config.enable_anomaly_detection and AnomalyDetectionSystem:
            try:
                self._modules['anomaly_detection'] = AnomalyDetectionSystem(
                    feature_size=self.config.num_subcarriers
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Anomaly Detection Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Anomaly Detection Module failed: {e}")
                status.error_count = 1
        
        self._module_status['anomaly_detection'] = status
    
    def _init_digital_twin(self):
        """Initialize digital twin module."""
        status = ModuleStatus(name="digital_twin")
        
        if self.config.enable_digital_twin and EnvironmentalDigitalTwin:
            try:
                bounds_3d = np.array([
                    [self.config.room_bounds[0, 0], self.config.room_bounds[1, 0], 0],
                    [self.config.room_bounds[0, 1], self.config.room_bounds[1, 1], self.config.room_bounds[2, 1]],
                ])
                self._modules['digital_twin'] = EnvironmentalDigitalTwin(
                    bounds=bounds_3d
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Digital Twin Module loaded")
            except Exception as e:
                logger.error(f"  ✗ Digital Twin Module failed: {e}")
                status.error_count = 1
        
        self._module_status['digital_twin'] = status
    
    def _init_orchestrator(self):
        """Initialize orchestrator if available."""
        status = ModuleStatus(name="orchestrator")
        
        if WifiSensingOrchestrator:
            try:
                self._modules['orchestrator'] = WifiSensingOrchestrator(
                    num_subcarriers=self.config.num_subcarriers
                )
                status.enabled = True
                status.loaded = True
                status.healthy = True
                logger.info("  ✓ Sensing Orchestrator loaded")
            except Exception as e:
                logger.error(f"  ✗ Sensing Orchestrator failed: {e}")
        
        self._module_status['orchestrator'] = status
    
    def process_reading(self, reading: SensorReading) -> IntegrationResult:
        """
        Process a single sensor reading through all enabled modules.
        
        Args:
            reading: SensorReading from ESP32
        
        Returns:
            IntegrationResult with all detected information
        """
        start_time = time.time()
        result = IntegrationResult(timestamp=reading.timestamp)
        
        with self._lock:
            self._stats['total_samples'] += 1
            
            # Combine amplitude and phase into complex CSI
            csi_complex = reading.csi_amplitude * np.exp(1j * reading.csi_phase)
            self._csi_buffer.append({
                'timestamp': reading.timestamp,
                'csi': csi_complex,
                'rssi': reading.rssi,
            })
            
            try:
                # Process through each module
                result = self._process_all_modules(reading, csi_complex, result)
                
            except Exception as e:
                logger.error(f"Error processing reading: {e}")
                self._stats['errors'] += 1
            
            # Calculate processing time
            result.processing_time_ms = (time.time() - start_time) * 1000
            
            # Update statistics
            self._update_stats(result)
            
            # Store result
            self._result_history.append(result)
            
            # Fire callbacks
            self._fire_callbacks(result)
        
        return result
    
    def _process_all_modules(self, reading: SensorReading, 
                            csi_complex: np.ndarray,
                            result: IntegrationResult) -> IntegrationResult:
        """Process through all enabled modules."""
        
        # Neural processor (feature extraction first)
        if 'neural_processor' in self._modules:
            try:
                neural_result = self._modules['neural_processor'].add_frame(
                    np.abs(csi_complex)
                )
                if neural_result:
                    result.neural_features = neural_result.features
                    result.modules_used.append('neural_processor')
            except Exception as e:
                self._handle_module_error('neural_processor', e)
        
        # Quantum localization
        if 'quantum_localization' in self._modules:
            try:
                loc_result = self._modules['quantum_localization'].update(
                    np.abs(csi_complex),
                    reading.position
                )
                result.estimated_position = loc_result.position
                result.position_uncertainty = loc_result.uncertainty
                result.modules_used.append('quantum_localization')
            except Exception as e:
                self._handle_module_error('quantum_localization', e)
        
        # Vital signs
        if 'vital_signs' in self._modules:
            try:
                vital_result = self._modules['vital_signs'].process_csi_frame(csi_complex)
                if vital_result:
                    result.heart_rate = vital_result.heart_rate
                    result.respiration_rate = vital_result.respiration_rate
                    result.modules_used.append('vital_signs')
            except Exception as e:
                self._handle_module_error('vital_signs', e)
        
        # Gesture recognition
        if 'gesture_recognition' in self._modules:
            try:
                gesture_result = self._modules['gesture_recognition'].process_csi_frame(csi_complex)
                if gesture_result and gesture_result.gesture:
                    result.detected_gesture = gesture_result.gesture
                    result.gesture_confidence = gesture_result.confidence
                    result.modules_used.append('gesture_recognition')
            except Exception as e:
                self._handle_module_error('gesture_recognition', e)
        
        # Gait identification
        if 'gait_identification' in self._modules and result.estimated_position is not None:
            try:
                gait_result = self._modules['gait_identification'].process_frame(
                    csi_complex, result.estimated_position
                )
                if gait_result and gait_result.person_id:
                    result.identified_person = gait_result.person_id
                    result.identification_confidence = gait_result.confidence
                    result.modules_used.append('gait_identification')
            except Exception as e:
                self._handle_module_error('gait_identification', e)
        
        # Predictive movement
        if 'predictive_movement' in self._modules and result.estimated_position is not None:
            try:
                pred_result = self._modules['predictive_movement'].predict(
                    result.estimated_position
                )
                if pred_result:
                    result.predicted_trajectory = pred_result.trajectory
                    result.movement_intent = pred_result.intent
                    result.modules_used.append('predictive_movement')
            except Exception as e:
                self._handle_module_error('predictive_movement', e)
        
        # Material tomography
        if 'material_tomography' in self._modules:
            try:
                mat_result = self._modules['material_tomography'].process_measurement(
                    csi_complex, reading.rssi
                )
                if mat_result:
                    result.detected_materials = mat_result.materials
                    result.modules_used.append('material_tomography')
            except Exception as e:
                self._handle_module_error('material_tomography', e)
        
        # Acoustic inference
        if 'acoustic_inference' in self._modules:
            try:
                acoustic_result = self._modules['acoustic_inference'].process_csi_frame(csi_complex)
                if acoustic_result and acoustic_result.events:
                    result.acoustic_events = [e.event_type for e in acoustic_result.events]
                    result.modules_used.append('acoustic_inference')
            except Exception as e:
                self._handle_module_error('acoustic_inference', e)
        
        # Anomaly detection
        if 'anomaly_detection' in self._modules:
            try:
                anomaly_report = self._modules['anomaly_detection'].process(
                    np.abs(csi_complex),
                    reading.device_mac,
                    result.estimated_position
                )
                result.anomaly_score = anomaly_report.overall_score
                result.anomalies = [a.to_dict() for a in anomaly_report.anomalies]
                result.modules_used.append('anomaly_detection')
            except Exception as e:
                self._handle_module_error('anomaly_detection', e)
        
        # Digital twin
        if 'digital_twin' in self._modules:
            try:
                twin = self._modules['digital_twin']
                twin.update_from_csi(
                    csi_complex,
                    tx_position=np.array([0, 0, 1]),  # Primary sensor
                    rx_position=np.array([5, 0, 1]),  # Remote sensor
                )
                
                if result.estimated_position is not None:
                    twin.update_person(
                        reading.device_mac or "unknown",
                        result.estimated_position
                    )
                result.modules_used.append('digital_twin')
            except Exception as e:
                self._handle_module_error('digital_twin', e)
        
        return result
    
    def _handle_module_error(self, module_name: str, error: Exception):
        """Handle module error."""
        if module_name in self._module_status:
            self._module_status[module_name].error_count += 1
            
            # Disable module if too many errors
            if self._module_status[module_name].error_count > 10:
                self._module_status[module_name].healthy = False
                logger.warning(f"Module {module_name} disabled due to errors")
    
    def _update_stats(self, result: IntegrationResult):
        """Update processing statistics."""
        self._stats['total_results'] += 1
        
        # Rolling average of processing time
        alpha = 0.1
        self._stats['avg_processing_time_ms'] = (
            alpha * result.processing_time_ms +
            (1 - alpha) * self._stats['avg_processing_time_ms']
        )
    
    def _fire_callbacks(self, result: IntegrationResult):
        """Fire registered callbacks."""
        for callback in self._callbacks.get('on_result', []):
            try:
                callback(result)
            except Exception:
                pass
        
        if result.anomaly_score > 0.5:
            for callback in self._callbacks.get('on_anomaly', []):
                try:
                    callback(result)
                except Exception:
                    pass
        
        if result.detected_gesture:
            for callback in self._callbacks.get('on_gesture', []):
                try:
                    callback(result)
                except Exception:
                    pass
        
        if result.identified_person:
            for callback in self._callbacks.get('on_person_identified', []):
                try:
                    callback(result)
                except Exception:
                    pass
    
    def register_callback(self, event: str, callback: Callable):
        """Register callback for events."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def get_module_status(self) -> Dict[str, Dict]:
        """Get status of all modules."""
        return {
            name: {
                'enabled': status.enabled,
                'loaded': status.loaded,
                'healthy': status.healthy,
                'error_count': status.error_count,
                'last_update': status.last_update,
            }
            for name, status in self._module_status.items()
        }
    
    def get_statistics(self) -> Dict:
        """Get processing statistics."""
        return {
            **self._stats,
            'modules': self.get_module_status(),
            'buffer_size': len(self._csi_buffer),
            'result_history_size': len(self._result_history),
        }
    
    def get_digital_twin(self) -> Optional[Any]:
        """Get digital twin instance."""
        return self._modules.get('digital_twin')
    
    def calibrate(self, position: np.ndarray, csi_data: np.ndarray):
        """Add calibration point for localization."""
        if 'quantum_localization' in self._modules:
            self._modules['quantum_localization'].calibrate(position, csi_data)
    
    def train_neural_processor(self, data: np.ndarray, epochs: int = 50):
        """Train the neural processor."""
        if 'neural_processor' in self._modules:
            self._modules['neural_processor'].train(data, epochs=epochs)
    
    def enroll_person(self, person_id: str, name: str):
        """Enroll a person for gait identification."""
        if 'gait_identification' in self._modules:
            self._modules['gait_identification'].enroll_person(person_id, name)
    
    def save_models(self, path: str):
        """Save all model data."""
        import os
        os.makedirs(path, exist_ok=True)
        
        if 'neural_processor' in self._modules:
            self._modules['neural_processor'].save(f"{path}/neural")
        
        if 'quantum_localization' in self._modules:
            self._modules['quantum_localization'].fingerprint_db.save(f"{path}/fingerprints.json")
        
        if 'digital_twin' in self._modules:
            self._modules['digital_twin'].save(f"{path}/digital_twin.gz")
    
    def load_models(self, path: str):
        """Load all model data."""
        try:
            if 'neural_processor' in self._modules:
                self._modules['neural_processor'].load(f"{path}/neural")
            
            if 'quantum_localization' in self._modules:
                self._modules['quantum_localization'].fingerprint_db.load(f"{path}/fingerprints.json")
        except Exception as e:
            logger.error(f"Error loading models: {e}")


# ============================================================================
# Helper function for easy integration with TomographicEngine
# ============================================================================

def create_hydra_integration(mode: str = "standard", 
                            room_bounds: np.ndarray = None) -> HydraAdvancedIntegration:
    """
    Create a HydraAdvancedIntegration instance for the TomographicEngine.
    
    Args:
        mode: One of "minimal", "standard", "advanced", "research"
        room_bounds: Room bounds [[x_min, x_max], [y_min, y_max], [z_min, z_max]]
    
    Returns:
        Configured HydraAdvancedIntegration instance
    """
    config = IntegrationConfig(
        mode=IntegrationMode(mode)
    )
    
    if room_bounds is not None:
        config.room_bounds = room_bounds
    
    return HydraAdvancedIntegration(config)


# Standalone testing
if __name__ == "__main__":
    print("=== Hydra Advanced Integration Test ===\n")
    
    # Create integration in research mode
    integration = create_hydra_integration("research")
    
    # Print module status
    print("\n--- Module Status ---")
    status = integration.get_module_status()
    for name, info in status.items():
        enabled = "✓" if info['enabled'] and info['loaded'] else "✗"
        healthy = "healthy" if info['healthy'] else "unhealthy"
        print(f"  {enabled} {name}: {healthy}, errors={info['error_count']}")
    
    # Generate test reading
    np.random.seed(42)
    
    reading = SensorReading(
        timestamp=time.time(),
        sensor_id="ESP32_001",
        rssi=-45,
        csi_amplitude=np.random.rand(52) + 0.5,
        csi_phase=np.random.rand(52) * 2 * np.pi - np.pi,
        device_mac="AA:BB:CC:DD:EE:FF",
    )
    
    # Process
    print("\n--- Processing Test Reading ---")
    result = integration.process_reading(reading)
    
    print(f"Processing time: {result.processing_time_ms:.2f} ms")
    print(f"Modules used: {', '.join(result.modules_used)}")
    
    if result.estimated_position is not None:
        print(f"Estimated position: {result.estimated_position}")
        print(f"Position uncertainty: {result.position_uncertainty:.3f} m")
    
    if result.heart_rate:
        print(f"Heart rate: {result.heart_rate:.1f} bpm")
    
    if result.detected_gesture:
        print(f"Gesture: {result.detected_gesture} ({result.gesture_confidence:.2f})")
    
    if result.anomalies:
        print(f"Anomalies: {len(result.anomalies)}")
    
    # Statistics
    print("\n--- Statistics ---")
    stats = integration.get_statistics()
    print(f"Total samples: {stats['total_samples']}")
    print(f"Total results: {stats['total_results']}")
    print(f"Avg processing time: {stats['avg_processing_time_ms']:.2f} ms")
