"""
WiFi Sensing Orchestrator - Unified Multi-Modal Sensing Platform
================================================================

MASTER ORCHESTRATION LAYER FOR ALL WIFI SENSING CAPABILITIES

Combines all sensing modules into a unified, real-time platform:
1. Vital Signs Monitoring
2. Gesture Recognition
3. Gait-Based Person Identification
4. Predictive Movement AI
5. Material Tomography
6. Acoustic Inference

Features:
- Unified CSI data distribution pipeline
- Cross-modal sensor fusion
- Real-time event correlation
- Adaptive resource management
- Priority-based processing
- Comprehensive analytics dashboard

Architecture:
┌─────────────────────────────────────────────────────────┐
│                   CSI Data Stream                        │
└─────────────────────┬───────────────────────────────────┘
                      │
         ┌────────────▼────────────┐
         │   Data Preprocessor     │
         │   (Noise, Calibration)  │
         └────────────┬────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    ▼                 ▼                 ▼
┌───────┐       ┌───────────┐     ┌──────────┐
│Vital  │       │  Gesture  │     │   Gait   │
│Signs  │       │Recognition│     │   ID     │
└───┬───┘       └─────┬─────┘     └────┬─────┘
    │                 │                 │
    └────────────┬────┴────────────────┘
                 ▼
         ┌──────────────┐
         │ Event Fusion │
         │  & Analysis  │
         └──────┬───────┘
                ▼
         ┌──────────────┐
         │  Dashboard   │
         │  & Alerts    │
         └──────────────┘

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable, Any, Set
from collections import deque
from enum import Enum, auto
import time
import threading
import queue
import json
from pathlib import Path
import logging

# Define fallback MaterialType for when imports fail
class MaterialType(Enum):
    """Material types detected through tomography."""
    UNKNOWN = auto()
    AIR = auto()
    WOOD = auto()
    CONCRETE = auto()
    METAL = auto()
    GLASS = auto()
    PLASTIC = auto()
    FABRIC = auto()
    HUMAN = auto()
    WATER = auto()
    ELECTRONICS = auto()

# Import all sensing modules
try:
    from .wifi_vital_signs import VitalSignsProcessor, VitalSigns, MultiPersonVitalMonitor
    from .wifi_gesture_recognition import GestureRecognitionEngine, GestureEvent, GestureType
    from .wifi_gait_identification import GaitIdentificationEngine, IdentificationResult
    from .wifi_predictive_movement import MovementPredictionEngine, MovementPrediction, Position3D
    from .wifi_material_tomography import MaterialTomographyEngine, MaterialEstimate, MaterialType as _MaterialType
    MaterialType = _MaterialType  # Use actual if available
    from .wifi_acoustic_inference import AcousticInferenceEngine, AcousticEvent, VoiceActivityResult
except ImportError:
    # Standalone mode - will be imported when used as package
    pass


class SensingMode(Enum):
    """Operating modes for the orchestrator."""
    FULL = auto()           # All modules active
    SURVEILLANCE = auto()   # Person detection, tracking, identification
    HEALTH = auto()         # Vital signs, activity monitoring
    SECURITY = auto()       # Intrusion, glass break, anomalies
    SMART_HOME = auto()     # Gestures, presence, automation
    MINIMAL = auto()        # Basic presence only
    CUSTOM = auto()         # User-defined module set


class EventPriority(Enum):
    """Event priority levels."""
    CRITICAL = 1    # Immediate action required
    HIGH = 2        # Important, process soon
    MEDIUM = 3      # Normal priority
    LOW = 4         # Background processing
    INFO = 5        # Informational only


@dataclass
class SensingEvent:
    """Unified event from any sensing module."""
    timestamp: float
    event_type: str          # Module-specific type
    module: str              # Source module name
    priority: EventPriority
    confidence: float
    data: Dict[str, Any]     # Module-specific data
    related_events: List[str] = field(default_factory=list)  # Correlated event IDs
    event_id: str = ""
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = f"{self.module}_{self.timestamp:.3f}"


@dataclass
class PersonContext:
    """Aggregated context for a detected person."""
    person_id: str
    first_seen: float
    last_seen: float
    
    # Identification
    identified_name: Optional[str] = None
    identification_confidence: float = 0.0
    
    # Current state
    position: Optional[Tuple[float, float, float]] = None
    velocity: Optional[Tuple[float, float, float]] = None
    predicted_position: Optional[Tuple[float, float, float]] = None
    
    # Vital signs
    heart_rate: Optional[float] = None
    respiration_rate: Optional[float] = None
    stress_level: Optional[str] = None
    
    # Activity
    current_activity: str = "unknown"
    last_gesture: Optional[str] = None
    is_speaking: bool = False
    
    # History
    activity_history: List[str] = field(default_factory=list)
    location_history: List[Tuple[float, float, float]] = field(default_factory=list)


@dataclass
class EnvironmentContext:
    """Current environment state."""
    timestamp: float
    
    # Occupancy
    num_people: int = 0
    people: Dict[str, PersonContext] = field(default_factory=dict)
    
    # Environment
    ambient_noise_level: float = 0.0  # dB
    detected_materials: Dict[str, MaterialType] = field(default_factory=dict)
    
    # Activity summary
    active_conversations: int = 0
    detected_events: List[str] = field(default_factory=list)
    
    # Anomalies
    anomaly_score: float = 0.0
    anomaly_reasons: List[str] = field(default_factory=list)


class CSIPreprocessor:
    """
    Preprocess CSI data for all modules.
    
    Handles:
    - Phase unwrapping
    - Noise filtering
    - Outlier removal
    - Calibration
    - Subcarrier selection
    """
    
    def __init__(self, num_subcarriers: int = 52):
        self.num_subcarriers = num_subcarriers
        
        # Phase tracking
        self.prev_phases = np.zeros(num_subcarriers)
        self.phase_offset = np.zeros(num_subcarriers)
        
        # Calibration
        self.calibrated = False
        self.baseline_amplitude = np.zeros(num_subcarriers)
        self.baseline_phase = np.zeros(num_subcarriers)
        self.calibration_samples: List[Tuple[np.ndarray, np.ndarray]] = []
        
        # Noise estimation
        self.noise_floor = np.zeros(num_subcarriers)
        
        # Outlier detection
        self.amplitude_history = deque(maxlen=100)
        
    def process(self, amplitudes: np.ndarray, phases: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Preprocess CSI frame.
        
        Returns:
            (processed_amplitudes, processed_phases)
        """
        # Ensure correct size
        amp = np.array(amplitudes[:self.num_subcarriers])
        phase = np.array(phases[:self.num_subcarriers])
        
        # Phase unwrapping
        phase_diff = phase - self.prev_phases
        jumps = np.abs(phase_diff) > np.pi
        self.phase_offset[jumps & (phase_diff > 0)] -= 2 * np.pi
        self.phase_offset[jumps & (phase_diff < 0)] += 2 * np.pi
        self.prev_phases = phase.copy()
        
        unwrapped_phase = phase + self.phase_offset
        
        # Calibration collection
        if not self.calibrated:
            self.calibration_samples.append((amp.copy(), unwrapped_phase.copy()))
            if len(self.calibration_samples) >= 100:
                self._calibrate()
        
        # Remove baseline
        if self.calibrated:
            amp = amp - self.baseline_amplitude
            unwrapped_phase = unwrapped_phase - self.baseline_phase
        
        # Outlier removal
        self.amplitude_history.append(amp)
        if len(self.amplitude_history) >= 10:
            median_amp = np.median(self.amplitude_history, axis=0)
            mad = np.median(np.abs(self.amplitude_history - median_amp), axis=0)
            
            # Replace outliers with median
            outliers = np.abs(amp - median_amp) > 3 * mad
            amp[outliers] = median_amp[outliers]
        
        return amp, unwrapped_phase
    
    def _calibrate(self):
        """Compute calibration baselines."""
        amps = np.array([s[0] for s in self.calibration_samples])
        phases = np.array([s[1] for s in self.calibration_samples])
        
        self.baseline_amplitude = np.mean(amps, axis=0)
        self.baseline_phase = np.mean(phases, axis=0)
        self.noise_floor = np.std(amps, axis=0)
        
        self.calibrated = True
        self.calibration_samples = []
    
    def reset_calibration(self):
        """Reset calibration state."""
        self.calibrated = False
        self.calibration_samples = []
        self.phase_offset = np.zeros(self.num_subcarriers)


class EventCorrelator:
    """
    Correlate events across different sensing modules.
    
    Detects patterns like:
    - Person approaching + gesture = intent to interact
    - Vital signs change + movement = activity state change
    - Sound + movement = person activity
    """
    
    def __init__(self, correlation_window: float = 2.0):
        self.correlation_window = correlation_window
        self.recent_events: deque = deque(maxlen=1000)
        
        # Correlation rules
        self.rules: List[Dict] = []
        self._init_rules()
    
    def _init_rules(self):
        """Initialize correlation rules."""
        self.rules = [
            {
                'name': 'interaction_intent',
                'conditions': [
                    ('movement', 'APPROACHING'),
                    ('gesture', '*'),
                ],
                'output': 'INTERACTION_INTENT',
                'priority': EventPriority.HIGH,
            },
            {
                'name': 'distress',
                'conditions': [
                    ('vital_signs', 'HIGH_HEART_RATE'),
                    ('movement', 'ERRATIC'),
                ],
                'output': 'POSSIBLE_DISTRESS',
                'priority': EventPriority.CRITICAL,
            },
            {
                'name': 'intrusion',
                'conditions': [
                    ('gait_id', 'UNKNOWN_PERSON'),
                    ('acoustic', 'GLASS_BREAK'),
                ],
                'output': 'INTRUSION_ALERT',
                'priority': EventPriority.CRITICAL,
            },
            {
                'name': 'conversation',
                'conditions': [
                    ('acoustic', 'SPEECH'),
                    ('movement', 'STATIONARY'),
                ],
                'output': 'CONVERSATION_DETECTED',
                'priority': EventPriority.LOW,
            },
        ]
    
    def add_event(self, event: SensingEvent) -> List[SensingEvent]:
        """
        Add event and check for correlations.
        
        Returns list of correlated meta-events.
        """
        self.recent_events.append(event)
        
        # Remove old events
        cutoff = time.time() - self.correlation_window
        while self.recent_events and self.recent_events[0].timestamp < cutoff:
            self.recent_events.popleft()
        
        # Check correlation rules
        correlated_events = []
        
        for rule in self.rules:
            if self._check_rule(rule):
                meta_event = SensingEvent(
                    timestamp=time.time(),
                    event_type=rule['output'],
                    module='correlator',
                    priority=rule['priority'],
                    confidence=0.8,
                    data={'rule': rule['name'], 'source_events': [e.event_id for e in self.recent_events]}
                )
                correlated_events.append(meta_event)
        
        return correlated_events
    
    def _check_rule(self, rule: Dict) -> bool:
        """Check if a correlation rule is satisfied."""
        conditions_met = 0
        
        for module, event_type in rule['conditions']:
            for event in self.recent_events:
                if event.module == module:
                    if event_type == '*' or event.event_type == event_type:
                        conditions_met += 1
                        break
        
        return conditions_met == len(rule['conditions'])


class AlertManager:
    """
    Manage alerts and notifications.
    """
    
    def __init__(self):
        self.alert_handlers: Dict[EventPriority, List[Callable]] = {
            p: [] for p in EventPriority
        }
        self.alert_history: deque = deque(maxlen=1000)
        self.suppressed_alerts: Set[str] = set()
        self.suppression_duration = 60.0  # seconds
        
    def register_handler(self, priority: EventPriority, handler: Callable):
        """Register alert handler for priority level."""
        self.alert_handlers[priority].append(handler)
    
    def raise_alert(self, event: SensingEvent):
        """Raise alert for event."""
        # Check suppression
        alert_key = f"{event.module}_{event.event_type}"
        if alert_key in self.suppressed_alerts:
            return
        
        # Record alert
        self.alert_history.append(event)
        
        # Call handlers
        for handler in self.alert_handlers[event.priority]:
            try:
                handler(event)
            except Exception as e:
                logging.error(f"Alert handler error: {e}")
        
        # Auto-suppress repeated alerts
        if event.priority in [EventPriority.CRITICAL, EventPriority.HIGH]:
            self.suppressed_alerts.add(alert_key)
            # Schedule unsuppression
            threading.Timer(
                self.suppression_duration,
                lambda: self.suppressed_alerts.discard(alert_key)
            ).start()


class WifiSensingOrchestrator:
    """
    Main orchestrator for all WiFi sensing capabilities.
    
    Provides unified interface for:
    - CSI data ingestion
    - Multi-modal processing
    - Event correlation
    - Alert management
    - Analytics
    """
    
    def __init__(self, 
                 mode: SensingMode = SensingMode.FULL,
                 num_subcarriers: int = 52,
                 sample_rate: float = 100):
        
        self.mode = mode
        self.num_subcarriers = num_subcarriers
        self.sample_rate = sample_rate
        
        # Core components
        self.preprocessor = CSIPreprocessor(num_subcarriers)
        self.correlator = EventCorrelator()
        self.alert_manager = AlertManager()
        
        # Sensing modules (lazy initialization)
        self._vital_signs: Optional[MultiPersonVitalMonitor] = None
        self._gesture: Optional[GestureRecognitionEngine] = None
        self._gait_id: Optional[GaitIdentificationEngine] = None
        self._movement: Optional[MovementPredictionEngine] = None
        self._material: Optional[MaterialTomographyEngine] = None
        self._acoustic: Optional[AcousticInferenceEngine] = None
        
        # State
        self.running = False
        self.environment = EnvironmentContext(timestamp=time.time())
        self.people: Dict[str, PersonContext] = {}
        
        # Event queue for async processing
        self.event_queue: queue.Queue = queue.Queue()
        self.events: deque = deque(maxlen=10000)
        
        # Callbacks
        self.on_event: Optional[Callable[[SensingEvent], None]] = None
        self.on_person_detected: Optional[Callable[[PersonContext], None]] = None
        self.on_environment_update: Optional[Callable[[EnvironmentContext], None]] = None
        
        # Statistics
        self.stats = {
            'frames_processed': 0,
            'events_generated': 0,
            'alerts_raised': 0,
            'start_time': time.time(),
        }
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize modules based on mode
        self._init_modules()
        
        # Start processing thread
        self._start_processor()
    
    def _init_modules(self):
        """Initialize sensing modules based on mode."""
        try:
            if self.mode in [SensingMode.FULL, SensingMode.HEALTH]:
                from .wifi_vital_signs import MultiPersonVitalMonitor
                self._vital_signs = MultiPersonVitalMonitor()
            
            if self.mode in [SensingMode.FULL, SensingMode.SMART_HOME]:
                from .wifi_gesture_recognition import GestureRecognitionEngine
                self._gesture = GestureRecognitionEngine(self.num_subcarriers)
            
            if self.mode in [SensingMode.FULL, SensingMode.SURVEILLANCE, SensingMode.SECURITY]:
                from .wifi_gait_identification import GaitIdentificationEngine
                self._gait_id = GaitIdentificationEngine(self.num_subcarriers)
            
            if self.mode in [SensingMode.FULL, SensingMode.SURVEILLANCE]:
                from .wifi_predictive_movement import MovementPredictionEngine
                self._movement = MovementPredictionEngine()
            
            if self.mode in [SensingMode.FULL]:
                from .wifi_material_tomography import MaterialTomographyEngine
                self._material = MaterialTomographyEngine()
            
            if self.mode in [SensingMode.FULL, SensingMode.SECURITY, SensingMode.SMART_HOME]:
                from .wifi_acoustic_inference import AcousticInferenceEngine
                self._acoustic = AcousticInferenceEngine(
                    sample_rate=min(1000, self.sample_rate * 10),
                    num_subcarriers=self.num_subcarriers
                )
                
        except ImportError as e:
            logging.warning(f"Could not import sensing module: {e}")
    
    def _start_processor(self):
        """Start background processing thread."""
        self.running = True
        self._processor_thread = threading.Thread(target=self._process_loop, daemon=True)
        self._processor_thread.start()
    
    def _process_loop(self):
        """Background processing loop."""
        while self.running:
            try:
                # Process events from queue
                try:
                    event = self.event_queue.get(timeout=0.1)
                    self._handle_event(event)
                except queue.Empty:
                    pass
                
                # Periodic environment update
                self._update_environment()
                
            except Exception as e:
                logging.error(f"Processor loop error: {e}")
    
    def add_csi_frame(self, 
                      amplitudes: List[float], 
                      phases: List[float],
                      timestamp: float = None,
                      source: str = "primary"):
        """
        Add CSI frame from sensor.
        
        Args:
            amplitudes: CSI amplitude per subcarrier
            phases: CSI phase per subcarrier
            timestamp: Frame timestamp
            source: Sensor source identifier
        """
        if timestamp is None:
            timestamp = time.time()
        
        with self._lock:
            # Preprocess
            amp, phase = self.preprocessor.process(
                np.array(amplitudes), 
                np.array(phases)
            )
            
            self.stats['frames_processed'] += 1
            
            # Distribute to modules
            self._distribute_to_modules(amp, phase, timestamp, source)
    
    def _distribute_to_modules(self, amp: np.ndarray, phase: np.ndarray, 
                               timestamp: float, source: str):
        """Distribute preprocessed CSI to all active modules."""
        amp_list = amp.tolist()
        phase_list = phase.tolist()
        
        # Vital signs
        if self._vital_signs:
            self._vital_signs.add_csi_frame("default", amp_list, phase_list, timestamp)
            vitals = self._vital_signs.get_all_vitals()
            for person_id, vital_data in vitals.items():
                if vital_data.get('heart_rate', 0) > 0:
                    self._emit_event(SensingEvent(
                        timestamp=timestamp,
                        event_type='VITAL_SIGNS_UPDATE',
                        module='vital_signs',
                        priority=EventPriority.INFO,
                        confidence=vital_data.get('confidence', 0.5),
                        data=vital_data
                    ))
        
        # Gesture recognition
        if self._gesture:
            self._gesture.add_csi_frame(amp_list, phase_list, timestamp)
            gesture = self._gesture.process()
            if gesture:
                self._emit_event(SensingEvent(
                    timestamp=timestamp,
                    event_type=gesture.gesture_type.name,
                    module='gesture',
                    priority=EventPriority.MEDIUM,
                    confidence=gesture.confidence,
                    data={
                        'gesture': gesture.gesture_type.name,
                        'duration_ms': gesture.duration_ms,
                        'velocity': gesture.velocity,
                    }
                ))
        
        # Gait identification
        if self._gait_id:
            self._gait_id.add_csi_frame(amp_list, phase_list, timestamp)
            result = self._gait_id.process()
            if result:
                event_type = 'PERSON_IDENTIFIED' if result.person_id else 'UNKNOWN_PERSON'
                priority = EventPriority.HIGH if result.is_new_person else EventPriority.MEDIUM
                
                self._emit_event(SensingEvent(
                    timestamp=timestamp,
                    event_type=event_type,
                    module='gait_id',
                    priority=priority,
                    confidence=result.confidence,
                    data={
                        'person_id': result.person_id,
                        'person_name': result.person_name,
                        'is_new': result.is_new_person,
                        'match_scores': result.match_scores,
                    }
                ))
        
        # Acoustic inference
        if self._acoustic:
            self._acoustic.add_csi_frame(amp_list, phase_list, timestamp)
            acoustic_event, vad_result = self._acoustic.process()
            
            if acoustic_event:
                priority = EventPriority.CRITICAL if acoustic_event.event_type.name == 'GLASS_BREAK' else EventPriority.MEDIUM
                
                self._emit_event(SensingEvent(
                    timestamp=timestamp,
                    event_type=acoustic_event.event_type.name,
                    module='acoustic',
                    priority=priority,
                    confidence=acoustic_event.confidence,
                    data={
                        'spl_db': acoustic_event.estimated_spl_db,
                        'frequency_range': acoustic_event.frequency_range,
                        'duration_ms': acoustic_event.duration_ms,
                    }
                ))
            
            if vad_result and vad_result.is_speech:
                self._emit_event(SensingEvent(
                    timestamp=timestamp,
                    event_type='SPEECH',
                    module='acoustic',
                    priority=EventPriority.LOW,
                    confidence=vad_result.confidence,
                    data={
                        'speakers': vad_result.estimated_speakers,
                        'dominant_freq': vad_result.dominant_frequency,
                    }
                ))
    
    def _emit_event(self, event: SensingEvent):
        """Emit event to queue and callbacks."""
        self.events.append(event)
        self.event_queue.put(event)
        self.stats['events_generated'] += 1
        
        if self.on_event:
            try:
                self.on_event(event)
            except Exception as e:
                logging.error(f"Event callback error: {e}")
    
    def _handle_event(self, event: SensingEvent):
        """Handle event from queue."""
        # Check for correlations
        correlated = self.correlator.add_event(event)
        for meta_event in correlated:
            self._emit_event(meta_event)
        
        # Update person context
        self._update_person_context(event)
        
        # Check for alerts
        if event.priority in [EventPriority.CRITICAL, EventPriority.HIGH]:
            self.alert_manager.raise_alert(event)
            self.stats['alerts_raised'] += 1
    
    def _update_person_context(self, event: SensingEvent):
        """Update person context from event."""
        person_id = event.data.get('person_id', 'unknown')
        
        if person_id not in self.people:
            self.people[person_id] = PersonContext(
                person_id=person_id,
                first_seen=event.timestamp,
                last_seen=event.timestamp
            )
            if self.on_person_detected:
                self.on_person_detected(self.people[person_id])
        
        person = self.people[person_id]
        person.last_seen = event.timestamp
        
        # Update based on event type
        if event.module == 'vital_signs':
            person.heart_rate = event.data.get('heart_rate')
            person.respiration_rate = event.data.get('respiration_rate')
            person.stress_level = event.data.get('stress_level')
        
        elif event.module == 'gesture':
            person.last_gesture = event.event_type
        
        elif event.module == 'gait_id':
            person.identified_name = event.data.get('person_name')
            person.identification_confidence = event.confidence
        
        elif event.module == 'movement':
            person.current_activity = event.data.get('intent', 'unknown')
    
    def _update_environment(self):
        """Update environment context."""
        now = time.time()
        
        # Update environment
        self.environment.timestamp = now
        self.environment.num_people = len([
            p for p in self.people.values()
            if now - p.last_seen < 30  # Active in last 30 seconds
        ])
        
        # Copy active people
        self.environment.people = {
            pid: p for pid, p in self.people.items()
            if now - p.last_seen < 30
        }
        
        # Get acoustic info
        if self._acoustic:
            self.environment.ambient_noise_level = self._acoustic.get_current_spl()
        
        # Callback
        if self.on_environment_update:
            self.on_environment_update(self.environment)
    
    def add_position_observation(self, x: float, y: float, z: float = 0,
                                 person_id: str = "default"):
        """Add position observation for movement prediction."""
        if self._movement:
            pos = Position3D(x, y, z, confidence=0.9, timestamp=time.time())
            self._movement.update_person(person_id, pos)
            
            prediction = self._movement.predict(person_id)
            if prediction:
                self._emit_event(SensingEvent(
                    timestamp=time.time(),
                    event_type=prediction.intent.name,
                    module='movement',
                    priority=EventPriority.LOW,
                    confidence=prediction.confidence,
                    data={
                        'person_id': person_id,
                        'intent': prediction.intent.name,
                        'predicted_positions': [
                            (p.x, p.y, p.z) for p in prediction.predicted_trajectory[:5]
                        ],
                    }
                ))
    
    def add_material_measurement(self, 
                                tx_pos: Tuple[float, float, float],
                                rx_pos: Tuple[float, float, float],
                                csi_amplitude: np.ndarray,
                                csi_phase: np.ndarray):
        """Add material tomography measurement."""
        if self._material:
            estimate = self._material.process_csi_measurement(
                tx_pos, rx_pos, csi_amplitude, csi_phase
            )
            
            if estimate:
                self._emit_event(SensingEvent(
                    timestamp=time.time(),
                    event_type='MATERIAL_DETECTED',
                    module='material',
                    priority=EventPriority.INFO,
                    confidence=estimate.confidence,
                    data={
                        'material': estimate.material_type.name,
                        'position': estimate.position,
                        'thickness': estimate.thickness,
                    }
                ))
    
    def get_environment_summary(self) -> Dict:
        """Get current environment summary."""
        return {
            'timestamp': self.environment.timestamp,
            'num_people': self.environment.num_people,
            'people': {
                pid: {
                    'name': p.identified_name,
                    'confidence': p.identification_confidence,
                    'activity': p.current_activity,
                    'heart_rate': p.heart_rate,
                    'stress': p.stress_level,
                    'last_gesture': p.last_gesture,
                    'is_speaking': p.is_speaking,
                }
                for pid, p in self.environment.people.items()
            },
            'ambient_noise_db': self.environment.ambient_noise_level,
            'anomaly_score': self.environment.anomaly_score,
        }
    
    def get_statistics(self) -> Dict:
        """Get orchestrator statistics."""
        uptime = time.time() - self.stats['start_time']
        
        return {
            'mode': self.mode.name,
            'uptime_seconds': uptime,
            'frames_processed': self.stats['frames_processed'],
            'events_generated': self.stats['events_generated'],
            'alerts_raised': self.stats['alerts_raised'],
            'fps': self.stats['frames_processed'] / max(1, uptime),
            'events_per_second': self.stats['events_generated'] / max(1, uptime),
            'calibrated': self.preprocessor.calibrated,
            'active_modules': self._get_active_modules(),
            'people_tracked': len(self.people),
        }
    
    def _get_active_modules(self) -> List[str]:
        """Get list of active modules."""
        modules = []
        if self._vital_signs: modules.append('vital_signs')
        if self._gesture: modules.append('gesture')
        if self._gait_id: modules.append('gait_id')
        if self._movement: modules.append('movement')
        if self._material: modules.append('material')
        if self._acoustic: modules.append('acoustic')
        return modules
    
    def stop(self):
        """Stop the orchestrator."""
        self.running = False
        if hasattr(self, '_processor_thread'):
            self._processor_thread.join(timeout=2.0)
    
    def reset(self):
        """Reset all state."""
        with self._lock:
            self.preprocessor.reset_calibration()
            self.people.clear()
            self.events.clear()
            self.stats = {
                'frames_processed': 0,
                'events_generated': 0,
                'alerts_raised': 0,
                'start_time': time.time(),
            }


# High-level convenience class
class HydraSensingPlatform:
    """
    High-level interface for the Hydra WiFi Sensing Platform.
    
    Simplified API for common use cases.
    """
    
    def __init__(self, mode: str = "full"):
        """
        Initialize platform.
        
        Args:
            mode: One of "full", "surveillance", "health", "security", "smart_home", "minimal"
        """
        mode_map = {
            'full': SensingMode.FULL,
            'surveillance': SensingMode.SURVEILLANCE,
            'health': SensingMode.HEALTH,
            'security': SensingMode.SECURITY,
            'smart_home': SensingMode.SMART_HOME,
            'minimal': SensingMode.MINIMAL,
        }
        
        self.orchestrator = WifiSensingOrchestrator(mode=mode_map.get(mode, SensingMode.FULL))
        
        # Simple callbacks
        self.on_person = None
        self.on_gesture = None
        self.on_alert = None
        self.on_sound = None
        
        # Set up routing
        self.orchestrator.on_event = self._route_event
    
    def _route_event(self, event: SensingEvent):
        """Route events to appropriate callbacks."""
        if event.module == 'gesture' and self.on_gesture:
            self.on_gesture(event.event_type, event.confidence)
        
        elif event.module == 'gait_id' and self.on_person:
            self.on_person(event.data.get('person_name', 'Unknown'), event.confidence)
        
        elif event.module == 'acoustic' and self.on_sound:
            self.on_sound(event.event_type, event.data.get('spl_db', 0))
        
        if event.priority in [EventPriority.CRITICAL, EventPriority.HIGH] and self.on_alert:
            self.on_alert(event.event_type, event.module, event.confidence)
    
    def feed_csi(self, amplitudes: List[float], phases: List[float]):
        """Feed CSI data to the platform."""
        self.orchestrator.add_csi_frame(amplitudes, phases)
    
    def get_status(self) -> Dict:
        """Get platform status."""
        return {
            'stats': self.orchestrator.get_statistics(),
            'environment': self.orchestrator.get_environment_summary(),
        }
    
    def stop(self):
        """Stop the platform."""
        self.orchestrator.stop()


# Standalone testing
if __name__ == "__main__":
    print("=== WiFi Sensing Orchestrator Test ===\n")
    
    # Create orchestrator in full mode
    orchestrator = WifiSensingOrchestrator(mode=SensingMode.FULL)
    
    events_received = []
    
    def on_event(event):
        events_received.append(event)
        if event.priority.value <= 2:  # HIGH or CRITICAL
            print(f"⚠️ {event.priority.name}: {event.module}/{event.event_type} ({event.confidence:.2f})")
    
    orchestrator.on_event = on_event
    
    # Simulate CSI data
    print("Feeding simulated CSI data...")
    np.random.seed(42)
    
    for i in range(500):
        t = i * 0.01  # 100 Hz
        
        # Simulate some activity
        if 100 < i < 150:
            # Gesture-like signal
            gesture_phase = 0.3 * np.sin(2 * np.pi * 2 * t)
        else:
            gesture_phase = 0
        
        phases = np.random.randn(52) * 0.02 + gesture_phase
        amplitudes = 50 + np.random.randn(52) * 2
        
        orchestrator.add_csi_frame(amplitudes.tolist(), phases.tolist(), t)
        
        time.sleep(0.001)  # Small delay
    
    # Wait for processing
    time.sleep(1)
    
    print(f"\nTotal events received: {len(events_received)}")
    print("\nOrchestrator Statistics:")
    print(json.dumps(orchestrator.get_statistics(), indent=2))
    
    print("\nEnvironment Summary:")
    print(json.dumps(orchestrator.get_environment_summary(), indent=2))
    
    orchestrator.stop()
