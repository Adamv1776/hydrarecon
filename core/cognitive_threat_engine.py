"""
Cognitive Threat Engine
Self-learning threat detection with neural network-based pattern recognition.
Continuous adaptation to new attack patterns and threat actor behaviors.
"""

import asyncio
import json
import hashlib
import math
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque
import random


class ThreatCategory(Enum):
    """Categories of threats"""
    MALWARE = auto()
    INTRUSION = auto()
    DATA_EXFIL = auto()
    LATERAL_MOVEMENT = auto()
    PRIVILEGE_ESCALATION = auto()
    PERSISTENCE = auto()
    RECONNAISSANCE = auto()
    DENIAL_OF_SERVICE = auto()
    INSIDER_THREAT = auto()
    APT = auto()


class BehaviorType(Enum):
    """Types of behavioral patterns"""
    NETWORK_TRAFFIC = auto()
    FILE_ACCESS = auto()
    PROCESS_EXECUTION = auto()
    USER_ACTIVITY = auto()
    AUTHENTICATION = auto()
    REGISTRY_MODIFICATION = auto()
    API_CALL = auto()
    DNS_QUERY = auto()


@dataclass
class ThreatSignature:
    """Learned threat signature"""
    id: str
    name: str
    category: ThreatCategory
    confidence: float
    features: Dict[str, float]
    iocs: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    last_seen: Optional[datetime] = None
    occurrences: int = 0


@dataclass
class BehaviorPattern:
    """Behavioral pattern for analysis"""
    id: str
    behavior_type: BehaviorType
    source: str
    timestamp: datetime
    features: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)
    anomaly_score: float = 0.0
    threat_score: float = 0.0


@dataclass
class ThreatEvent:
    """Detected threat event"""
    id: str
    timestamp: datetime
    category: ThreatCategory
    severity: float  # 0.0 - 1.0
    confidence: float
    source: str
    description: str
    related_patterns: List[str] = field(default_factory=list)
    matched_signatures: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    iocs: Dict[str, Any] = field(default_factory=dict)


class NeuralLayer:
    """Simple neural network layer"""
    
    def __init__(self, input_size: int, output_size: int):
        self.weights = [[random.gauss(0, 0.5) for _ in range(input_size)] 
                        for _ in range(output_size)]
        self.biases = [random.gauss(0, 0.1) for _ in range(output_size)]
    
    def forward(self, inputs: List[float]) -> List[float]:
        """Forward pass"""
        outputs = []
        for i, (weight_row, bias) in enumerate(zip(self.weights, self.biases)):
            activation = sum(w * x for w, x in zip(weight_row, inputs)) + bias
            # ReLU activation
            outputs.append(max(0, activation))
        return outputs
    
    def backward(self, inputs: List[float], output_gradients: List[float], 
                 learning_rate: float) -> List[float]:
        """Backward pass with gradient update"""
        input_gradients = [0.0] * len(inputs)
        
        for i, (weight_row, grad) in enumerate(zip(self.weights, output_gradients)):
            for j in range(len(weight_row)):
                input_gradients[j] += weight_row[j] * grad
                self.weights[i][j] -= learning_rate * grad * inputs[j]
            self.biases[i] -= learning_rate * grad
        
        return input_gradients


class ThreatNeuralNetwork:
    """Neural network for threat classification"""
    
    def __init__(self, input_size: int = 64, hidden_size: int = 128, 
                 output_size: int = 10):
        self.layer1 = NeuralLayer(input_size, hidden_size)
        self.layer2 = NeuralLayer(hidden_size, hidden_size // 2)
        self.layer3 = NeuralLayer(hidden_size // 2, output_size)
        self.learning_rate = 0.01
    
    def predict(self, features: List[float]) -> List[float]:
        """Forward pass through network"""
        h1 = self.layer1.forward(features)
        h2 = self.layer2.forward(h1)
        output = self.layer3.forward(h2)
        
        # Softmax
        exp_output = [math.exp(min(x, 10)) for x in output]  # Clip to prevent overflow
        total = sum(exp_output)
        return [x / total if total > 0 else 1/len(output) for x in exp_output]
    
    def train(self, features: List[float], target: List[float]):
        """Train with backpropagation"""
        # Forward pass
        h1 = self.layer1.forward(features)
        h2 = self.layer2.forward(h1)
        output = self.layer3.forward(h2)
        
        # Compute loss gradients
        output_grads = [o - t for o, t in zip(output, target)]
        
        # Backward pass
        h2_grads = self.layer3.backward(h2, output_grads, self.learning_rate)
        h1_grads = self.layer2.backward(h1, h2_grads, self.learning_rate)
        self.layer1.backward(features, h1_grads, self.learning_rate)


class AnomalyDetector:
    """Statistical anomaly detection"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.feature_stats: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {"mean": 0, "std": 1, "count": 0, "sum": 0, "sum_sq": 0}
        )
        self.history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
    
    def update(self, feature_name: str, value: float):
        """Update statistics for feature"""
        stats = self.feature_stats[feature_name]
        self.history[feature_name].append(value)
        
        stats["count"] += 1
        stats["sum"] += value
        stats["sum_sq"] += value ** 2
        
        n = stats["count"]
        stats["mean"] = stats["sum"] / n
        
        if n > 1:
            variance = (stats["sum_sq"] - stats["sum"]**2 / n) / (n - 1)
            stats["std"] = math.sqrt(max(0, variance))
    
    def get_anomaly_score(self, feature_name: str, value: float) -> float:
        """Calculate anomaly score using z-score"""
        stats = self.feature_stats[feature_name]
        
        if stats["count"] < 10 or stats["std"] == 0:
            return 0.0
        
        z_score = abs(value - stats["mean"]) / stats["std"]
        
        # Convert to probability using sigmoid
        return 1 / (1 + math.exp(-z_score + 3))  # Shifted sigmoid
    
    def detect_anomalies(self, features: Dict[str, float], 
                         threshold: float = 0.7) -> List[Tuple[str, float]]:
        """Detect anomalies in feature set"""
        anomalies = []
        
        for name, value in features.items():
            score = self.get_anomaly_score(name, value)
            if score >= threshold:
                anomalies.append((name, score))
            self.update(name, value)
        
        return anomalies


class BehaviorAnalyzer:
    """Analyzes behavioral patterns for threats"""
    
    def __init__(self):
        self.baseline_behaviors: Dict[str, Dict[str, Any]] = {}
        self.behavior_sequences: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )
        self.threat_patterns: List[Dict] = self._init_threat_patterns()
    
    def _init_threat_patterns(self) -> List[Dict]:
        """Initialize known threat behavioral patterns"""
        return [
            {
                "name": "Credential Dumping Sequence",
                "category": ThreatCategory.PRIVILEGE_ESCALATION,
                "sequence": ["process_lsass_access", "file_sam_read", "network_smb_auth"],
                "confidence": 0.9
            },
            {
                "name": "Lateral Movement via PsExec",
                "category": ThreatCategory.LATERAL_MOVEMENT,
                "sequence": ["process_psexec_spawn", "network_smb_pipe", "process_remote_create"],
                "confidence": 0.85
            },
            {
                "name": "Data Exfiltration Pattern",
                "category": ThreatCategory.DATA_EXFIL,
                "sequence": ["file_bulk_read", "process_compress", "network_unusual_upload"],
                "confidence": 0.88
            },
            {
                "name": "Persistence via Registry",
                "category": ThreatCategory.PERSISTENCE,
                "sequence": ["registry_run_key", "file_drop", "process_delayed_start"],
                "confidence": 0.82
            },
            {
                "name": "Ransomware Behavior",
                "category": ThreatCategory.MALWARE,
                "sequence": ["file_enumerate", "file_mass_modify", "file_extension_change"],
                "confidence": 0.95
            },
        ]
    
    def analyze(self, pattern: BehaviorPattern) -> Tuple[float, List[str]]:
        """Analyze behavior pattern for threats"""
        # Add to sequence history
        self.behavior_sequences[pattern.source].append(pattern)
        
        threat_score = 0.0
        matched_patterns = []
        
        # Check against known threat patterns
        recent_behaviors = list(self.behavior_sequences[pattern.source])[-10:]
        behavior_names = [self._get_behavior_name(b) for b in recent_behaviors]
        
        for threat_pattern in self.threat_patterns:
            if self._sequence_match(behavior_names, threat_pattern["sequence"]):
                threat_score = max(threat_score, threat_pattern["confidence"])
                matched_patterns.append(threat_pattern["name"])
        
        return threat_score, matched_patterns
    
    def _get_behavior_name(self, pattern: BehaviorPattern) -> str:
        """Convert behavior pattern to name"""
        return f"{pattern.behavior_type.name.lower()}_{pattern.features.get('action', 'unknown')}"
    
    def _sequence_match(self, observed: List[str], pattern: List[str]) -> bool:
        """Check if observed sequence matches threat pattern"""
        pattern_idx = 0
        for behavior in observed:
            if pattern_idx < len(pattern) and pattern[pattern_idx] in behavior:
                pattern_idx += 1
        return pattern_idx == len(pattern)
    
    def update_baseline(self, source: str, behaviors: List[BehaviorPattern]):
        """Update behavioral baseline for source"""
        if source not in self.baseline_behaviors:
            self.baseline_behaviors[source] = {
                "behavior_counts": defaultdict(int),
                "time_patterns": defaultdict(list),
                "typical_features": {}
            }
        
        baseline = self.baseline_behaviors[source]
        
        for behavior in behaviors:
            behavior_key = f"{behavior.behavior_type.name}:{behavior.features.get('action', '')}"
            baseline["behavior_counts"][behavior_key] += 1
            baseline["time_patterns"][behavior.behavior_type.name].append(
                behavior.timestamp.hour
            )


class ThreatCorrelator:
    """Correlates events to identify complex threats"""
    
    def __init__(self, correlation_window: timedelta = timedelta(hours=1)):
        self.correlation_window = correlation_window
        self.event_buffer: deque = deque(maxlen=10000)
        self.correlation_rules: List[Dict] = self._init_rules()
    
    def _init_rules(self) -> List[Dict]:
        """Initialize correlation rules"""
        return [
            {
                "name": "Brute Force Attack",
                "conditions": [
                    {"type": "count", "event_type": "auth_failure", "threshold": 5, "window": 60},
                ],
                "severity": 0.8,
                "category": ThreatCategory.INTRUSION
            },
            {
                "name": "Reconnaissance Followed by Exploitation",
                "conditions": [
                    {"type": "sequence", "events": ["port_scan", "exploit_attempt"]},
                ],
                "severity": 0.9,
                "category": ThreatCategory.INTRUSION
            },
            {
                "name": "Data Staging for Exfiltration",
                "conditions": [
                    {"type": "volume", "event_type": "file_copy", "threshold_mb": 100, "window": 300},
                ],
                "severity": 0.85,
                "category": ThreatCategory.DATA_EXFIL
            },
        ]
    
    def add_event(self, event: Dict[str, Any]):
        """Add event to correlation buffer"""
        event["_timestamp"] = datetime.now()
        self.event_buffer.append(event)
    
    def correlate(self) -> List[ThreatEvent]:
        """Run correlation analysis"""
        threats = []
        now = datetime.now()
        
        for rule in self.correlation_rules:
            if self._evaluate_rule(rule, now):
                threat = ThreatEvent(
                    id=hashlib.md5(f"{rule['name']}{now}".encode()).hexdigest()[:12],
                    timestamp=now,
                    category=rule["category"],
                    severity=rule["severity"],
                    confidence=0.8,
                    source="correlation_engine",
                    description=f"Correlated threat: {rule['name']}"
                )
                threats.append(threat)
        
        return threats
    
    def _evaluate_rule(self, rule: Dict, now: datetime) -> bool:
        """Evaluate a correlation rule"""
        for condition in rule["conditions"]:
            if not self._evaluate_condition(condition, now):
                return False
        return True
    
    def _evaluate_condition(self, condition: Dict, now: datetime) -> bool:
        """Evaluate a single condition"""
        window_seconds = condition.get("window", 3600)
        cutoff = now - timedelta(seconds=window_seconds)
        
        relevant_events = [
            e for e in self.event_buffer 
            if e["_timestamp"] >= cutoff
        ]
        
        if condition["type"] == "count":
            matching = [e for e in relevant_events 
                       if e.get("type") == condition["event_type"]]
            return len(matching) >= condition["threshold"]
        
        elif condition["type"] == "sequence":
            event_types = [e.get("type") for e in relevant_events]
            return self._check_sequence(event_types, condition["events"])
        
        elif condition["type"] == "volume":
            matching = [e for e in relevant_events 
                       if e.get("type") == condition["event_type"]]
            total_size = sum(e.get("size_mb", 0) for e in matching)
            return total_size >= condition["threshold_mb"]
        
        return False
    
    def _check_sequence(self, observed: List[str], required: List[str]) -> bool:
        """Check if required sequence exists in observed events"""
        req_idx = 0
        for event_type in observed:
            if req_idx < len(required) and event_type == required[req_idx]:
                req_idx += 1
        return req_idx == len(required)


class CognitiveThreatEngine:
    """Main cognitive threat detection engine"""
    
    def __init__(self, config, db):
        self.config = config
        self.db = db
        
        # Neural network for threat classification
        self.threat_classifier = ThreatNeuralNetwork(
            input_size=64, hidden_size=128, output_size=len(ThreatCategory)
        )
        
        # Detection components
        self.anomaly_detector = AnomalyDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.correlator = ThreatCorrelator()
        
        # Learned signatures
        self.signatures: Dict[str, ThreatSignature] = {}
        self.threat_history: List[ThreatEvent] = []
        
        # Feature extractors
        self.feature_extractors: Dict[BehaviorType, Callable] = {
            BehaviorType.NETWORK_TRAFFIC: self._extract_network_features,
            BehaviorType.FILE_ACCESS: self._extract_file_features,
            BehaviorType.PROCESS_EXECUTION: self._extract_process_features,
            BehaviorType.USER_ACTIVITY: self._extract_user_features,
            BehaviorType.AUTHENTICATION: self._extract_auth_features,
        }
        
        # Callbacks
        self.on_threat_detected: List[Callable] = []
        self.on_anomaly_detected: List[Callable] = []
    
    async def analyze_behavior(self, behavior: BehaviorPattern) -> Optional[ThreatEvent]:
        """Analyze a behavior pattern for threats"""
        # Extract features
        features = self._extract_features(behavior)
        
        # Detect anomalies
        anomalies = self.anomaly_detector.detect_anomalies(features)
        if anomalies:
            behavior.anomaly_score = max(score for _, score in anomalies)
            await self._emit_anomaly(behavior, anomalies)
        
        # Analyze behavior patterns
        threat_score, matched_patterns = self.behavior_analyzer.analyze(behavior)
        behavior.threat_score = threat_score
        
        # Neural network classification
        feature_vector = self._features_to_vector(features)
        predictions = self.threat_classifier.predict(feature_vector)
        
        # Determine if threat
        max_category_idx = predictions.index(max(predictions))
        max_confidence = predictions[max_category_idx]
        
        if max_confidence > 0.7 or threat_score > 0.8:
            threat = ThreatEvent(
                id=hashlib.md5(f"{behavior.id}{datetime.now()}".encode()).hexdigest()[:12],
                timestamp=datetime.now(),
                category=list(ThreatCategory)[max_category_idx],
                severity=max(max_confidence, threat_score),
                confidence=max_confidence,
                source=behavior.source,
                description=f"Threat detected: {matched_patterns if matched_patterns else 'Neural classification'}",
                related_patterns=[behavior.id],
                matched_signatures=matched_patterns
            )
            
            self.threat_history.append(threat)
            await self._emit_threat(threat)
            
            # Learn from this detection
            await self._learn_from_detection(behavior, threat)
            
            return threat
        
        return None
    
    async def process_event_stream(self, events: List[Dict[str, Any]]):
        """Process stream of events for threat detection"""
        for event in events:
            # Convert to behavior pattern
            behavior = self._event_to_behavior(event)
            if behavior:
                await self.analyze_behavior(behavior)
            
            # Add to correlator
            self.correlator.add_event(event)
        
        # Run correlation analysis
        correlated_threats = self.correlator.correlate()
        for threat in correlated_threats:
            self.threat_history.append(threat)
            await self._emit_threat(threat)
    
    def learn_signature(self, name: str, category: ThreatCategory,
                        samples: List[BehaviorPattern], iocs: List[str] = None):
        """Learn new threat signature from samples"""
        if not samples:
            return None
        
        # Extract common features
        all_features = [self._extract_features(s) for s in samples]
        avg_features = {}
        
        for key in all_features[0].keys():
            values = [f.get(key, 0) for f in all_features if key in f]
            if values:
                avg_features[key] = sum(values) / len(values)
        
        signature = ThreatSignature(
            id=hashlib.md5(f"{name}{datetime.now()}".encode()).hexdigest()[:12],
            name=name,
            category=category,
            confidence=0.8,
            features=avg_features,
            iocs=iocs or [],
            occurrences=len(samples)
        )
        
        self.signatures[signature.id] = signature
        
        # Train neural network on these samples
        target = [0.0] * len(ThreatCategory)
        target[list(ThreatCategory).index(category)] = 1.0
        
        for sample in samples:
            features = self._extract_features(sample)
            feature_vector = self._features_to_vector(features)
            self.threat_classifier.train(feature_vector, target)
        
        return signature
    
    async def _learn_from_detection(self, behavior: BehaviorPattern, 
                                     threat: ThreatEvent):
        """Continuous learning from detections"""
        # Update neural network
        target = [0.0] * len(ThreatCategory)
        target[list(ThreatCategory).index(threat.category)] = 1.0
        
        features = self._extract_features(behavior)
        feature_vector = self._features_to_vector(features)
        self.threat_classifier.train(feature_vector, target)
    
    def _extract_features(self, behavior: BehaviorPattern) -> Dict[str, float]:
        """Extract features from behavior pattern"""
        extractor = self.feature_extractors.get(behavior.behavior_type)
        if extractor:
            return extractor(behavior)
        return behavior.features
    
    def _features_to_vector(self, features: Dict[str, float], 
                            size: int = 64) -> List[float]:
        """Convert features dict to fixed-size vector"""
        vector = [0.0] * size
        
        for i, (key, value) in enumerate(sorted(features.items())):
            if i < size:
                try:
                    vector[i] = float(value)
                except (ValueError, TypeError):
                    vector[i] = hash(str(value)) % 1000 / 1000.0
        
        return vector
    
    def _event_to_behavior(self, event: Dict[str, Any]) -> Optional[BehaviorPattern]:
        """Convert raw event to behavior pattern"""
        event_type = event.get("type", "")
        
        type_mapping = {
            "network": BehaviorType.NETWORK_TRAFFIC,
            "file": BehaviorType.FILE_ACCESS,
            "process": BehaviorType.PROCESS_EXECUTION,
            "user": BehaviorType.USER_ACTIVITY,
            "auth": BehaviorType.AUTHENTICATION,
        }
        
        for key, behavior_type in type_mapping.items():
            if key in event_type.lower():
                return BehaviorPattern(
                    id=hashlib.md5(json.dumps(event).encode()).hexdigest()[:12],
                    behavior_type=behavior_type,
                    source=event.get("source", "unknown"),
                    timestamp=datetime.now(),
                    features=event.get("features", {}),
                    context=event
                )
        
        return None
    
    def _extract_network_features(self, behavior: BehaviorPattern) -> Dict[str, float]:
        """Extract network traffic features"""
        features = behavior.features.copy()
        context = behavior.context
        
        features.update({
            "bytes_sent": context.get("bytes_sent", 0),
            "bytes_received": context.get("bytes_received", 0),
            "packet_count": context.get("packets", 0),
            "port": context.get("dst_port", 0),
            "protocol_tcp": 1 if context.get("protocol") == "tcp" else 0,
            "protocol_udp": 1 if context.get("protocol") == "udp" else 0,
            "connection_duration": context.get("duration", 0),
            "is_encrypted": 1 if context.get("encrypted") else 0,
        })
        
        return features
    
    def _extract_file_features(self, behavior: BehaviorPattern) -> Dict[str, float]:
        """Extract file access features"""
        features = behavior.features.copy()
        context = behavior.context
        
        features.update({
            "file_size": context.get("size", 0),
            "is_executable": 1 if context.get("extension") in [".exe", ".dll", ".bat"] else 0,
            "is_script": 1 if context.get("extension") in [".ps1", ".vbs", ".js"] else 0,
            "is_office": 1 if context.get("extension") in [".doc", ".xls", ".ppt"] else 0,
            "operation_read": 1 if context.get("operation") == "read" else 0,
            "operation_write": 1 if context.get("operation") == "write" else 0,
            "operation_delete": 1 if context.get("operation") == "delete" else 0,
        })
        
        return features
    
    def _extract_process_features(self, behavior: BehaviorPattern) -> Dict[str, float]:
        """Extract process execution features"""
        features = behavior.features.copy()
        context = behavior.context
        
        features.update({
            "has_network": 1 if context.get("has_network") else 0,
            "has_file_access": 1 if context.get("has_file") else 0,
            "child_process_count": context.get("children", 0),
            "cpu_usage": context.get("cpu", 0),
            "memory_usage": context.get("memory", 0),
            "is_elevated": 1 if context.get("elevated") else 0,
            "is_system": 1 if context.get("user") == "SYSTEM" else 0,
        })
        
        return features
    
    def _extract_user_features(self, behavior: BehaviorPattern) -> Dict[str, float]:
        """Extract user activity features"""
        features = behavior.features.copy()
        context = behavior.context
        
        hour = behavior.timestamp.hour
        features.update({
            "is_business_hours": 1 if 9 <= hour <= 17 else 0,
            "is_weekend": 1 if behavior.timestamp.weekday() >= 5 else 0,
            "action_count": context.get("action_count", 1),
            "session_duration": context.get("session_duration", 0),
        })
        
        return features
    
    def _extract_auth_features(self, behavior: BehaviorPattern) -> Dict[str, float]:
        """Extract authentication features"""
        features = behavior.features.copy()
        context = behavior.context
        
        features.update({
            "is_success": 1 if context.get("success") else 0,
            "is_failure": 0 if context.get("success") else 1,
            "attempt_count": context.get("attempts", 1),
            "is_mfa": 1 if context.get("mfa") else 0,
            "is_new_device": 1 if context.get("new_device") else 0,
            "is_new_location": 1 if context.get("new_location") else 0,
        })
        
        return features
    
    async def _emit_threat(self, threat: ThreatEvent):
        """Emit threat detection event"""
        for callback in self.on_threat_detected:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(threat)
                else:
                    callback(threat)
            except Exception:
                pass
    
    async def _emit_anomaly(self, behavior: BehaviorPattern, 
                            anomalies: List[Tuple[str, float]]):
        """Emit anomaly detection event"""
        for callback in self.on_anomaly_detected:
            try:
                data = {"behavior": behavior, "anomalies": anomalies}
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception:
                pass
    
    def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat detection summary"""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_threats = [t for t in self.threat_history if t.timestamp >= cutoff]
        
        by_category = defaultdict(int)
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for threat in recent_threats:
            by_category[threat.category.name] += 1
            
            if threat.severity >= 0.9:
                by_severity["critical"] += 1
            elif threat.severity >= 0.7:
                by_severity["high"] += 1
            elif threat.severity >= 0.4:
                by_severity["medium"] += 1
            else:
                by_severity["low"] += 1
        
        return {
            "total_threats": len(recent_threats),
            "by_category": dict(by_category),
            "by_severity": by_severity,
            "signatures_count": len(self.signatures),
            "model_trained": True
        }
    
    def export_model(self) -> Dict[str, Any]:
        """Export trained model and signatures"""
        return {
            "signatures": {k: {
                "id": v.id,
                "name": v.name,
                "category": v.category.name,
                "confidence": v.confidence,
                "features": v.features,
                "iocs": v.iocs,
                "occurrences": v.occurrences
            } for k, v in self.signatures.items()},
            "anomaly_stats": dict(self.anomaly_detector.feature_stats),
        }
    
    def import_model(self, data: Dict[str, Any]):
        """Import trained model and signatures"""
        for sig_data in data.get("signatures", {}).values():
            signature = ThreatSignature(
                id=sig_data["id"],
                name=sig_data["name"],
                category=ThreatCategory[sig_data["category"]],
                confidence=sig_data["confidence"],
                features=sig_data["features"],
                iocs=sig_data.get("iocs", []),
                occurrences=sig_data.get("occurrences", 0)
            )
            self.signatures[signature.id] = signature
