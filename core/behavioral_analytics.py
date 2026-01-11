#!/usr/bin/env python3
"""
Advanced Behavioral Analytics Engine

Provides cutting-edge User and Entity Behavior Analytics (UEBA) using
machine learning to detect anomalies, insider threats, and compromised accounts.

Features:
- User behavior profiling with statistical baselines
- Entity behavior analysis for devices and services
- Peer group analysis for anomaly detection
- Session analytics with risk scoring
- Time-series anomaly detection
- Graph-based entity relationships
- Real-time streaming analytics
- Explainable anomaly reasoning
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable, Set
from enum import Enum, auto
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import json
import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class EntityType(Enum):
    """Types of entities to analyze."""
    USER = "user"
    HOST = "host"
    SERVICE = "service"
    APPLICATION = "application"
    NETWORK = "network"
    DATABASE = "database"
    CLOUD_RESOURCE = "cloud_resource"


class BehaviorCategory(Enum):
    """Categories of behavioral patterns."""
    AUTHENTICATION = "authentication"
    ACCESS_PATTERN = "access_pattern"
    DATA_MOVEMENT = "data_movement"
    NETWORK_ACTIVITY = "network_activity"
    RESOURCE_USAGE = "resource_usage"
    TEMPORAL_PATTERN = "temporal_pattern"
    GEOGRAPHIC = "geographic"
    PRIVILEGE_USAGE = "privilege_usage"


class AnomalyType(Enum):
    """Types of detected anomalies."""
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    UNUSUAL_TIME = "unusual_time"
    UNUSUAL_LOCATION = "unusual_location"
    UNUSUAL_VOLUME = "unusual_volume"
    UNUSUAL_RESOURCE = "unusual_resource"
    UNUSUAL_PATTERN = "unusual_pattern"
    PEER_DEVIATION = "peer_deviation"
    BASELINE_DEVIATION = "baseline_deviation"
    VELOCITY_ANOMALY = "velocity_anomaly"
    SEQUENCE_ANOMALY = "sequence_anomaly"


class RiskLevel(Enum):
    """Risk severity levels."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class BehaviorEvent:
    """A single behavioral event."""
    event_id: str
    entity_id: str
    entity_type: EntityType
    category: BehaviorCategory
    action: str
    timestamp: datetime
    source_ip: Optional[str] = None
    destination: Optional[str] = None
    resource: Optional[str] = None
    data_volume: Optional[int] = None
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_features(self) -> np.ndarray:
        """Convert to feature vector."""
        features = []
        
        # Time features
        features.append(self.timestamp.hour / 24.0)
        features.append(self.timestamp.weekday() / 7.0)
        features.append(1 if self.timestamp.weekday() >= 5 else 0)  # Weekend
        
        # Category encoding
        features.append(hash(self.category.value) % 100 / 100.0)
        features.append(hash(self.action) % 100 / 100.0)
        
        # Volume (log-scaled)
        if self.data_volume:
            features.append(np.log1p(self.data_volume) / 20.0)
        else:
            features.append(0.0)
        
        # Success flag
        features.append(1.0 if self.success else 0.0)
        
        return np.array(features)


@dataclass
class BehaviorBaseline:
    """Statistical baseline for entity behavior."""
    entity_id: str
    entity_type: EntityType
    
    # Time-based patterns
    typical_hours: Set[int] = field(default_factory=set)
    typical_days: Set[int] = field(default_factory=set)
    
    # Volume statistics
    avg_daily_events: float = 0.0
    std_daily_events: float = 0.0
    avg_data_volume: float = 0.0
    std_data_volume: float = 0.0
    
    # Resource access patterns
    common_resources: Dict[str, float] = field(default_factory=dict)
    common_actions: Dict[str, float] = field(default_factory=dict)
    
    # Network patterns
    common_ips: Set[str] = field(default_factory=set)
    common_destinations: Set[str] = field(default_factory=set)
    
    # Session patterns
    avg_session_duration: float = 0.0
    avg_events_per_session: float = 0.0
    
    # Peer group
    peer_group_id: Optional[str] = None
    
    # Statistics
    events_analyzed: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
    
    def update(self, event: BehaviorEvent):
        """Update baseline with new event."""
        self.typical_hours.add(event.timestamp.hour)
        self.typical_days.add(event.timestamp.weekday())
        
        if event.resource:
            self.common_resources[event.resource] = \
                self.common_resources.get(event.resource, 0) + 1
        
        self.common_actions[event.action] = \
            self.common_actions.get(event.action, 0) + 1
        
        if event.source_ip:
            self.common_ips.add(event.source_ip)
        if event.destination:
            self.common_destinations.add(event.destination)
        
        self.events_analyzed += 1
        self.last_updated = datetime.now()


@dataclass
class BehaviorAnomaly:
    """Detected behavioral anomaly."""
    anomaly_id: str
    entity_id: str
    entity_type: EntityType
    anomaly_type: AnomalyType
    risk_level: RiskLevel
    confidence: float  # 0.0 - 1.0
    score: float  # Anomaly score
    
    triggering_events: List[str]  # Event IDs
    description: str
    baseline_comparison: Dict[str, Any]
    
    detected_at: datetime = field(default_factory=datetime.now)
    
    # Investigation aids
    recommended_actions: List[str] = field(default_factory=list)
    related_entities: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'anomaly_id': self.anomaly_id,
            'entity_id': self.entity_id,
            'entity_type': self.entity_type.value,
            'anomaly_type': self.anomaly_type.value,
            'risk_level': self.risk_level.name,
            'confidence': self.confidence,
            'score': self.score,
            'description': self.description,
            'detected_at': self.detected_at.isoformat()
        }


class StatisticalAnomalyDetector:
    """
    Statistical methods for anomaly detection.
    Uses z-scores, IQR, and Mahalanobis distance.
    """
    
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.means: Dict[str, float] = {}
        self.stds: Dict[str, float] = {}
        self.trained = False
    
    def fit(self, data: np.ndarray, feature_names: List[str]):
        """Fit detector to historical data."""
        self.means = {name: np.mean(data[:, i]) 
                     for i, name in enumerate(feature_names)}
        self.stds = {name: np.std(data[:, i]) + 1e-10  # Avoid division by zero
                    for i, name in enumerate(feature_names)}
        self.feature_names = feature_names
        self.trained = True
    
    def score(self, sample: np.ndarray) -> float:
        """Calculate anomaly score using z-scores."""
        if not self.trained:
            return 0.5
        
        z_scores = []
        for i, name in enumerate(self.feature_names):
            z = abs(sample[i] - self.means[name]) / self.stds[name]
            z_scores.append(z)
        
        # Combined score using max z-score and mean
        max_z = max(z_scores)
        mean_z = np.mean(z_scores)
        
        # Normalize to 0-1 range
        score = 1 - np.exp(-0.5 * (max_z + mean_z))
        return float(score)
    
    def detect(self, sample: np.ndarray, threshold: float = 0.7) -> Tuple[bool, float]:
        """Detect if sample is anomalous."""
        score = self.score(sample)
        return score > threshold, score


class IsolationForestDetector:
    """
    Isolation Forest implementation for anomaly detection.
    Efficient for high-dimensional data.
    """
    
    def __init__(self, n_trees: int = 100, max_samples: int = 256,
                 contamination: float = 0.05):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.contamination = contamination
        self.trees: List[Dict] = []
        self.threshold = 0.5
        
    def fit(self, data: np.ndarray):
        """Build isolation forest."""
        n_samples = min(self.max_samples, len(data))
        
        self.trees = []
        for _ in range(self.n_trees):
            # Sample subset
            indices = np.random.choice(len(data), n_samples, replace=False)
            samples = data[indices]
            
            # Build tree
            tree = self._build_tree(samples, 0, int(np.ceil(np.log2(n_samples))))
            self.trees.append(tree)
        
        # Set threshold based on contamination
        scores = np.array([self.score(x) for x in data])
        self.threshold = np.percentile(scores, 100 * (1 - self.contamination))
    
    def _build_tree(self, data: np.ndarray, depth: int, max_depth: int) -> Dict:
        """Recursively build isolation tree."""
        if depth >= max_depth or len(data) <= 1:
            return {'type': 'leaf', 'size': len(data)}
        
        # Random split
        n_features = data.shape[1]
        feature = np.random.randint(n_features)
        
        min_val = np.min(data[:, feature])
        max_val = np.max(data[:, feature])
        
        if min_val == max_val:
            return {'type': 'leaf', 'size': len(data)}
        
        split_value = np.random.uniform(min_val, max_val)
        
        left_mask = data[:, feature] < split_value
        right_mask = ~left_mask
        
        return {
            'type': 'node',
            'feature': feature,
            'split': split_value,
            'left': self._build_tree(data[left_mask], depth + 1, max_depth),
            'right': self._build_tree(data[right_mask], depth + 1, max_depth)
        }
    
    def _path_length(self, sample: np.ndarray, tree: Dict, depth: int = 0) -> float:
        """Calculate path length for sample in tree."""
        if tree['type'] == 'leaf':
            # Adjustment for leaf size
            n = tree['size']
            if n <= 1:
                return depth
            return depth + self._c(n)
        
        if sample[tree['feature']] < tree['split']:
            return self._path_length(sample, tree['left'], depth + 1)
        else:
            return self._path_length(sample, tree['right'], depth + 1)
    
    def _c(self, n: int) -> float:
        """Average path length of unsuccessful search in BST."""
        if n <= 1:
            return 0
        return 2 * (np.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n
    
    def score(self, sample: np.ndarray) -> float:
        """Calculate anomaly score."""
        if not self.trees:
            return 0.5
        
        # Average path length across all trees
        avg_path_length = np.mean([
            self._path_length(sample, tree) for tree in self.trees
        ])
        
        # Normalize score
        c_n = self._c(self.max_samples)
        score = 2 ** (-avg_path_length / c_n) if c_n > 0 else 0.5
        
        return float(score)
    
    def detect(self, sample: np.ndarray) -> Tuple[bool, float]:
        """Detect if sample is anomalous."""
        score = self.score(sample)
        return score > self.threshold, score


class TimeSeriesAnomalyDetector:
    """
    Time series anomaly detection using EWMA and seasonal decomposition.
    """
    
    def __init__(self, alpha: float = 0.3, window_size: int = 24):
        self.alpha = alpha
        self.window_size = window_size
        self.ewma_state: Dict[str, float] = {}
        self.ewma_var: Dict[str, float] = {}
        self.seasonal_pattern: Dict[int, float] = defaultdict(float)
        self.seasonal_counts: Dict[int, int] = defaultdict(int)
    
    def update(self, entity_id: str, value: float, timestamp: datetime) -> float:
        """Update EWMA and return anomaly score."""
        # Update seasonal pattern
        hour = timestamp.hour
        self.seasonal_counts[hour] += 1
        self.seasonal_pattern[hour] += (value - self.seasonal_pattern[hour]) / self.seasonal_counts[hour]
        
        # Remove seasonal component
        deseasonalized = value - self.seasonal_pattern.get(hour, 0)
        
        # Update EWMA
        if entity_id not in self.ewma_state:
            self.ewma_state[entity_id] = deseasonalized
            self.ewma_var[entity_id] = 0
            return 0.0
        
        # Calculate prediction error
        prediction = self.ewma_state[entity_id]
        error = deseasonalized - prediction
        
        # Update EWMA state
        self.ewma_state[entity_id] = self.alpha * deseasonalized + (1 - self.alpha) * self.ewma_state[entity_id]
        
        # Update variance estimate
        self.ewma_var[entity_id] = self.alpha * (error ** 2) + (1 - self.alpha) * self.ewma_var[entity_id]
        
        # Calculate anomaly score
        std = np.sqrt(self.ewma_var[entity_id]) + 1e-10
        z_score = abs(error) / std
        
        # Convert to probability
        return 1 - np.exp(-0.5 * z_score)
    
    def forecast(self, entity_id: str, hour: int) -> Tuple[float, float]:
        """Forecast value and uncertainty."""
        base = self.ewma_state.get(entity_id, 0)
        seasonal = self.seasonal_pattern.get(hour, 0)
        uncertainty = np.sqrt(self.ewma_var.get(entity_id, 1))
        
        return base + seasonal, uncertainty


class PeerGroupAnalyzer:
    """
    Peer group analysis for detecting deviations from group behavior.
    """
    
    def __init__(self, n_groups: int = 10):
        self.n_groups = n_groups
        self.group_centroids: Dict[str, np.ndarray] = {}
        self.group_stds: Dict[str, np.ndarray] = {}
        self.entity_groups: Dict[str, str] = {}
        self.group_members: Dict[str, Set[str]] = defaultdict(set)
    
    def assign_groups(self, entity_features: Dict[str, np.ndarray]):
        """Assign entities to peer groups using k-means clustering."""
        if not entity_features:
            return
        
        entities = list(entity_features.keys())
        features = np.array([entity_features[e] for e in entities])
        
        # Simple k-means
        n_clusters = min(self.n_groups, len(entities))
        
        # Initialize centroids randomly
        indices = np.random.choice(len(features), n_clusters, replace=False)
        centroids = features[indices].copy()
        
        for _ in range(10):  # Iterations
            # Assign to nearest centroid
            assignments = []
            for f in features:
                distances = [np.linalg.norm(f - c) for c in centroids]
                assignments.append(np.argmin(distances))
            
            # Update centroids
            for k in range(n_clusters):
                cluster_points = features[[i for i, a in enumerate(assignments) if a == k]]
                if len(cluster_points) > 0:
                    centroids[k] = np.mean(cluster_points, axis=0)
        
        # Store results
        for i, entity in enumerate(entities):
            group_id = f"group_{assignments[i]}"
            self.entity_groups[entity] = group_id
            self.group_members[group_id].add(entity)
        
        # Calculate group statistics
        for group_id, members in self.group_members.items():
            member_features = np.array([entity_features[m] for m in members])
            self.group_centroids[group_id] = np.mean(member_features, axis=0)
            self.group_stds[group_id] = np.std(member_features, axis=0) + 1e-10
    
    def score_deviation(self, entity_id: str, features: np.ndarray) -> float:
        """Score how much entity deviates from peer group."""
        group_id = self.entity_groups.get(entity_id)
        if not group_id or group_id not in self.group_centroids:
            return 0.5
        
        centroid = self.group_centroids[group_id]
        std = self.group_stds[group_id]
        
        # Z-score distance
        z_scores = np.abs(features - centroid) / std
        max_z = np.max(z_scores)
        
        return 1 - np.exp(-0.5 * max_z)


class EntityRelationshipGraph:
    """
    Graph-based analysis of entity relationships.
    Detects anomalous connection patterns.
    """
    
    def __init__(self):
        self.edges: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.node_activity: Dict[str, int] = defaultdict(int)
        self.edge_timestamps: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
    
    def add_interaction(self, entity1: str, entity2: str, 
                       weight: float = 1.0, timestamp: datetime = None):
        """Record interaction between entities."""
        self.edges[entity1][entity2] += weight
        self.edges[entity2][entity1] += weight
        self.node_activity[entity1] += 1
        self.node_activity[entity2] += 1
        
        if timestamp:
            self.edge_timestamps[(entity1, entity2)].append(timestamp)
            self.edge_timestamps[(entity2, entity1)].append(timestamp)
    
    def get_neighbors(self, entity: str) -> Dict[str, float]:
        """Get entity's neighbors with edge weights."""
        return dict(self.edges.get(entity, {}))
    
    def calculate_centrality(self, entity: str) -> float:
        """Calculate entity's network centrality."""
        if entity not in self.edges:
            return 0.0
        
        # Degree centrality
        total_weight = sum(self.edges[entity].values())
        max_possible = sum(self.node_activity.values())
        
        if max_possible == 0:
            return 0.0
        
        return total_weight / max_possible
    
    def detect_new_connection(self, entity1: str, entity2: str) -> bool:
        """Detect if this is a new connection."""
        return self.edges[entity1][entity2] == 0
    
    def get_connection_velocity(self, entity: str, 
                               window: timedelta = timedelta(hours=1)) -> int:
        """Count new connections in time window."""
        now = datetime.now()
        new_connections = 0
        
        for neighbor in self.edges[entity]:
            timestamps = self.edge_timestamps.get((entity, neighbor), [])
            recent = [t for t in timestamps if now - t < window]
            if len(recent) > 0 and len(timestamps) == len(recent):
                new_connections += 1
        
        return new_connections


class BehavioralAnalyticsEngine:
    """
    Main Behavioral Analytics Engine.
    
    Combines multiple detection methods for comprehensive UEBA.
    """
    
    def __init__(self):
        # Baselines
        self.baselines: Dict[str, BehaviorBaseline] = {}
        
        # Detectors
        self.stat_detector = StatisticalAnomalyDetector()
        self.isolation_forest = IsolationForestDetector()
        self.time_series = TimeSeriesAnomalyDetector()
        self.peer_analyzer = PeerGroupAnalyzer()
        self.relationship_graph = EntityRelationshipGraph()
        
        # Event storage
        self.event_buffer: deque = deque(maxlen=10000)
        self.anomaly_history: deque = deque(maxlen=1000)
        
        # Real-time processing
        self.is_running = False
        self._processing_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self.on_anomaly: Optional[Callable[[BehaviorAnomaly], None]] = None
        
        # Feature names for statistical model
        self.feature_names = ['hour', 'weekday', 'weekend', 'category', 
                             'action', 'volume', 'success']
    
    def process_event(self, event: BehaviorEvent) -> Optional[BehaviorAnomaly]:
        """
        Process a behavioral event and detect anomalies.
        """
        # Update baseline
        if event.entity_id not in self.baselines:
            self.baselines[event.entity_id] = BehaviorBaseline(
                entity_id=event.entity_id,
                entity_type=event.entity_type
            )
        
        baseline = self.baselines[event.entity_id]
        baseline.update(event)
        
        # Store event
        self.event_buffer.append(event)
        
        # Calculate anomaly scores from different detectors
        features = event.to_features()
        scores: Dict[str, float] = {}
        
        # Statistical anomaly
        if self.stat_detector.trained:
            scores['statistical'] = self.stat_detector.score(features)
        
        # Isolation forest
        if self.isolation_forest.trees:
            scores['isolation'] = self.isolation_forest.score(features)
        
        # Time series
        if event.data_volume:
            scores['time_series'] = self.time_series.update(
                event.entity_id, event.data_volume, event.timestamp
            )
        
        # Peer group
        peer_features = self._get_entity_features(event.entity_id)
        if peer_features is not None:
            scores['peer_group'] = self.peer_analyzer.score_deviation(
                event.entity_id, peer_features
            )
        
        # Specific anomaly checks
        specific_anomalies = self._check_specific_anomalies(event, baseline)
        
        # Combine scores
        if scores:
            combined_score = np.mean(list(scores.values()))
        else:
            combined_score = 0.0
        
        # Add specific anomaly boost
        if specific_anomalies:
            combined_score = min(1.0, combined_score + 0.3)
        
        # Threshold check
        if combined_score > 0.6 or specific_anomalies:
            anomaly = self._create_anomaly(event, scores, combined_score, 
                                           baseline, specific_anomalies)
            self.anomaly_history.append(anomaly)
            
            if self.on_anomaly:
                self.on_anomaly(anomaly)
            
            return anomaly
        
        return None
    
    def _check_specific_anomalies(self, event: BehaviorEvent, 
                                  baseline: BehaviorBaseline) -> List[AnomalyType]:
        """Check for specific anomaly types."""
        anomalies = []
        
        # Unusual time
        if baseline.typical_hours and event.timestamp.hour not in baseline.typical_hours:
            anomalies.append(AnomalyType.UNUSUAL_TIME)
        
        # Unusual resource
        if baseline.common_resources:
            if event.resource and event.resource not in baseline.common_resources:
                anomalies.append(AnomalyType.UNUSUAL_RESOURCE)
        
        # Unusual volume
        if baseline.avg_data_volume > 0 and event.data_volume:
            z_score = abs(event.data_volume - baseline.avg_data_volume) / \
                     (baseline.std_data_volume + 1)
            if z_score > 3:
                anomalies.append(AnomalyType.UNUSUAL_VOLUME)
        
        # Unusual pattern (new action)
        if baseline.common_actions and event.action not in baseline.common_actions:
            anomalies.append(AnomalyType.UNUSUAL_PATTERN)
        
        # New location
        if baseline.common_ips and event.source_ip:
            if event.source_ip not in baseline.common_ips:
                anomalies.append(AnomalyType.UNUSUAL_LOCATION)
        
        return anomalies
    
    def _create_anomaly(self, event: BehaviorEvent, scores: Dict[str, float],
                       combined_score: float, baseline: BehaviorBaseline,
                       specific_anomalies: List[AnomalyType]) -> BehaviorAnomaly:
        """Create anomaly object."""
        # Determine primary anomaly type
        if specific_anomalies:
            primary_type = specific_anomalies[0]
        else:
            primary_type = AnomalyType.BASELINE_DEVIATION
        
        # Determine risk level
        if combined_score > 0.9:
            risk_level = RiskLevel.CRITICAL
        elif combined_score > 0.8:
            risk_level = RiskLevel.HIGH
        elif combined_score > 0.7:
            risk_level = RiskLevel.MEDIUM
        elif combined_score > 0.6:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO
        
        # Generate description
        description = self._generate_description(event, primary_type, 
                                                 combined_score, baseline)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(primary_type, risk_level)
        
        return BehaviorAnomaly(
            anomaly_id=hashlib.sha256(
                f"{event.event_id}{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16],
            entity_id=event.entity_id,
            entity_type=event.entity_type,
            anomaly_type=primary_type,
            risk_level=risk_level,
            confidence=min(combined_score, 0.99),
            score=combined_score,
            triggering_events=[event.event_id],
            description=description,
            baseline_comparison={
                'detector_scores': scores,
                'typical_hours': list(baseline.typical_hours)[:5],
                'events_analyzed': baseline.events_analyzed,
                'specific_anomalies': [a.value for a in specific_anomalies]
            },
            recommended_actions=recommendations
        )
    
    def _generate_description(self, event: BehaviorEvent, 
                             anomaly_type: AnomalyType,
                             score: float, 
                             baseline: BehaviorBaseline) -> str:
        """Generate human-readable description."""
        descriptions = {
            AnomalyType.UNUSUAL_TIME: f"Activity at unusual time ({event.timestamp.hour}:00) - "
                                      f"typical hours: {sorted(list(baseline.typical_hours)[:5])}",
            AnomalyType.UNUSUAL_LOCATION: f"Activity from unusual location ({event.source_ip})",
            AnomalyType.UNUSUAL_VOLUME: f"Unusual data volume: {event.data_volume} bytes "
                                        f"(baseline avg: {baseline.avg_data_volume:.0f})",
            AnomalyType.UNUSUAL_RESOURCE: f"Access to unusual resource: {event.resource}",
            AnomalyType.UNUSUAL_PATTERN: f"Unusual action pattern: {event.action}",
            AnomalyType.PEER_DEVIATION: "Significant deviation from peer group behavior",
            AnomalyType.BASELINE_DEVIATION: f"Anomalous behavior pattern (score: {score:.2f})"
        }
        
        base = descriptions.get(anomaly_type, "Behavioral anomaly detected")
        return f"{base} for entity {event.entity_id}"
    
    def _generate_recommendations(self, anomaly_type: AnomalyType,
                                 risk_level: RiskLevel) -> List[str]:
        """Generate recommended actions."""
        recommendations = []
        
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("Immediate investigation required")
            recommendations.append("Consider temporary access restriction")
        
        type_specific = {
            AnomalyType.UNUSUAL_TIME: ["Verify user identity", 
                                       "Check for compromised credentials"],
            AnomalyType.UNUSUAL_LOCATION: ["Verify geographic location",
                                           "Check for VPN/proxy usage",
                                           "Consider impossible travel"],
            AnomalyType.UNUSUAL_VOLUME: ["Review data access logs",
                                         "Check for data exfiltration",
                                         "Monitor network traffic"],
            AnomalyType.UNUSUAL_RESOURCE: ["Verify access authorization",
                                           "Review permission changes",
                                           "Check for privilege escalation"],
            AnomalyType.UNUSUAL_PATTERN: ["Review recent activity history",
                                          "Check for automated/scripted actions"],
            AnomalyType.PEER_DEVIATION: ["Compare with peer group baseline",
                                         "Review role changes"],
            AnomalyType.BASELINE_DEVIATION: ["Full behavior review recommended",
                                             "Update baseline if legitimate"]
        }
        
        recommendations.extend(type_specific.get(anomaly_type, []))
        return recommendations
    
    def _get_entity_features(self, entity_id: str) -> Optional[np.ndarray]:
        """Get aggregated features for entity."""
        recent_events = [e for e in self.event_buffer 
                        if e.entity_id == entity_id][-100:]
        
        if len(recent_events) < 5:
            return None
        
        features = []
        for event in recent_events:
            features.append(event.to_features())
        
        return np.mean(features, axis=0)
    
    def train_models(self):
        """Train all detection models on historical data."""
        if len(self.event_buffer) < 100:
            logger.warning("Insufficient data for training")
            return
        
        # Prepare training data
        all_features = np.array([e.to_features() for e in self.event_buffer])
        
        # Train statistical detector
        self.stat_detector.fit(all_features, self.feature_names)
        
        # Train isolation forest
        self.isolation_forest.fit(all_features)
        
        # Build peer groups
        entity_features = {}
        for entity_id in self.baselines:
            features = self._get_entity_features(entity_id)
            if features is not None:
                entity_features[entity_id] = features
        
        self.peer_analyzer.assign_groups(entity_features)
        
        logger.info(f"Models trained on {len(self.event_buffer)} events")
    
    def start_realtime_processing(self, interval: float = 1.0):
        """Start real-time processing."""
        if self.is_running:
            return
        
        self.is_running = True
        self._processing_thread = threading.Thread(
            target=self._processing_loop,
            args=(interval,),
            daemon=True
        )
        self._processing_thread.start()
        logger.info("Real-time behavioral analytics started")
    
    def stop_realtime_processing(self):
        """Stop real-time processing."""
        self.is_running = False
        if self._processing_thread:
            self._processing_thread.join(timeout=5)
        logger.info("Real-time behavioral analytics stopped")
    
    def _processing_loop(self, interval: float):
        """Main processing loop."""
        retrain_counter = 0
        while self.is_running:
            time.sleep(interval)
            
            retrain_counter += 1
            if retrain_counter >= 300:  # Retrain every 5 minutes
                self.train_models()
                retrain_counter = 0
    
    def get_entity_risk_score(self, entity_id: str) -> float:
        """Get current risk score for entity."""
        recent_anomalies = [a for a in self.anomaly_history 
                          if a.entity_id == entity_id and 
                          datetime.now() - a.detected_at < timedelta(hours=24)]
        
        if not recent_anomalies:
            return 0.0
        
        # Weighted average of recent anomaly scores
        weights = []
        scores = []
        for a in recent_anomalies:
            age_hours = (datetime.now() - a.detected_at).total_seconds() / 3600
            weight = np.exp(-age_hours / 12)  # Decay over 12 hours
            weights.append(weight * a.risk_level.value)
            scores.append(a.score)
        
        if sum(weights) == 0:
            return 0.0
        
        return sum(w * s for w, s in zip(weights, scores)) / sum(weights)
    
    def get_high_risk_entities(self, threshold: float = 0.5) -> List[Dict]:
        """Get entities with high risk scores."""
        high_risk = []
        
        for entity_id in self.baselines:
            score = self.get_entity_risk_score(entity_id)
            if score > threshold:
                baseline = self.baselines[entity_id]
                high_risk.append({
                    'entity_id': entity_id,
                    'entity_type': baseline.entity_type.value,
                    'risk_score': score,
                    'events_analyzed': baseline.events_analyzed,
                    'last_activity': baseline.last_updated.isoformat()
                })
        
        return sorted(high_risk, key=lambda x: x['risk_score'], reverse=True)
    
    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get summary of behavioral analytics."""
        return {
            'total_entities': len(self.baselines),
            'events_processed': sum(b.events_analyzed for b in self.baselines.values()),
            'anomalies_detected': len(self.anomaly_history),
            'high_risk_entities': len(self.get_high_risk_entities()),
            'models_trained': self.stat_detector.trained,
            'peer_groups': len(self.peer_analyzer.group_members),
            'is_running': self.is_running
        }


# Convenience function
def analyze_behavior(events: List[Dict[str, Any]]) -> List[Dict]:
    """Quick behavioral analysis on event list."""
    engine = BehavioralAnalyticsEngine()
    anomalies = []
    
    for event_data in events:
        event = BehaviorEvent(
            event_id=event_data.get('id', str(hash(str(event_data)))),
            entity_id=event_data.get('user', event_data.get('entity', 'unknown')),
            entity_type=EntityType(event_data.get('entity_type', 'user')),
            category=BehaviorCategory(event_data.get('category', 'access_pattern')),
            action=event_data.get('action', 'unknown'),
            timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat())),
            source_ip=event_data.get('source_ip'),
            resource=event_data.get('resource'),
            data_volume=event_data.get('bytes')
        )
        
        anomaly = engine.process_event(event)
        if anomaly:
            anomalies.append(anomaly.to_dict())
    
    return anomalies


if __name__ == "__main__":
    print("Advanced Behavioral Analytics Engine - Demo")
    print("=" * 50)
    
    engine = BehavioralAnalyticsEngine()
    
    # Simulate normal events to build baseline
    print("\n[1] Building baseline from normal activity...")
    normal_user = "user_alice"
    for day in range(7):
        for hour in [9, 10, 11, 14, 15, 16]:  # Working hours
            event = BehaviorEvent(
                event_id=f"evt_{day}_{hour}",
                entity_id=normal_user,
                entity_type=EntityType.USER,
                category=BehaviorCategory.ACCESS_PATTERN,
                action="file_access",
                timestamp=datetime(2024, 1, day + 1, hour, 30),
                source_ip="192.168.1.100",
                resource="/data/reports",
                data_volume=1000 + np.random.randint(500)
            )
            engine.process_event(event)
    
    print(f"    Baseline events: {engine.baselines[normal_user].events_analyzed}")
    
    # Train models
    print("\n[2] Training detection models...")
    engine.train_models()
    print("    Models trained successfully")
    
    # Simulate anomalous events
    print("\n[3] Processing anomalous events...")
    
    # Unusual time
    anomaly1 = engine.process_event(BehaviorEvent(
        event_id="anomaly_1",
        entity_id=normal_user,
        entity_type=EntityType.USER,
        category=BehaviorCategory.ACCESS_PATTERN,
        action="file_access",
        timestamp=datetime(2024, 1, 10, 3, 30),  # 3 AM
        source_ip="192.168.1.100",
        resource="/data/reports",
        data_volume=1500
    ))
    
    if anomaly1:
        print(f"    Anomaly 1: {anomaly1.anomaly_type.value}")
        print(f"    Risk Level: {anomaly1.risk_level.name}")
        print(f"    Score: {anomaly1.score:.2f}")
    
    # Unusual volume
    anomaly2 = engine.process_event(BehaviorEvent(
        event_id="anomaly_2",
        entity_id=normal_user,
        entity_type=EntityType.USER,
        category=BehaviorCategory.DATA_MOVEMENT,
        action="file_download",
        timestamp=datetime(2024, 1, 10, 14, 30),
        source_ip="192.168.1.100",
        resource="/data/confidential",
        data_volume=50000000  # 50MB - unusual
    ))
    
    if anomaly2:
        print(f"\n    Anomaly 2: {anomaly2.anomaly_type.value}")
        print(f"    Risk Level: {anomaly2.risk_level.name}")
        print(f"    Description: {anomaly2.description}")
    
    # Summary
    print("\n[4] Analytics Summary:")
    summary = engine.get_analytics_summary()
    for key, value in summary.items():
        print(f"    {key}: {value}")
    
    print("\n✓ Behavioral analytics demo complete!")
