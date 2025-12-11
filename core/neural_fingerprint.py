"""
Neural Network System Fingerprinting
ML-based advanced system and service identification.
Deep learning approach to OS, service, and application fingerprinting.
"""

import asyncio
import hashlib
import math
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime
from collections import defaultdict
import random
import socket


class FingerprintType(Enum):
    """Types of fingerprints"""
    OS = auto()
    SERVICE = auto()
    APPLICATION = auto()
    HARDWARE = auto()
    NETWORK_DEVICE = auto()
    IOT_DEVICE = auto()
    CONTAINER = auto()
    CLOUD_INSTANCE = auto()


class ProbeType(Enum):
    """Types of network probes"""
    TCP_SYN = auto()
    TCP_ACK = auto()
    TCP_FIN = auto()
    TCP_XMAS = auto()
    TCP_NULL = auto()
    ICMP_ECHO = auto()
    ICMP_TIMESTAMP = auto()
    UDP = auto()
    HTTP = auto()
    HTTPS = auto()
    SSH = auto()
    SMB = auto()
    DNS = auto()


@dataclass
class ProbeResult:
    """Result from a network probe"""
    probe_type: ProbeType
    timestamp: datetime
    response_time: float  # ms
    response_data: bytes
    tcp_flags: int = 0
    ttl: int = 0
    window_size: int = 0
    tcp_options: List[Tuple[int, bytes]] = field(default_factory=list)
    mss: int = 0
    df_bit: bool = False


@dataclass
class Fingerprint:
    """System fingerprint"""
    id: str
    fingerprint_type: FingerprintType
    target: str
    confidence: float
    identification: str
    version: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    features: Dict[str, float] = field(default_factory=dict)
    probes_used: List[ProbeType] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class FingerprintDatabase:
    """Database of known fingerprints"""
    os_signatures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    service_signatures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    application_signatures: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class NeuralLayer:
    """Neural network layer for fingerprint classification"""
    
    def __init__(self, input_size: int, output_size: int, activation: str = "relu"):
        self.weights = [[random.gauss(0, 0.3) for _ in range(input_size)] 
                        for _ in range(output_size)]
        self.biases = [random.gauss(0, 0.1) for _ in range(output_size)]
        self.activation = activation
    
    def forward(self, inputs: List[float]) -> List[float]:
        """Forward pass"""
        outputs = []
        for i, (weight_row, bias) in enumerate(zip(self.weights, self.biases)):
            z = sum(w * x for w, x in zip(weight_row, inputs)) + bias
            
            # Activation
            if self.activation == "relu":
                outputs.append(max(0, z))
            elif self.activation == "sigmoid":
                outputs.append(1 / (1 + math.exp(-max(-500, min(500, z)))))
            elif self.activation == "softmax":
                outputs.append(z)  # Will apply softmax after
            else:
                outputs.append(z)
        
        # Apply softmax if needed
        if self.activation == "softmax" and outputs:
            max_val = max(outputs)
            exp_outputs = [math.exp(min(o - max_val, 10)) for o in outputs]
            total = sum(exp_outputs)
            outputs = [e / total if total > 0 else 1/len(outputs) for e in exp_outputs]
        
        return outputs
    
    def backward(self, inputs: List[float], gradients: List[float], 
                 learning_rate: float) -> List[float]:
        """Backward pass"""
        input_gradients = [0.0] * len(inputs)
        
        for i, (weight_row, grad) in enumerate(zip(self.weights, gradients)):
            for j in range(len(weight_row)):
                input_gradients[j] += weight_row[j] * grad
                self.weights[i][j] -= learning_rate * grad * inputs[j]
            self.biases[i] -= learning_rate * grad
        
        return input_gradients


class FingerprintClassifier:
    """Neural network classifier for fingerprints"""
    
    def __init__(self, feature_size: int = 128, num_classes: int = 50):
        self.layer1 = NeuralLayer(feature_size, 256, "relu")
        self.layer2 = NeuralLayer(256, 128, "relu")
        self.layer3 = NeuralLayer(128, 64, "relu")
        self.layer4 = NeuralLayer(64, num_classes, "softmax")
        
        self.learning_rate = 0.001
        self.class_labels: List[str] = []
    
    def predict(self, features: List[float]) -> Tuple[int, float, List[float]]:
        """Predict class from features"""
        h1 = self.layer1.forward(features)
        h2 = self.layer2.forward(h1)
        h3 = self.layer3.forward(h2)
        output = self.layer4.forward(h3)
        
        max_idx = output.index(max(output))
        confidence = output[max_idx]
        
        return max_idx, confidence, output
    
    def train(self, features: List[float], target_class: int):
        """Train on single sample"""
        # Forward pass
        h1 = self.layer1.forward(features)
        h2 = self.layer2.forward(h1)
        h3 = self.layer3.forward(h2)
        output = self.layer4.forward(h3)
        
        # Compute gradients (cross-entropy loss)
        target = [0.0] * len(output)
        if target_class < len(target):
            target[target_class] = 1.0
        
        output_grads = [o - t for o, t in zip(output, target)]
        
        # Backward pass
        h3_grads = self.layer4.backward(h3, output_grads, self.learning_rate)
        h2_grads = self.layer3.backward(h2, h3_grads, self.learning_rate)
        h1_grads = self.layer2.backward(h1, h2_grads, self.learning_rate)
        self.layer1.backward(features, h1_grads, self.learning_rate)
    
    def get_class_label(self, class_idx: int) -> str:
        """Get class label"""
        if class_idx < len(self.class_labels):
            return self.class_labels[class_idx]
        return f"Unknown-{class_idx}"
    
    def add_class(self, label: str) -> int:
        """Add new class"""
        if label not in self.class_labels:
            self.class_labels.append(label)
        return self.class_labels.index(label)


class FeatureExtractor:
    """Extract features from probe results"""
    
    def __init__(self):
        self.feature_names: List[str] = []
    
    def extract_tcp_features(self, probe: ProbeResult) -> Dict[str, float]:
        """Extract TCP-related features"""
        features = {
            "ttl": probe.ttl / 255.0,
            "ttl_category": self._categorize_ttl(probe.ttl),
            "window_size": probe.window_size / 65535.0,
            "window_category": self._categorize_window(probe.window_size),
            "mss": probe.mss / 1500.0 if probe.mss else 0,
            "df_bit": 1.0 if probe.df_bit else 0.0,
            "response_time": min(probe.response_time / 1000.0, 1.0),
        }
        
        # TCP flags features
        features["flag_syn"] = 1.0 if probe.tcp_flags & 0x02 else 0.0
        features["flag_ack"] = 1.0 if probe.tcp_flags & 0x10 else 0.0
        features["flag_rst"] = 1.0 if probe.tcp_flags & 0x04 else 0.0
        features["flag_fin"] = 1.0 if probe.tcp_flags & 0x01 else 0.0
        features["flag_psh"] = 1.0 if probe.tcp_flags & 0x08 else 0.0
        
        # TCP options features
        for opt_kind, opt_data in probe.tcp_options:
            features[f"tcp_opt_{opt_kind}"] = 1.0
        
        return features
    
    def extract_timing_features(self, probes: List[ProbeResult]) -> Dict[str, float]:
        """Extract timing-based features"""
        if not probes:
            return {}
        
        times = [p.response_time for p in probes]
        
        return {
            "timing_mean": sum(times) / len(times) / 1000.0,
            "timing_min": min(times) / 1000.0,
            "timing_max": max(times) / 1000.0,
            "timing_std": self._std_dev(times) / 1000.0,
            "timing_variance": self._variance(times) / 1000000.0,
        }
    
    def extract_banner_features(self, banner: bytes) -> Dict[str, float]:
        """Extract features from service banner"""
        if not banner:
            return {"banner_length": 0}
        
        banner_str = banner.decode('utf-8', errors='ignore').lower()
        
        features = {
            "banner_length": len(banner) / 1000.0,
            "has_version": 1.0 if any(v in banner_str for v in ['version', 'ver', 'v.']) else 0.0,
            "has_os_hint": 1.0 if any(os in banner_str for os in ['linux', 'windows', 'unix', 'freebsd']) else 0.0,
        }
        
        # Common software indicators
        software_hints = ['apache', 'nginx', 'iis', 'openssh', 'mysql', 'postgresql', 
                         'microsoft', 'ubuntu', 'debian', 'centos', 'redhat']
        for sw in software_hints:
            features[f"hint_{sw}"] = 1.0 if sw in banner_str else 0.0
        
        return features
    
    def extract_http_features(self, response: bytes) -> Dict[str, float]:
        """Extract HTTP response features"""
        if not response:
            return {}
        
        response_str = response.decode('utf-8', errors='ignore')
        lines = response_str.split('\n')
        headers = {}
        
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        features = {
            "http_status": self._extract_http_status(lines[0] if lines else ""),
            "has_server_header": 1.0 if "server" in headers else 0.0,
            "has_powered_by": 1.0 if "x-powered-by" in headers else 0.0,
            "header_count": len(headers) / 50.0,
            "content_length": float(headers.get("content-length", 0)) / 100000.0,
        }
        
        # Server header analysis
        server = headers.get("server", "").lower()
        for sw in ['apache', 'nginx', 'iis', 'lighttpd', 'cloudflare']:
            features[f"server_{sw}"] = 1.0 if sw in server else 0.0
        
        return features
    
    def _categorize_ttl(self, ttl: int) -> float:
        """Categorize TTL value"""
        if ttl <= 32:
            return 0.0
        elif ttl <= 64:
            return 0.25  # Linux/macOS
        elif ttl <= 128:
            return 0.5  # Windows
        elif ttl <= 255:
            return 0.75  # Network devices
        return 1.0
    
    def _categorize_window(self, window: int) -> float:
        """Categorize window size"""
        if window < 1000:
            return 0.1
        elif window < 10000:
            return 0.3
        elif window < 30000:
            return 0.5
        elif window < 50000:
            return 0.7
        return 0.9
    
    def _std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)
    
    def _variance(self, values: List[float]) -> float:
        """Calculate variance"""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)
    
    def _extract_http_status(self, status_line: str) -> float:
        """Extract HTTP status code as feature"""
        try:
            parts = status_line.split()
            if len(parts) >= 2:
                code = int(parts[1])
                return code / 600.0
        except (ValueError, IndexError):
            pass
        return 0.0
    
    def to_vector(self, features: Dict[str, float], size: int = 128) -> List[float]:
        """Convert features dict to fixed-size vector"""
        vector = [0.0] * size
        
        sorted_items = sorted(features.items())
        for i, (key, value) in enumerate(sorted_items):
            if i < size:
                try:
                    vector[i] = float(value)
                except (ValueError, TypeError):
                    vector[i] = 0.0
        
        return vector


class ProbeEngine:
    """Network probing engine"""
    
    def __init__(self):
        self.timeout = 3.0
        self.retry_count = 2
    
    async def tcp_syn_probe(self, target: str, port: int) -> Optional[ProbeResult]:
        """Send TCP SYN probe"""
        start_time = datetime.now()
        
        try:
            # Simulated probe (actual implementation would use raw sockets)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            end_time = datetime.now()
            
            response_time = (end_time - start_time).total_seconds() * 1000
            
            sock.close()
            
            return ProbeResult(
                probe_type=ProbeType.TCP_SYN,
                timestamp=start_time,
                response_time=response_time,
                response_data=b"",
                tcp_flags=0x12 if result == 0 else 0x14,  # SYN-ACK or RST-ACK
                ttl=64,  # Simulated
                window_size=65535
            )
        except socket.timeout:
            return None
        except Exception:
            return None
    
    async def http_probe(self, target: str, port: int = 80, 
                          use_ssl: bool = False) -> Optional[ProbeResult]:
        """Send HTTP probe"""
        start_time = datetime.now()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(4096)
            end_time = datetime.now()
            
            sock.close()
            
            return ProbeResult(
                probe_type=ProbeType.HTTPS if use_ssl else ProbeType.HTTP,
                timestamp=start_time,
                response_time=(end_time - start_time).total_seconds() * 1000,
                response_data=response
            )
        except Exception:
            return None
    
    async def banner_grab(self, target: str, port: int, 
                           probe_data: bytes = b"") -> Optional[bytes]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            if probe_data:
                sock.send(probe_data)
            
            banner = sock.recv(1024)
            sock.close()
            
            return banner
        except Exception:
            return None


class NeuralFingerprinter:
    """Main neural network fingerprinting engine"""
    
    def __init__(self, config, db):
        self.config = config
        self.db = db
        
        self.os_classifier = FingerprintClassifier(128, 50)
        self.service_classifier = FingerprintClassifier(128, 100)
        self.feature_extractor = FeatureExtractor()
        self.probe_engine = ProbeEngine()
        
        self.fingerprint_db = self._init_fingerprint_db()
        self.results: Dict[str, Fingerprint] = {}
        
        # Initialize class labels
        self._init_class_labels()
    
    def _init_fingerprint_db(self) -> FingerprintDatabase:
        """Initialize fingerprint database"""
        db = FingerprintDatabase()
        
        # OS signatures
        db.os_signatures = {
            "linux": {
                "ttl_range": (60, 64),
                "window_sizes": [5840, 14600, 29200, 65535],
                "mss": 1460,
                "tcp_options": [2, 4, 8, 1, 3]
            },
            "windows": {
                "ttl_range": (126, 128),
                "window_sizes": [8192, 16384, 65535],
                "mss": 1460,
                "tcp_options": [2, 1, 3, 1, 1, 4]
            },
            "freebsd": {
                "ttl_range": (62, 64),
                "window_sizes": [65535],
                "mss": 1460,
                "tcp_options": [2, 4, 8, 1, 3]
            },
            "macos": {
                "ttl_range": (62, 64),
                "window_sizes": [65535],
                "mss": 1460,
                "tcp_options": [2, 4, 8, 1, 3]
            },
        }
        
        return db
    
    def _init_class_labels(self):
        """Initialize classifier labels"""
        os_labels = [
            "Linux 2.6", "Linux 3.x", "Linux 4.x", "Linux 5.x",
            "Windows XP", "Windows 7", "Windows 8", "Windows 10", "Windows 11",
            "Windows Server 2008", "Windows Server 2012", "Windows Server 2016", "Windows Server 2019",
            "FreeBSD", "OpenBSD", "NetBSD",
            "macOS", "iOS", "Android",
            "Cisco IOS", "Juniper JUNOS",
            "ESXi", "VMware",
            "Unknown"
        ]
        
        for label in os_labels:
            self.os_classifier.add_class(label)
        
        service_labels = [
            "Apache httpd", "nginx", "Microsoft IIS", "lighttpd",
            "OpenSSH", "Dropbear SSH",
            "MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle",
            "Postfix", "Exim", "Microsoft Exchange",
            "BIND", "dnsmasq",
            "vsftpd", "ProFTPD", "Microsoft FTP",
            "Samba", "Windows SMB",
            "Unknown"
        ]
        
        for label in service_labels:
            self.service_classifier.add_class(label)
    
    async def fingerprint_host(self, target: str, 
                                ports: List[int] = None) -> Dict[str, Any]:
        """Perform comprehensive host fingerprinting"""
        ports = ports or [22, 80, 443, 445, 3389]
        
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "os_fingerprint": None,
            "services": [],
            "probes_sent": 0,
            "confidence_score": 0.0
        }
        
        all_probes = []
        
        # Probe each port
        for port in ports:
            # TCP SYN probe
            syn_result = await self.probe_engine.tcp_syn_probe(target, port)
            if syn_result:
                all_probes.append(syn_result)
                results["probes_sent"] += 1
            
            # Service identification
            banner = await self.probe_engine.banner_grab(target, port)
            if banner:
                service = await self._identify_service(target, port, banner, syn_result)
                if service:
                    results["services"].append(service)
        
        # HTTP probes for common web ports
        for port in [80, 443, 8080, 8443]:
            if port in ports:
                http_result = await self.probe_engine.http_probe(target, port)
                if http_result:
                    all_probes.append(http_result)
        
        # OS fingerprinting from all probes
        if all_probes:
            os_fp = await self._identify_os(target, all_probes)
            results["os_fingerprint"] = os_fp
            results["confidence_score"] = os_fp.get("confidence", 0) if os_fp else 0
        
        return results
    
    async def _identify_os(self, target: str, 
                           probes: List[ProbeResult]) -> Dict[str, Any]:
        """Identify OS from probe results"""
        # Extract features
        all_features = {}
        
        for probe in probes:
            tcp_features = self.feature_extractor.extract_tcp_features(probe)
            all_features.update(tcp_features)
        
        timing_features = self.feature_extractor.extract_timing_features(probes)
        all_features.update(timing_features)
        
        # Convert to vector
        feature_vector = self.feature_extractor.to_vector(all_features)
        
        # Classify
        class_idx, confidence, probabilities = self.os_classifier.predict(feature_vector)
        predicted_os = self.os_classifier.get_class_label(class_idx)
        
        # Also check signature matching
        signature_match = self._match_os_signature(probes)
        
        # Combine results
        final_confidence = confidence
        if signature_match and signature_match[0] == predicted_os:
            final_confidence = min(0.99, confidence + 0.1)
        
        fingerprint = Fingerprint(
            id=hashlib.md5(f"{target}{datetime.now()}".encode()).hexdigest()[:12],
            fingerprint_type=FingerprintType.OS,
            target=target,
            confidence=final_confidence,
            identification=predicted_os,
            details={
                "signature_match": signature_match,
                "top_predictions": self._get_top_predictions(probabilities, 3)
            },
            features=all_features,
            probes_used=[p.probe_type for p in probes]
        )
        
        self.results[fingerprint.id] = fingerprint
        
        return {
            "os": predicted_os,
            "confidence": final_confidence,
            "fingerprint_id": fingerprint.id,
            "details": fingerprint.details
        }
    
    async def _identify_service(self, target: str, port: int, 
                                 banner: bytes, tcp_probe: ProbeResult = None) -> Dict[str, Any]:
        """Identify service from banner"""
        # Extract banner features
        banner_features = self.feature_extractor.extract_banner_features(banner)
        
        if tcp_probe:
            tcp_features = self.feature_extractor.extract_tcp_features(tcp_probe)
            banner_features.update(tcp_features)
        
        # Convert to vector
        feature_vector = self.feature_extractor.to_vector(banner_features)
        
        # Classify
        class_idx, confidence, probabilities = self.service_classifier.predict(feature_vector)
        predicted_service = self.service_classifier.get_class_label(class_idx)
        
        # Extract version from banner if possible
        version = self._extract_version(banner)
        
        fingerprint = Fingerprint(
            id=hashlib.md5(f"{target}{port}{datetime.now()}".encode()).hexdigest()[:12],
            fingerprint_type=FingerprintType.SERVICE,
            target=f"{target}:{port}",
            confidence=confidence,
            identification=predicted_service,
            version=version,
            details={"banner": banner.decode('utf-8', errors='ignore')[:200]},
            features=banner_features
        )
        
        self.results[fingerprint.id] = fingerprint
        
        return {
            "port": port,
            "service": predicted_service,
            "version": version,
            "confidence": confidence,
            "banner_preview": banner[:100].decode('utf-8', errors='ignore'),
            "fingerprint_id": fingerprint.id
        }
    
    def _match_os_signature(self, probes: List[ProbeResult]) -> Optional[Tuple[str, float]]:
        """Match probes against OS signature database"""
        best_match = None
        best_score = 0.0
        
        for os_name, signature in self.fingerprint_db.os_signatures.items():
            score = 0.0
            matches = 0
            
            for probe in probes:
                # TTL match
                ttl_min, ttl_max = signature.get("ttl_range", (0, 255))
                if ttl_min <= probe.ttl <= ttl_max:
                    score += 0.3
                    matches += 1
                
                # Window size match
                if probe.window_size in signature.get("window_sizes", []):
                    score += 0.3
                    matches += 1
                
                # MSS match
                if probe.mss == signature.get("mss", 0):
                    score += 0.2
                    matches += 1
            
            if matches > 0:
                avg_score = score / matches
                if avg_score > best_score:
                    best_score = avg_score
                    best_match = os_name
        
        if best_match and best_score > 0.5:
            return (best_match, best_score)
        return None
    
    def _extract_version(self, banner: bytes) -> Optional[str]:
        """Extract version from banner"""
        import re
        
        banner_str = banner.decode('utf-8', errors='ignore')
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',  # X.Y.Z
            r'(\d+\.\d+)',  # X.Y
            r'version[:\s]+(\S+)',  # version: X
            r'v(\d+[\d.]+)',  # vX.Y.Z
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner_str, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _get_top_predictions(self, probabilities: List[float], n: int = 3) -> List[Dict]:
        """Get top N predictions"""
        indexed = [(i, p) for i, p in enumerate(probabilities)]
        sorted_preds = sorted(indexed, key=lambda x: x[1], reverse=True)[:n]
        
        return [
            {
                "class": self.os_classifier.get_class_label(idx),
                "probability": prob
            }
            for idx, prob in sorted_preds
        ]
    
    def train_on_sample(self, fingerprint_type: FingerprintType,
                        features: Dict[str, float], label: str):
        """Train classifier on new sample"""
        feature_vector = self.feature_extractor.to_vector(features)
        
        if fingerprint_type == FingerprintType.OS:
            class_idx = self.os_classifier.add_class(label)
            self.os_classifier.train(feature_vector, class_idx)
        elif fingerprint_type == FingerprintType.SERVICE:
            class_idx = self.service_classifier.add_class(label)
            self.service_classifier.train(feature_vector, class_idx)
    
    def export_model(self) -> Dict[str, Any]:
        """Export trained model"""
        return {
            "os_labels": self.os_classifier.class_labels,
            "service_labels": self.service_classifier.class_labels,
            "fingerprint_db": {
                "os": self.fingerprint_db.os_signatures,
                "services": self.fingerprint_db.service_signatures
            }
        }
    
    def get_fingerprint_stats(self) -> Dict[str, Any]:
        """Get fingerprinting statistics"""
        return {
            "total_fingerprints": len(self.results),
            "os_classes": len(self.os_classifier.class_labels),
            "service_classes": len(self.service_classifier.class_labels),
            "by_type": {
                fp_type.name: sum(1 for fp in self.results.values() 
                                  if fp.fingerprint_type == fp_type)
                for fp_type in FingerprintType
            }
        }
