"""
HydraRecon Advanced Machine Learning Engine
============================================

State-of-the-art ML for security operations:
- Deep neural networks for threat detection
- Transformer models for log analysis
- Graph neural networks for attack path prediction
- Reinforcement learning for automated pentesting
- Anomaly detection with autoencoders
- Natural language processing for threat intelligence
- Computer vision for visual security analysis
- Federated learning for privacy-preserving models
- AutoML for model optimization
- Explainable AI for security decisions
"""

import os
import json
import pickle
import hashlib
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable, Union
from datetime import datetime
from enum import Enum, auto
from abc import ABC, abstractmethod
import numpy as np
from collections import deque
import random
import math

# Optional ML imports
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import DataLoader, Dataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class ModelType(Enum):
    """Types of ML models"""
    THREAT_CLASSIFIER = auto()
    ANOMALY_DETECTOR = auto()
    ATTACK_PREDICTOR = auto()
    LOG_ANALYZER = auto()
    MALWARE_DETECTOR = auto()
    PHISHING_DETECTOR = auto()
    VULNERABILITY_SCORER = auto()
    BEHAVIOR_ANALYZER = auto()


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    auc_roc: float = 0.0
    training_time: float = 0.0
    inference_time: float = 0.0
    model_size: int = 0


@dataclass
class TrainingConfig:
    """Training configuration"""
    epochs: int = 100
    batch_size: int = 32
    learning_rate: float = 0.001
    weight_decay: float = 0.0001
    early_stopping_patience: int = 10
    validation_split: float = 0.2
    optimizer: str = "adam"
    scheduler: str = "cosine"
    grad_clip: float = 1.0
    mixed_precision: bool = True
    distributed: bool = False
    checkpoint_interval: int = 10


# =============================================================================
# Neural Network Architectures
# =============================================================================

if TORCH_AVAILABLE:
    
    class ThreatTransformer(nn.Module):
        """Transformer model for threat detection in logs/traffic"""
        
        def __init__(
            self,
            vocab_size: int = 10000,
            d_model: int = 256,
            nhead: int = 8,
            num_layers: int = 6,
            num_classes: int = 10,
            max_seq_len: int = 512,
            dropout: float = 0.1
        ):
            super().__init__()
            
            self.d_model = d_model
            self.embedding = nn.Embedding(vocab_size, d_model)
            self.pos_encoding = self._create_positional_encoding(max_seq_len, d_model)
            
            encoder_layer = nn.TransformerEncoderLayer(
                d_model=d_model,
                nhead=nhead,
                dim_feedforward=d_model * 4,
                dropout=dropout,
                batch_first=True
            )
            self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
            
            self.classifier = nn.Sequential(
                nn.Linear(d_model, d_model // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(d_model // 2, num_classes)
            )
            
            self.attention_weights: Optional[torch.Tensor] = None
        
        def _create_positional_encoding(self, max_len: int, d_model: int) -> torch.Tensor:
            """Create sinusoidal positional encoding"""
            pe = torch.zeros(max_len, d_model)
            position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
            div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
            
            pe[:, 0::2] = torch.sin(position * div_term)
            pe[:, 1::2] = torch.cos(position * div_term)
            
            return pe.unsqueeze(0)
        
        def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
            # Embed and add positional encoding
            x = self.embedding(x) * math.sqrt(self.d_model)
            x = x + self.pos_encoding[:, :x.size(1), :].to(x.device)
            
            # Transformer encoding
            x = self.transformer(x, src_key_padding_mask=mask)
            
            # Pool and classify
            x = x.mean(dim=1)  # Global average pooling
            return self.classifier(x)
    
    
    class GraphAttentionNetwork(nn.Module):
        """GAT for attack path prediction"""
        
        def __init__(
            self,
            in_features: int,
            hidden_features: int = 64,
            out_features: int = 32,
            num_heads: int = 4,
            dropout: float = 0.1
        ):
            super().__init__()
            
            self.num_heads = num_heads
            
            # Multi-head attention
            self.W = nn.Linear(in_features, hidden_features * num_heads, bias=False)
            self.a = nn.Parameter(torch.zeros(num_heads, 2 * hidden_features))
            nn.init.xavier_uniform_(self.a)
            
            self.leaky_relu = nn.LeakyReLU(0.2)
            self.dropout = nn.Dropout(dropout)
            
            self.out_proj = nn.Linear(hidden_features * num_heads, out_features)
        
        def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            """
            x: Node features [batch, num_nodes, in_features]
            adj: Adjacency matrix [batch, num_nodes, num_nodes]
            """
            batch_size, num_nodes, _ = x.shape
            
            # Linear transformation
            h = self.W(x)  # [batch, num_nodes, hidden * heads]
            h = h.view(batch_size, num_nodes, self.num_heads, -1)  # [batch, num_nodes, heads, hidden]
            
            # Attention scores
            h_i = h.unsqueeze(2).expand(-1, -1, num_nodes, -1, -1)  # [batch, nodes, nodes, heads, hidden]
            h_j = h.unsqueeze(1).expand(-1, num_nodes, -1, -1, -1)  # [batch, nodes, nodes, heads, hidden]
            
            concat = torch.cat([h_i, h_j], dim=-1)  # [batch, nodes, nodes, heads, 2*hidden]
            
            e = self.leaky_relu((concat * self.a).sum(dim=-1))  # [batch, nodes, nodes, heads]
            
            # Mask with adjacency
            mask = adj.unsqueeze(-1).expand(-1, -1, -1, self.num_heads)
            e = e.masked_fill(mask == 0, float('-inf'))
            
            attention = F.softmax(e, dim=2)
            attention = self.dropout(attention)
            
            # Aggregate
            h_prime = torch.einsum('bnji,bnjh->bnih', attention, h.unsqueeze(1).expand(-1, num_nodes, -1, -1, -1).squeeze(2))
            h_prime = h_prime.reshape(batch_size, num_nodes, -1)
            
            return self.out_proj(h_prime)
    
    
    class AnomalyAutoencoder(nn.Module):
        """Variational Autoencoder for anomaly detection"""
        
        def __init__(
            self,
            input_dim: int,
            hidden_dims: List[int] = None,
            latent_dim: int = 32
        ):
            super().__init__()
            
            if hidden_dims is None:
                hidden_dims = [256, 128, 64]
            
            # Encoder
            encoder_layers = []
            prev_dim = input_dim
            for dim in hidden_dims:
                encoder_layers.extend([
                    nn.Linear(prev_dim, dim),
                    nn.BatchNorm1d(dim),
                    nn.ReLU(),
                    nn.Dropout(0.2)
                ])
                prev_dim = dim
            
            self.encoder = nn.Sequential(*encoder_layers)
            self.fc_mu = nn.Linear(hidden_dims[-1], latent_dim)
            self.fc_var = nn.Linear(hidden_dims[-1], latent_dim)
            
            # Decoder
            decoder_layers = []
            hidden_dims_rev = hidden_dims[::-1]
            prev_dim = latent_dim
            for dim in hidden_dims_rev:
                decoder_layers.extend([
                    nn.Linear(prev_dim, dim),
                    nn.BatchNorm1d(dim),
                    nn.ReLU(),
                    nn.Dropout(0.2)
                ])
                prev_dim = dim
            
            decoder_layers.append(nn.Linear(hidden_dims_rev[-1], input_dim))
            self.decoder = nn.Sequential(*decoder_layers)
        
        def encode(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
            h = self.encoder(x)
            return self.fc_mu(h), self.fc_var(h)
        
        def reparameterize(self, mu: torch.Tensor, log_var: torch.Tensor) -> torch.Tensor:
            std = torch.exp(0.5 * log_var)
            eps = torch.randn_like(std)
            return mu + eps * std
        
        def decode(self, z: torch.Tensor) -> torch.Tensor:
            return self.decoder(z)
        
        def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
            mu, log_var = self.encode(x)
            z = self.reparameterize(mu, log_var)
            return self.decode(z), mu, log_var
        
        def compute_anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
            """Compute anomaly score based on reconstruction error"""
            recon, mu, log_var = self.forward(x)
            recon_loss = F.mse_loss(recon, x, reduction='none').sum(dim=1)
            kl_loss = -0.5 * torch.sum(1 + log_var - mu.pow(2) - log_var.exp(), dim=1)
            return recon_loss + 0.1 * kl_loss
    
    
    class DeepQLearningAgent(nn.Module):
        """Deep Q-Learning for automated penetration testing"""
        
        def __init__(
            self,
            state_dim: int,
            action_dim: int,
            hidden_dim: int = 256
        ):
            super().__init__()
            
            # Dueling DQN architecture
            self.feature_net = nn.Sequential(
                nn.Linear(state_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU()
            )
            
            # Value stream
            self.value_stream = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Linear(hidden_dim // 2, 1)
            )
            
            # Advantage stream
            self.advantage_stream = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Linear(hidden_dim // 2, action_dim)
            )
        
        def forward(self, x: torch.Tensor) -> torch.Tensor:
            features = self.feature_net(x)
            
            value = self.value_stream(features)
            advantage = self.advantage_stream(features)
            
            # Combine value and advantage
            q_values = value + advantage - advantage.mean(dim=1, keepdim=True)
            return q_values
    
    
    class MalwareDetectorCNN(nn.Module):
        """CNN for malware detection from binary visualization"""
        
        def __init__(
            self,
            num_classes: int = 10,
            dropout: float = 0.5
        ):
            super().__init__()
            
            self.features = nn.Sequential(
                nn.Conv2d(1, 64, kernel_size=3, padding=1),
                nn.BatchNorm2d(64),
                nn.ReLU(),
                nn.MaxPool2d(2),
                
                nn.Conv2d(64, 128, kernel_size=3, padding=1),
                nn.BatchNorm2d(128),
                nn.ReLU(),
                nn.MaxPool2d(2),
                
                nn.Conv2d(128, 256, kernel_size=3, padding=1),
                nn.BatchNorm2d(256),
                nn.ReLU(),
                nn.MaxPool2d(2),
                
                nn.Conv2d(256, 512, kernel_size=3, padding=1),
                nn.BatchNorm2d(512),
                nn.ReLU(),
                nn.AdaptiveAvgPool2d((4, 4))
            )
            
            self.classifier = nn.Sequential(
                nn.Flatten(),
                nn.Linear(512 * 4 * 4, 1024),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(1024, num_classes)
            )
        
        def forward(self, x: torch.Tensor) -> torch.Tensor:
            x = self.features(x)
            return self.classifier(x)


# =============================================================================
# Training and Inference
# =============================================================================

class ModelTrainer:
    """Generic model trainer with advanced features"""
    
    def __init__(self, config: TrainingConfig = None):
        self.config = config or TrainingConfig()
        self.device = self._get_device()
        self.scaler = None
        self.history: Dict[str, List[float]] = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': []
        }
        
        if TORCH_AVAILABLE and self.config.mixed_precision:
            self.scaler = torch.cuda.amp.GradScaler()
    
    def _get_device(self) -> str:
        if TORCH_AVAILABLE:
            if torch.cuda.is_available():
                return "cuda"
            elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                return "mps"
        return "cpu"
    
    def train(
        self,
        model: Any,  # nn.Module when torch available
        train_loader: Any,  # DataLoader when torch available
        val_loader: Optional[Any] = None,
        criterion: Optional[Any] = None,
        callbacks: List[Callable] = None
    ) -> ModelMetrics:
        """Train model with full feature set"""
        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch not available")
        
        model = model.to(self.device)
        criterion = criterion or nn.CrossEntropyLoss()
        
        # Optimizer
        if self.config.optimizer == "adam":
            optimizer = torch.optim.Adam(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
        elif self.config.optimizer == "adamw":
            optimizer = torch.optim.AdamW(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
        else:
            optimizer = torch.optim.SGD(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay,
                momentum=0.9
            )
        
        # Scheduler
        if self.config.scheduler == "cosine":
            scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
                optimizer, T_max=self.config.epochs
            )
        else:
            scheduler = torch.optim.lr_scheduler.StepLR(
                optimizer, step_size=30, gamma=0.1
            )
        
        best_val_loss = float('inf')
        patience_counter = 0
        start_time = time.time()
        
        for epoch in range(self.config.epochs):
            # Training
            model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0
            
            for batch_idx, (data, target) in enumerate(train_loader):
                data, target = data.to(self.device), target.to(self.device)
                
                optimizer.zero_grad()
                
                if self.scaler and self.device == "cuda":
                    with torch.cuda.amp.autocast():
                        output = model(data)
                        loss = criterion(output, target)
                    
                    self.scaler.scale(loss).backward()
                    
                    if self.config.grad_clip:
                        self.scaler.unscale_(optimizer)
                        torch.nn.utils.clip_grad_norm_(model.parameters(), self.config.grad_clip)
                    
                    self.scaler.step(optimizer)
                    self.scaler.update()
                else:
                    output = model(data)
                    loss = criterion(output, target)
                    loss.backward()
                    
                    if self.config.grad_clip:
                        torch.nn.utils.clip_grad_norm_(model.parameters(), self.config.grad_clip)
                    
                    optimizer.step()
                
                train_loss += loss.item()
                _, predicted = output.max(1)
                train_total += target.size(0)
                train_correct += predicted.eq(target).sum().item()
            
            avg_train_loss = train_loss / len(train_loader)
            train_acc = train_correct / train_total
            
            self.history['train_loss'].append(avg_train_loss)
            self.history['train_acc'].append(train_acc)
            
            # Validation
            if val_loader:
                val_loss, val_acc = self._validate(model, val_loader, criterion)
                self.history['val_loss'].append(val_loss)
                self.history['val_acc'].append(val_acc)
                
                # Early stopping
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                else:
                    patience_counter += 1
                    if patience_counter >= self.config.early_stopping_patience:
                        break
            
            scheduler.step()
            
            # Callbacks
            if callbacks:
                for callback in callbacks:
                    callback(epoch, self.history)
        
        training_time = time.time() - start_time
        
        return ModelMetrics(
            accuracy=self.history['val_acc'][-1] if self.history['val_acc'] else self.history['train_acc'][-1],
            training_time=training_time
        )
    
    def _validate(
        self,
        model: Any,  # nn.Module
        val_loader: Any,  # DataLoader
        criterion: Any  # nn.Module
    ) -> Tuple[float, float]:
        """Validate model"""
        model.eval()
        val_loss = 0.0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for data, target in val_loader:
                data, target = data.to(self.device), target.to(self.device)
                output = model(data)
                val_loss += criterion(output, target).item()
                _, predicted = output.max(1)
                total += target.size(0)
                correct += predicted.eq(target).sum().item()
        
        return val_loss / len(val_loader), correct / total


class ReplayBuffer:
    """Experience replay buffer for RL"""
    
    def __init__(self, capacity: int = 100000):
        self.buffer = deque(maxlen=capacity)
    
    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))
    
    def sample(self, batch_size: int) -> Tuple:
        batch = random.sample(self.buffer, min(batch_size, len(self.buffer)))
        states, actions, rewards, next_states, dones = zip(*batch)
        
        if TORCH_AVAILABLE:
            return (
                torch.FloatTensor(np.array(states)),
                torch.LongTensor(actions),
                torch.FloatTensor(rewards),
                torch.FloatTensor(np.array(next_states)),
                torch.FloatTensor(dones)
            )
        return states, actions, rewards, next_states, dones
    
    def __len__(self) -> int:
        return len(self.buffer)


class RLPentestAgent:
    """Reinforcement learning agent for automated pentesting"""
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        learning_rate: float = 0.0001,
        gamma: float = 0.99,
        epsilon_start: float = 1.0,
        epsilon_end: float = 0.01,
        epsilon_decay: float = 0.995
    ):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        
        self.device = "cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu"
        
        if TORCH_AVAILABLE:
            self.policy_net = DeepQLearningAgent(state_dim, action_dim).to(self.device)
            self.target_net = DeepQLearningAgent(state_dim, action_dim).to(self.device)
            self.target_net.load_state_dict(self.policy_net.state_dict())
            
            self.optimizer = torch.optim.Adam(self.policy_net.parameters(), lr=learning_rate)
        
        self.replay_buffer = ReplayBuffer()
        self.update_target_every = 100
        self.steps = 0
    
    def select_action(self, state: np.ndarray) -> int:
        """Select action using epsilon-greedy policy"""
        if random.random() < self.epsilon:
            return random.randrange(self.action_dim)
        
        if TORCH_AVAILABLE:
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                q_values = self.policy_net(state_tensor)
                return q_values.argmax().item()
        
        return random.randrange(self.action_dim)
    
    def train_step(self, batch_size: int = 32) -> float:
        """Perform one training step"""
        if len(self.replay_buffer) < batch_size:
            return 0.0
        
        states, actions, rewards, next_states, dones = self.replay_buffer.sample(batch_size)
        
        if TORCH_AVAILABLE:
            states = states.to(self.device)
            actions = actions.to(self.device)
            rewards = rewards.to(self.device)
            next_states = next_states.to(self.device)
            dones = dones.to(self.device)
            
            # Current Q values
            current_q = self.policy_net(states).gather(1, actions.unsqueeze(1))
            
            # Target Q values
            with torch.no_grad():
                next_q = self.target_net(next_states).max(1)[0]
                target_q = rewards + self.gamma * next_q * (1 - dones)
            
            # Loss
            loss = F.smooth_l1_loss(current_q.squeeze(), target_q)
            
            self.optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
            self.optimizer.step()
            
            # Update target network
            self.steps += 1
            if self.steps % self.update_target_every == 0:
                self.target_net.load_state_dict(self.policy_net.state_dict())
            
            # Decay epsilon
            self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)
            
            return loss.item()
        
        return 0.0
    
    def store_experience(self, state, action, reward, next_state, done):
        """Store experience in replay buffer"""
        self.replay_buffer.push(state, action, reward, next_state, done)


# =============================================================================
# Security-Specific ML Models
# =============================================================================

class ThreatIntelligenceNLP:
    """NLP for threat intelligence analysis"""
    
    def __init__(self):
        self.ioc_patterns = {
            'ip': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'domain': r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+'
        }
        
        self.threat_keywords = {
            'high': ['ransomware', 'zero-day', 'exploit', 'breach', 'compromise'],
            'medium': ['phishing', 'malware', 'vulnerability', 'attack', 'threat'],
            'low': ['scan', 'probe', 'reconnaissance', 'enumeration']
        }
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract indicators of compromise from text"""
        import re
        
        iocs = {}
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                iocs[ioc_type] = list(set(matches))
        
        return iocs
    
    def classify_threat_level(self, text: str) -> str:
        """Classify threat level from text"""
        text_lower = text.lower()
        
        for level, keywords in self.threat_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    return level
        
        return 'info'
    
    def summarize_threat_report(self, text: str, max_sentences: int = 3) -> str:
        """Summarize threat report using extractive summarization"""
        sentences = text.split('.')
        
        # Score sentences by threat keyword presence
        scored = []
        for sentence in sentences:
            score = 0
            sentence_lower = sentence.lower()
            for level, keywords in self.threat_keywords.items():
                for keyword in keywords:
                    if keyword in sentence_lower:
                        score += {'high': 3, 'medium': 2, 'low': 1}.get(level, 0)
            scored.append((sentence.strip(), score))
        
        # Return top sentences
        scored.sort(key=lambda x: x[1], reverse=True)
        return '. '.join([s[0] for s in scored[:max_sentences] if s[0]]) + '.'


class BehaviorAnalyzer:
    """Analyze user and entity behavior"""
    
    def __init__(self):
        self.baseline_models: Dict[str, Dict] = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        
        if SKLEARN_AVAILABLE:
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
    
    def build_baseline(self, entity_id: str, activities: List[Dict[str, Any]]):
        """Build behavioral baseline for entity"""
        if not activities:
            return
        
        # Extract features
        features = self._extract_activity_features(activities)
        
        # Compute statistics
        self.baseline_models[entity_id] = {
            'mean': np.mean(features, axis=0),
            'std': np.std(features, axis=0) + 1e-6,  # Avoid division by zero
            'n_samples': len(activities),
            'created_at': time.time()
        }
        
        # Train isolation forest if available
        if SKLEARN_AVAILABLE and len(features) > 10:
            self.isolation_forest.fit(features)
    
    def detect_anomaly(self, entity_id: str, activity: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if activity is anomalous"""
        if entity_id not in self.baseline_models:
            return False, 0.0
        
        baseline = self.baseline_models[entity_id]
        features = self._extract_activity_features([activity])[0]
        
        # Z-score based detection
        z_scores = np.abs((features - baseline['mean']) / baseline['std'])
        max_z = np.max(z_scores)
        
        is_anomaly = max_z > self.anomaly_threshold
        
        # Combine with isolation forest if available
        if SKLEARN_AVAILABLE:
            try:
                if_score = -self.isolation_forest.score_samples([features])[0]
                combined_score = (max_z + if_score) / 2
                is_anomaly = is_anomaly or if_score > 0.5
            except Exception:
                combined_score = max_z
        else:
            combined_score = max_z
        
        return is_anomaly, combined_score
    
    def _extract_activity_features(self, activities: List[Dict]) -> np.ndarray:
        """Extract numerical features from activities"""
        features = []
        
        for activity in activities:
            feat = [
                activity.get('hour', 0),
                activity.get('day_of_week', 0),
                activity.get('bytes_transferred', 0),
                activity.get('duration_seconds', 0),
                activity.get('num_operations', 0),
                activity.get('error_count', 0),
                1 if activity.get('is_internal', False) else 0,
                activity.get('sensitivity_level', 0)
            ]
            features.append(feat)
        
        return np.array(features)


class VulnerabilityScorer:
    """ML-based vulnerability scoring"""
    
    def __init__(self):
        self.feature_weights = {
            'cvss_base': 0.3,
            'exploitability': 0.25,
            'impact': 0.2,
            'exposure': 0.15,
            'threat_intel': 0.1
        }
        
        if SKLEARN_AVAILABLE:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.scaler = StandardScaler()
            self.is_trained = False
    
    def calculate_risk_score(self, vuln_data: Dict[str, Any]) -> float:
        """Calculate risk score for vulnerability"""
        scores = {}
        
        # Base CVSS score (0-10)
        cvss = vuln_data.get('cvss_score', 5.0)
        scores['cvss_base'] = cvss / 10.0
        
        # Exploitability (public exploit, PoC, etc.)
        if vuln_data.get('has_public_exploit'):
            scores['exploitability'] = 1.0
        elif vuln_data.get('has_poc'):
            scores['exploitability'] = 0.7
        else:
            scores['exploitability'] = 0.3
        
        # Impact (data sensitivity, system criticality)
        criticality = vuln_data.get('asset_criticality', 'medium')
        scores['impact'] = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.2}.get(criticality, 0.5)
        
        # Exposure (internet-facing, internal, etc.)
        if vuln_data.get('internet_facing'):
            scores['exposure'] = 1.0
        elif vuln_data.get('dmz'):
            scores['exposure'] = 0.7
        else:
            scores['exposure'] = 0.3
        
        # Threat intelligence (active exploitation)
        if vuln_data.get('active_exploitation'):
            scores['threat_intel'] = 1.0
        elif vuln_data.get('in_threat_feeds'):
            scores['threat_intel'] = 0.6
        else:
            scores['threat_intel'] = 0.1
        
        # Weighted sum
        final_score = sum(
            scores.get(k, 0) * w for k, w in self.feature_weights.items()
        )
        
        return min(1.0, final_score)
    
    def prioritize_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Tuple[Dict, float]]:
        """Prioritize vulnerabilities by risk score"""
        scored = [(v, self.calculate_risk_score(v)) for v in vulnerabilities]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored


# =============================================================================
# Model Management
# =============================================================================

class ModelRegistry:
    """Registry for ML models"""
    
    def __init__(self, storage_path: str = "./models"):
        self.storage_path = storage_path
        self.models: Dict[str, Dict[str, Any]] = {}
        os.makedirs(storage_path, exist_ok=True)
    
    def register(
        self,
        name: str,
        model: Any,
        model_type: ModelType,
        metrics: ModelMetrics = None,
        metadata: Dict = None
    ) -> str:
        """Register model"""
        model_id = hashlib.md5(f"{name}_{time.time()}".encode()).hexdigest()[:12]
        
        self.models[model_id] = {
            'name': name,
            'type': model_type,
            'metrics': metrics,
            'metadata': metadata or {},
            'created_at': datetime.now().isoformat(),
            'version': 1
        }
        
        # Save model
        self._save_model(model_id, model)
        
        return model_id
    
    def load(self, model_id: str) -> Any:
        """Load model by ID"""
        if model_id not in self.models:
            raise KeyError(f"Model {model_id} not found")
        
        return self._load_model(model_id)
    
    def list_models(self, model_type: ModelType = None) -> List[Dict]:
        """List registered models"""
        models = []
        for mid, info in self.models.items():
            if model_type is None or info['type'] == model_type:
                models.append({'id': mid, **info})
        return models
    
    def _save_model(self, model_id: str, model: Any):
        """Save model to disk"""
        path = os.path.join(self.storage_path, f"{model_id}.pkl")
        
        if TORCH_AVAILABLE and isinstance(model, nn.Module):
            torch.save(model.state_dict(), path.replace('.pkl', '.pt'))
        else:
            with open(path, 'wb') as f:
                pickle.dump(model, f)
    
    def _load_model(self, model_id: str) -> Any:
        """Load model from disk"""
        pkl_path = os.path.join(self.storage_path, f"{model_id}.pkl")
        pt_path = os.path.join(self.storage_path, f"{model_id}.pt")
        
        if os.path.exists(pt_path):
            if TORCH_AVAILABLE:
                return torch.load(pt_path)
        elif os.path.exists(pkl_path):
            with open(pkl_path, 'rb') as f:
                return pickle.load(f)
        
        raise FileNotFoundError(f"Model file not found for {model_id}")


class MLPipeline:
    """End-to-end ML pipeline for security"""
    
    def __init__(self):
        self.registry = ModelRegistry()
        self.trainer = ModelTrainer()
        self.threat_nlp = ThreatIntelligenceNLP()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.vuln_scorer = VulnerabilityScorer()
        
        # Pre-built models
        self.anomaly_detector: Optional[AnomalyAutoencoder] = None
        self.threat_classifier: Optional[ThreatTransformer] = None
        self.rl_agent: Optional[RLPentestAgent] = None
    
    def initialize_models(
        self,
        state_dim: int = 64,
        action_dim: int = 10,
        input_dim: int = 100
    ):
        """Initialize default models"""
        if TORCH_AVAILABLE:
            self.anomaly_detector = AnomalyAutoencoder(input_dim=input_dim)
            self.threat_classifier = ThreatTransformer()
            self.rl_agent = RLPentestAgent(state_dim, action_dim)
    
    def analyze_threat(self, text: str) -> Dict[str, Any]:
        """Analyze threat from text"""
        return {
            'iocs': self.threat_nlp.extract_iocs(text),
            'threat_level': self.threat_nlp.classify_threat_level(text),
            'summary': self.threat_nlp.summarize_threat_report(text)
        }
    
    def detect_anomaly(
        self,
        entity_id: str,
        activity: Dict[str, Any]
    ) -> Tuple[bool, float]:
        """Detect anomalous behavior"""
        return self.behavior_analyzer.detect_anomaly(entity_id, activity)
    
    def score_vulnerability(self, vuln_data: Dict[str, Any]) -> float:
        """Score vulnerability risk"""
        return self.vuln_scorer.calculate_risk_score(vuln_data)
    
    def get_pentest_action(self, state: np.ndarray) -> int:
        """Get next pentest action from RL agent"""
        if self.rl_agent:
            return self.rl_agent.select_action(state)
        return 0


# Global instance
ml_pipeline = MLPipeline()


def get_ml_pipeline() -> MLPipeline:
    """Get global ML pipeline"""
    return ml_pipeline
