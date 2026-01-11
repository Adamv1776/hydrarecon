#!/usr/bin/env python3
"""
Privacy-Preserving Computation Engine - HydraRecon v1.2.0

Implements privacy-preserving techniques for secure data analysis:
- Differential Privacy for statistical queries
- Homomorphic Encryption for encrypted computation
- Secure Multi-Party Computation (MPC) primitives
- K-Anonymity and L-Diversity for data anonymization

Enables security analytics without exposing sensitive data.

Author: HydraRecon Team
"""

import asyncio
import hashlib
import json
import logging
import math
import secrets
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from collections import defaultdict

import numpy as np

logger = logging.getLogger(__name__)


class PrivacyMechanism(Enum):
    """Privacy mechanism types."""
    LAPLACE = "laplace"
    GAUSSIAN = "gaussian"
    EXPONENTIAL = "exponential"
    RANDOMIZED_RESPONSE = "randomized_response"


class NoiseType(Enum):
    """Types of noise for differential privacy."""
    LAPLACE = "laplace"
    GAUSSIAN = "gaussian"


@dataclass
class PrivacyBudget:
    """
    Privacy budget tracker for differential privacy.
    Tracks epsilon and delta consumption across queries.
    """
    total_epsilon: float
    total_delta: float
    consumed_epsilon: float = 0.0
    consumed_delta: float = 0.0
    queries: List[Dict] = field(default_factory=list)
    
    @property
    def remaining_epsilon(self) -> float:
        return max(0, self.total_epsilon - self.consumed_epsilon)
    
    @property
    def remaining_delta(self) -> float:
        return max(0, self.total_delta - self.consumed_delta)
    
    def can_query(self, epsilon: float, delta: float = 0.0) -> bool:
        """Check if budget allows this query."""
        return (self.consumed_epsilon + epsilon <= self.total_epsilon and
                self.consumed_delta + delta <= self.total_delta)
    
    def consume(self, epsilon: float, delta: float = 0.0, query_name: str = ""):
        """Consume budget for a query."""
        if not self.can_query(epsilon, delta):
            raise ValueError("Insufficient privacy budget")
        
        self.consumed_epsilon += epsilon
        self.consumed_delta += delta
        self.queries.append({
            'name': query_name,
            'epsilon': epsilon,
            'delta': delta,
            'timestamp': datetime.now().isoformat()
        })
    
    def reset(self):
        """Reset budget (use with caution)."""
        self.consumed_epsilon = 0.0
        self.consumed_delta = 0.0
        self.queries = []


class DifferentialPrivacy:
    """
    Differential Privacy implementation with various noise mechanisms.
    
    Provides ε-differential privacy guarantees for numeric queries.
    """
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        Initialize with privacy parameters.
        
        Args:
            epsilon: Privacy loss parameter (smaller = more private)
            delta: Probability of privacy breach (for approximate DP)
        """
        self.epsilon = epsilon
        self.delta = delta
        self.budget = PrivacyBudget(epsilon, delta)
    
    def laplace_mechanism(self, true_value: float, sensitivity: float,
                         epsilon: Optional[float] = None) -> float:
        """
        Apply Laplace mechanism for ε-differential privacy.
        
        Args:
            true_value: The actual query result
            sensitivity: Global sensitivity of the query (max change per record)
            epsilon: Privacy parameter (uses default if not specified)
            
        Returns:
            Noisy result satisfying ε-DP
        """
        eps = epsilon or self.epsilon
        
        # Check budget
        if not self.budget.can_query(eps):
            raise ValueError("Privacy budget exhausted")
        
        # Laplace scale parameter
        scale = sensitivity / eps
        
        # Sample from Laplace distribution
        noise = np.random.laplace(0, scale)
        
        # Consume budget
        self.budget.consume(eps, 0.0, "laplace")
        
        return true_value + noise
    
    def gaussian_mechanism(self, true_value: float, sensitivity: float,
                          epsilon: Optional[float] = None,
                          delta: Optional[float] = None) -> float:
        """
        Apply Gaussian mechanism for (ε,δ)-differential privacy.
        
        Args:
            true_value: The actual query result
            sensitivity: L2 sensitivity of the query
            epsilon: Privacy parameter
            delta: Failure probability
            
        Returns:
            Noisy result satisfying (ε,δ)-DP
        """
        eps = epsilon or self.epsilon
        dlt = delta or self.delta
        
        if not self.budget.can_query(eps, dlt):
            raise ValueError("Privacy budget exhausted")
        
        # Gaussian std dev for (ε,δ)-DP
        sigma = sensitivity * math.sqrt(2 * math.log(1.25 / dlt)) / eps
        
        # Sample from Gaussian
        noise = np.random.normal(0, sigma)
        
        self.budget.consume(eps, dlt, "gaussian")
        
        return true_value + noise
    
    def exponential_mechanism(self, data: List[Any], 
                             utility_fn: Callable[[Any], float],
                             sensitivity: float,
                             epsilon: Optional[float] = None) -> Any:
        """
        Apply exponential mechanism for selecting from discrete options.
        
        Args:
            data: List of candidate options
            utility_fn: Function mapping options to utility scores
            sensitivity: Sensitivity of utility function
            epsilon: Privacy parameter
            
        Returns:
            Selected option with probability proportional to exp(ε·u/(2Δ))
        """
        eps = epsilon or self.epsilon
        
        if not self.budget.can_query(eps):
            raise ValueError("Privacy budget exhausted")
        
        if not data:
            raise ValueError("Empty data list")
        
        # Calculate utilities
        utilities = np.array([utility_fn(x) for x in data])
        
        # Calculate selection probabilities
        scaled_utilities = (eps * utilities) / (2 * sensitivity)
        
        # Numerical stability: subtract max before exp
        scaled_utilities = scaled_utilities - np.max(scaled_utilities)
        probs = np.exp(scaled_utilities)
        probs = probs / np.sum(probs)
        
        # Sample according to probabilities
        idx = np.random.choice(len(data), p=probs)
        
        self.budget.consume(eps, 0.0, "exponential")
        
        return data[idx]
    
    def randomized_response(self, true_value: bool, 
                           p: float = 0.5) -> bool:
        """
        Randomized response mechanism for binary queries.
        
        Args:
            true_value: True binary value
            p: Probability of answering truthfully (0.5-1.0)
            
        Returns:
            Possibly flipped response
        """
        # Epsilon for this p
        eps = math.log((p) / (1 - p)) if p < 1 else float('inf')
        
        if not self.budget.can_query(abs(eps)):
            raise ValueError("Privacy budget exhausted")
        
        if np.random.random() < p:
            response = true_value
        else:
            response = np.random.random() < 0.5
        
        self.budget.consume(abs(eps), 0.0, "randomized_response")
        
        return response
    
    def private_count(self, data: List[Any], 
                     predicate: Callable[[Any], bool],
                     epsilon: Optional[float] = None) -> float:
        """
        Private counting query with Laplace noise.
        
        Args:
            data: Dataset
            predicate: Boolean function to count
            epsilon: Privacy parameter
            
        Returns:
            Noisy count
        """
        true_count = sum(1 for x in data if predicate(x))
        # Sensitivity is 1 for counting queries
        return self.laplace_mechanism(true_count, sensitivity=1.0, epsilon=epsilon)
    
    def private_mean(self, data: List[float], 
                    lower: float, upper: float,
                    epsilon: Optional[float] = None) -> float:
        """
        Private mean with bounded data.
        
        Args:
            data: Numeric data (must be in [lower, upper])
            lower: Lower bound on data values
            upper: Upper bound on data values
            epsilon: Privacy parameter
            
        Returns:
            Noisy mean
        """
        if not data:
            return 0.0
        
        eps = epsilon or self.epsilon
        
        # Clip data to bounds
        clipped = np.clip(data, lower, upper)
        
        # Sensitivity of mean is (upper - lower) / n
        n = len(data)
        sensitivity = (upper - lower) / n
        
        true_mean = np.mean(clipped)
        
        return self.laplace_mechanism(true_mean, sensitivity, eps)
    
    def private_sum(self, data: List[float],
                   lower: float, upper: float,
                   epsilon: Optional[float] = None) -> float:
        """
        Private sum with bounded data.
        
        Args:
            data: Numeric data
            lower: Lower bound per element
            upper: Upper bound per element
            epsilon: Privacy parameter
            
        Returns:
            Noisy sum
        """
        # Clip data
        clipped = np.clip(data, lower, upper)
        
        # Sensitivity is upper - lower (one person's contribution)
        sensitivity = upper - lower
        
        true_sum = np.sum(clipped)
        
        return self.laplace_mechanism(true_sum, sensitivity, epsilon)
    
    def private_histogram(self, data: List[Any],
                         bins: List[Any],
                         epsilon: Optional[float] = None) -> Dict[Any, float]:
        """
        Private histogram with per-bin noise.
        
        Args:
            data: Categorical data
            bins: Histogram bins/categories
            epsilon: Total privacy budget (split across bins)
            
        Returns:
            Noisy histogram
        """
        eps = epsilon or self.epsilon
        
        # Split budget across bins
        eps_per_bin = eps / len(bins)
        
        # Count true values
        counts = defaultdict(int)
        for x in data:
            if x in bins:
                counts[x] += 1
        
        # Add noise to each bin
        noisy_histogram = {}
        for bin_val in bins:
            true_count = counts.get(bin_val, 0)
            noisy_count = self.laplace_mechanism(
                true_count, 
                sensitivity=1.0, 
                epsilon=eps_per_bin
            )
            noisy_histogram[bin_val] = max(0, noisy_count)  # Clamp to non-negative
        
        return noisy_histogram


class SimplePaillier:
    """
    Simplified Paillier-like homomorphic encryption.
    
    Supports addition of encrypted values.
    Note: This is a simplified implementation for demonstration.
    Use a proper cryptographic library for production.
    """
    
    def __init__(self, key_bits: int = 512):
        """Initialize with key size."""
        self.key_bits = key_bits
        self.n = None
        self.g = None
        self.lambda_n = None
        self.mu = None
        self._generate_keys()
    
    def _generate_keys(self):
        """Generate public and private keys."""
        # Generate two large primes
        p = self._generate_prime(self.key_bits // 2)
        q = self._generate_prime(self.key_bits // 2)
        
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1  # Simple choice for g
        
        # Private key components
        self.lambda_n = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        
        # Precompute mu
        x = pow(self.g, self.lambda_n, self.n_sq)
        l_x = (x - 1) // self.n
        self.mu = pow(l_x, -1, self.n) if l_x != 0 else 1
    
    def _generate_prime(self, bits: int) -> int:
        """Generate a random prime number."""
        while True:
            candidate = secrets.randbits(bits) | (1 << bits - 1) | 1
            if self._is_prime(candidate):
                return candidate
    
    def _is_prime(self, n: int, k: int = 10) -> bool:
        """Miller-Rabin primality test."""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def encrypt(self, plaintext: int) -> int:
        """
        Encrypt a plaintext integer.
        
        Args:
            plaintext: Integer to encrypt (must be < n)
            
        Returns:
            Ciphertext
        """
        if plaintext >= self.n or plaintext < 0:
            raise ValueError(f"Plaintext must be in [0, {self.n})")
        
        # Random r for semantic security
        r = secrets.randbelow(self.n - 1) + 1
        while math.gcd(r, self.n) != 1:
            r = secrets.randbelow(self.n - 1) + 1
        
        # c = g^m * r^n mod n^2
        c = (pow(self.g, plaintext, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        
        return c
    
    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt a ciphertext.
        
        Args:
            ciphertext: Encrypted value
            
        Returns:
            Decrypted plaintext
        """
        # L(c^lambda mod n^2) * mu mod n
        x = pow(ciphertext, self.lambda_n, self.n_sq)
        l_x = (x - 1) // self.n
        plaintext = (l_x * self.mu) % self.n
        
        return plaintext
    
    def add(self, c1: int, c2: int) -> int:
        """
        Add two encrypted values homomorphically.
        
        Args:
            c1: First ciphertext
            c2: Second ciphertext
            
        Returns:
            Ciphertext of sum
        """
        return (c1 * c2) % self.n_sq
    
    def multiply_const(self, ciphertext: int, constant: int) -> int:
        """
        Multiply encrypted value by a constant.
        
        Args:
            ciphertext: Encrypted value
            constant: Plaintext constant
            
        Returns:
            Ciphertext of product
        """
        return pow(ciphertext, constant, self.n_sq)


class SecureAggregation:
    """
    Secure aggregation for federated learning style computations.
    
    Allows multiple parties to compute aggregate statistics
    without revealing individual contributions.
    """
    
    def __init__(self, num_parties: int, modulus: int = 2**32):
        """
        Initialize secure aggregation.
        
        Args:
            num_parties: Number of participating parties
            modulus: Modulus for arithmetic (should be > sum of inputs)
        """
        self.num_parties = num_parties
        self.modulus = modulus
        self.masks: Dict[int, List[int]] = {}
        self._generate_masks()
    
    def _generate_masks(self):
        """Generate pairwise masking values."""
        # For each party pair (i,j) where i < j, generate a shared mask
        # Party i adds mask, party j subtracts it
        
        for i in range(self.num_parties):
            self.masks[i] = []
            for j in range(self.num_parties):
                if i < j:
                    # Generate random mask
                    mask = secrets.randbelow(self.modulus)
                    self.masks[i].append(mask)
                elif i > j:
                    # Use negative of mask (already generated)
                    self.masks[i].append(-self.masks[j][i] % self.modulus)
                else:
                    self.masks[i].append(0)
    
    def mask_value(self, party_id: int, value: int) -> int:
        """
        Mask a party's value for secure aggregation.
        
        Args:
            party_id: ID of the party (0 to num_parties-1)
            value: Value to mask
            
        Returns:
            Masked value
        """
        if party_id < 0 or party_id >= self.num_parties:
            raise ValueError(f"Invalid party ID: {party_id}")
        
        # Add all masks for this party
        total_mask = sum(self.masks[party_id]) % self.modulus
        
        return (value + total_mask) % self.modulus
    
    def aggregate(self, masked_values: List[int]) -> int:
        """
        Aggregate masked values from all parties.
        
        Args:
            masked_values: List of masked values from each party
            
        Returns:
            Sum of original values (masks cancel out)
        """
        if len(masked_values) != self.num_parties:
            raise ValueError(f"Expected {self.num_parties} values, got {len(masked_values)}")
        
        # Sum all masked values - masks cancel out
        total = sum(masked_values) % self.modulus
        
        return total


class DataAnonymizer:
    """
    Data anonymization using k-anonymity and l-diversity.
    """
    
    def __init__(self, k: int = 5, l: int = 2):
        """
        Initialize anonymizer.
        
        Args:
            k: Minimum group size for k-anonymity
            l: Minimum distinct sensitive values for l-diversity
        """
        self.k = k
        self.l = l
    
    def generalize_age(self, age: int, granularity: int = 10) -> str:
        """Generalize age to range."""
        lower = (age // granularity) * granularity
        upper = lower + granularity - 1
        return f"{lower}-{upper}"
    
    def generalize_zipcode(self, zipcode: str, digits: int = 3) -> str:
        """Generalize zipcode by masking digits."""
        if len(zipcode) < digits:
            return "*" * len(zipcode)
        return zipcode[:digits] + "*" * (len(zipcode) - digits)
    
    def suppress_outliers(self, data: List[Dict], 
                         quasi_identifiers: List[str],
                         sensitive_attr: str) -> List[Dict]:
        """
        Suppress records that don't meet k-anonymity.
        
        Args:
            data: List of records
            quasi_identifiers: Columns used for grouping
            sensitive_attr: Sensitive attribute for l-diversity
            
        Returns:
            Anonymized data with outliers removed
        """
        # Group by quasi-identifiers
        groups = defaultdict(list)
        
        for record in data:
            key = tuple(record.get(qi, '') for qi in quasi_identifiers)
            groups[key].append(record)
        
        # Filter groups meeting k-anonymity and l-diversity
        anonymized = []
        
        for key, group in groups.items():
            # Check k-anonymity
            if len(group) < self.k:
                continue
            
            # Check l-diversity
            sensitive_values = set(r.get(sensitive_attr) for r in group)
            if len(sensitive_values) < self.l:
                continue
            
            anonymized.extend(group)
        
        return anonymized
    
    def apply_k_anonymity(self, data: List[Dict],
                         quasi_identifiers: List[str],
                         generalizations: Dict[str, Callable]) -> List[Dict]:
        """
        Apply k-anonymity through generalization.
        
        Args:
            data: List of records
            quasi_identifiers: Columns to generalize
            generalizations: Dict mapping column names to generalization functions
            
        Returns:
            Anonymized data
        """
        anonymized = []
        
        for record in data:
            new_record = record.copy()
            
            for qi in quasi_identifiers:
                if qi in generalizations and qi in new_record:
                    new_record[qi] = generalizations[qi](new_record[qi])
            
            anonymized.append(new_record)
        
        return anonymized


class PrivacyPreservingAnalytics:
    """
    High-level privacy-preserving analytics engine.
    Combines differential privacy with secure computation.
    """
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        Initialize analytics engine.
        
        Args:
            epsilon: Default privacy parameter
            delta: Default delta for approximate DP
        """
        self.dp = DifferentialPrivacy(epsilon, delta)
        self.anonymizer = DataAnonymizer()
    
    def private_statistics(self, data: List[float],
                          lower: float, upper: float,
                          epsilon: float = 0.5) -> Dict[str, float]:
        """
        Compute private statistics on numeric data.
        
        Args:
            data: Numeric data
            lower: Lower bound
            upper: Upper bound
            epsilon: Total privacy budget (split across stats)
            
        Returns:
            Dictionary of noisy statistics
        """
        eps_per_stat = epsilon / 4  # Split across 4 statistics
        
        return {
            'count': max(0, self.dp.laplace_mechanism(
                len(data), 1.0, eps_per_stat
            )),
            'sum': self.dp.private_sum(data, lower, upper, eps_per_stat),
            'mean': self.dp.private_mean(data, lower, upper, eps_per_stat),
            'max': self.dp.laplace_mechanism(
                max(data) if data else 0,
                upper - lower,
                eps_per_stat
            )
        }
    
    def private_threat_counts(self, threat_data: List[Dict],
                             categories: List[str],
                             epsilon: float = 1.0) -> Dict[str, float]:
        """
        Compute private threat category counts.
        
        Args:
            threat_data: List of threat records with 'category' field
            categories: List of threat categories
            epsilon: Privacy budget
            
        Returns:
            Noisy counts per category
        """
        # Extract categories
        data = [t.get('category', 'unknown') for t in threat_data]
        
        return self.dp.private_histogram(data, categories, epsilon)
    
    def secure_aggregate_scores(self, scores: List[float],
                               num_parties: int) -> float:
        """
        Securely aggregate risk scores from multiple parties.
        
        Args:
            scores: Risk scores from each party
            num_parties: Number of parties
            
        Returns:
            Aggregate score (mean)
        """
        agg = SecureAggregation(num_parties, modulus=2**32)
        
        # Scale to integers
        scaled = [int(s * 1000) for s in scores]
        
        # Mask each value
        masked = [agg.mask_value(i, v) for i, v in enumerate(scaled)]
        
        # Aggregate
        total = agg.aggregate(masked)
        
        # Scale back
        return (total / 1000) / num_parties
    
    def anonymize_logs(self, logs: List[Dict],
                      quasi_identifiers: List[str] = None,
                      sensitive_field: str = 'action') -> List[Dict]:
        """
        Anonymize security logs while preserving analytics utility.
        
        Args:
            logs: List of log records
            quasi_identifiers: Fields to generalize
            sensitive_field: Sensitive attribute to protect
            
        Returns:
            Anonymized logs
        """
        qi = quasi_identifiers or ['timestamp', 'source_ip', 'user_id']
        
        # Define generalizations
        generalizations = {
            'timestamp': lambda t: t[:13] + ':00:00' if isinstance(t, str) and len(t) > 13 else t,
            'source_ip': lambda ip: '.'.join(ip.split('.')[:2]) + '.0.0' if '.' in str(ip) else ip,
            'user_id': lambda u: hashlib.sha256(str(u).encode()).hexdigest()[:8]
        }
        
        # Apply k-anonymity
        anonymized = self.anonymizer.apply_k_anonymity(
            logs, qi, generalizations
        )
        
        # Suppress outliers
        return self.anonymizer.suppress_outliers(
            anonymized, qi, sensitive_field
        )
    
    def get_budget_status(self) -> Dict:
        """Get current privacy budget status."""
        return {
            'total_epsilon': self.dp.budget.total_epsilon,
            'consumed_epsilon': self.dp.budget.consumed_epsilon,
            'remaining_epsilon': self.dp.budget.remaining_epsilon,
            'total_delta': self.dp.budget.total_delta,
            'consumed_delta': self.dp.budget.consumed_delta,
            'remaining_delta': self.dp.budget.remaining_delta,
            'query_count': len(self.dp.budget.queries)
        }


# Testing
def main():
    """Test privacy-preserving computation."""
    print("Privacy-Preserving Computation Tests")
    print("=" * 50)
    
    # Test Differential Privacy
    print("\n1. Differential Privacy")
    dp = DifferentialPrivacy(epsilon=1.0)
    
    data = list(range(100))
    
    true_mean = np.mean(data)
    private_mean = dp.private_mean(data, 0, 100, epsilon=0.5)
    
    print(f"   True mean: {true_mean:.2f}")
    print(f"   Private mean (ε=0.5): {private_mean:.2f}")
    print(f"   Error: {abs(true_mean - private_mean):.2f}")
    
    # Test histogram
    categories = ['A', 'B', 'C', 'D']
    cat_data = np.random.choice(categories, 1000).tolist()
    
    true_hist = {c: cat_data.count(c) for c in categories}
    private_hist = dp.private_histogram(cat_data, categories, epsilon=0.5)
    
    print(f"\n   True histogram: {true_hist}")
    print(f"   Private histogram: {dict((k, int(v)) for k, v in private_hist.items())}")
    
    # Test Homomorphic Encryption
    print("\n2. Homomorphic Encryption (Simplified Paillier)")
    he = SimplePaillier(key_bits=256)  # Small for demo
    
    a, b = 42, 58
    enc_a = he.encrypt(a)
    enc_b = he.encrypt(b)
    
    # Homomorphic addition
    enc_sum = he.add(enc_a, enc_b)
    dec_sum = he.decrypt(enc_sum)
    
    print(f"   a = {a}, b = {b}")
    print(f"   Encrypted sum decrypts to: {dec_sum}")
    print(f"   Correct: {dec_sum == a + b}")
    
    # Scalar multiplication
    enc_triple = he.multiply_const(enc_a, 3)
    dec_triple = he.decrypt(enc_triple)
    
    print(f"   3 * {a} encrypted = {dec_triple}")
    print(f"   Correct: {dec_triple == 3 * a}")
    
    # Test Secure Aggregation
    print("\n3. Secure Aggregation")
    num_parties = 5
    values = [100, 200, 150, 300, 250]  # Secret values
    
    agg = SecureAggregation(num_parties)
    
    masked = [agg.mask_value(i, v) for i, v in enumerate(values)]
    total = agg.aggregate(masked)
    
    print(f"   Secret values: {values}")
    print(f"   Aggregated sum: {total}")
    print(f"   Correct: {total == sum(values)}")
    
    # Test Data Anonymization
    print("\n4. Data Anonymization")
    anonymizer = DataAnonymizer(k=2, l=2)
    
    sample_data = [
        {'age': 25, 'zipcode': '12345', 'disease': 'flu'},
        {'age': 27, 'zipcode': '12346', 'disease': 'cold'},
        {'age': 26, 'zipcode': '12344', 'disease': 'flu'},
        {'age': 35, 'zipcode': '54321', 'disease': 'diabetes'},
    ]
    
    # Apply generalizations
    generalizations = {
        'age': lambda a: anonymizer.generalize_age(a, 10),
        'zipcode': lambda z: anonymizer.generalize_zipcode(z, 3)
    }
    
    anonymized = anonymizer.apply_k_anonymity(
        sample_data, ['age', 'zipcode'], generalizations
    )
    
    print("   Original:")
    for r in sample_data[:2]:
        print(f"     {r}")
    print("   Anonymized:")
    for r in anonymized[:2]:
        print(f"     {r}")
    
    # Test High-Level Analytics
    print("\n5. Privacy-Preserving Analytics")
    analytics = PrivacyPreservingAnalytics(epsilon=2.0)
    
    scores = [75.5, 82.3, 91.0, 68.7, 88.2]
    stats = analytics.private_statistics(scores, 0, 100, epsilon=1.0)
    
    print(f"   Private statistics:")
    for k, v in stats.items():
        print(f"     {k}: {v:.2f}")
    
    print(f"\n   Budget status:")
    budget = analytics.get_budget_status()
    print(f"     Consumed ε: {budget['consumed_epsilon']:.2f}")
    print(f"     Remaining ε: {budget['remaining_epsilon']:.2f}")
    
    print("\n" + "=" * 50)
    print("All tests completed!")


if __name__ == "__main__":
    main()
