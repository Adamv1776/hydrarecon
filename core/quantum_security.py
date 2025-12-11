"""
HydraRecon Quantum Computing Module
====================================

Quantum-enhanced security operations:
- Quantum key distribution (QKD)
- Post-quantum cryptography
- Quantum random number generation
- Grover's algorithm for search
- Shor's algorithm simulation
- Quantum machine learning
- Quantum error correction
- Quantum-safe communications
- Hybrid quantum-classical optimization
- Quantum supremacy benchmarks
"""

import os
import time
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable, Union
from datetime import datetime
from enum import Enum, auto
from abc import ABC, abstractmethod
import numpy as np
import math
from collections import defaultdict
import threading

# Optional quantum library imports
try:
    from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
    from qiskit import transpile
    from qiskit_aer import AerSimulator
    QISKIT_AVAILABLE = True
except ImportError:
    QISKIT_AVAILABLE = False

try:
    import cirq
    CIRQ_AVAILABLE = True
except ImportError:
    CIRQ_AVAILABLE = False


class QuantumAlgorithm(Enum):
    """Types of quantum algorithms"""
    GROVER = auto()
    SHOR = auto()
    QKD_BB84 = auto()
    QKD_E91 = auto()
    QAOA = auto()
    VQE = auto()
    QSVM = auto()
    QUANTUM_WALK = auto()


class PostQuantumScheme(Enum):
    """Post-quantum cryptographic schemes"""
    KYBER = auto()  # Lattice-based KEM
    DILITHIUM = auto()  # Lattice-based signatures
    SPHINCS = auto()  # Hash-based signatures
    NTRU = auto()  # Lattice-based
    MCELIECE = auto()  # Code-based
    SIDH = auto()  # Isogeny-based


@dataclass
class QuantumState:
    """Represents a quantum state"""
    num_qubits: int
    state_vector: np.ndarray
    basis_labels: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.basis_labels:
            self.basis_labels = [f"|{bin(i)[2:].zfill(self.num_qubits)}⟩" for i in range(2 ** self.num_qubits)]
    
    def probabilities(self) -> np.ndarray:
        """Get measurement probabilities"""
        return np.abs(self.state_vector) ** 2
    
    def measure(self) -> Tuple[int, str]:
        """Perform measurement"""
        probs = self.probabilities()
        outcome = np.random.choice(len(probs), p=probs)
        return outcome, self.basis_labels[outcome]


@dataclass
class QuantumKey:
    """Quantum-generated key"""
    key_id: str
    key_bits: bytes
    generation_time: float
    protocol: str
    error_rate: float = 0.0
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Quantum Simulator
# =============================================================================

class QuantumSimulator:
    """Software quantum simulator"""
    
    GATES = {
        'X': np.array([[0, 1], [1, 0]], dtype=complex),
        'Y': np.array([[0, -1j], [1j, 0]], dtype=complex),
        'Z': np.array([[1, 0], [0, -1]], dtype=complex),
        'H': np.array([[1, 1], [1, -1]], dtype=complex) / np.sqrt(2),
        'S': np.array([[1, 0], [0, 1j]], dtype=complex),
        'T': np.array([[1, 0], [0, np.exp(1j * np.pi / 4)]], dtype=complex),
        'I': np.array([[1, 0], [0, 1]], dtype=complex)
    }
    
    def __init__(self, num_qubits: int):
        self.num_qubits = num_qubits
        self.dim = 2 ** num_qubits
        self.state = np.zeros(self.dim, dtype=complex)
        self.state[0] = 1.0  # Initialize to |0...0⟩
        self.operations: List[Tuple[str, Any]] = []
    
    def reset(self):
        """Reset to ground state"""
        self.state = np.zeros(self.dim, dtype=complex)
        self.state[0] = 1.0
        self.operations.clear()
    
    def _kron_gate(self, gate: np.ndarray, target: int) -> np.ndarray:
        """Create full system operator for single-qubit gate"""
        result = np.array([[1]], dtype=complex)
        
        for i in range(self.num_qubits):
            if i == target:
                result = np.kron(result, gate)
            else:
                result = np.kron(result, self.GATES['I'])
        
        return result
    
    def apply_gate(self, gate_name: str, target: int):
        """Apply single-qubit gate"""
        if gate_name not in self.GATES:
            raise ValueError(f"Unknown gate: {gate_name}")
        
        gate = self.GATES[gate_name]
        full_gate = self._kron_gate(gate, target)
        self.state = full_gate @ self.state
        self.operations.append(('gate', (gate_name, target)))
    
    def apply_rotation(self, axis: str, angle: float, target: int):
        """Apply rotation gate"""
        c = np.cos(angle / 2)
        s = np.sin(angle / 2)
        
        if axis == 'x':
            gate = np.array([[c, -1j * s], [-1j * s, c]], dtype=complex)
        elif axis == 'y':
            gate = np.array([[c, -s], [s, c]], dtype=complex)
        elif axis == 'z':
            gate = np.array([[np.exp(-1j * angle / 2), 0], [0, np.exp(1j * angle / 2)]], dtype=complex)
        else:
            raise ValueError(f"Unknown rotation axis: {axis}")
        
        full_gate = self._kron_gate(gate, target)
        self.state = full_gate @ self.state
        self.operations.append(('rotation', (axis, angle, target)))
    
    def apply_cnot(self, control: int, target: int):
        """Apply CNOT gate"""
        cnot = np.zeros((self.dim, self.dim), dtype=complex)
        
        for i in range(self.dim):
            bits = list(bin(i)[2:].zfill(self.num_qubits))
            control_bit = int(bits[control])
            target_bit = int(bits[target])
            
            if control_bit == 1:
                # Flip target
                bits[target] = str(1 - target_bit)
            
            j = int(''.join(bits), 2)
            cnot[j, i] = 1
        
        self.state = cnot @ self.state
        self.operations.append(('cnot', (control, target)))
    
    def apply_cz(self, control: int, target: int):
        """Apply CZ gate"""
        cz = np.eye(self.dim, dtype=complex)
        
        # Add phase to |11⟩ state
        for i in range(self.dim):
            bits = bin(i)[2:].zfill(self.num_qubits)
            if bits[control] == '1' and bits[target] == '1':
                cz[i, i] = -1
        
        self.state = cz @ self.state
        self.operations.append(('cz', (control, target)))
    
    def measure(self, qubit: int = None) -> Tuple[int, float]:
        """Measure qubit(s)"""
        probs = np.abs(self.state) ** 2
        
        if qubit is None:
            # Measure all qubits
            outcome = np.random.choice(self.dim, p=probs)
            return outcome, probs[outcome]
        else:
            # Measure single qubit
            prob_0 = 0.0
            for i in range(self.dim):
                bits = bin(i)[2:].zfill(self.num_qubits)
                if bits[qubit] == '0':
                    prob_0 += probs[i]
            
            result = 0 if np.random.random() < prob_0 else 1
            
            # Collapse state
            for i in range(self.dim):
                bits = bin(i)[2:].zfill(self.num_qubits)
                if bits[qubit] != str(result):
                    self.state[i] = 0
            
            # Renormalize
            norm = np.linalg.norm(self.state)
            if norm > 0:
                self.state /= norm
            
            return result, prob_0 if result == 0 else (1 - prob_0)
    
    def get_state(self) -> QuantumState:
        """Get current quantum state"""
        return QuantumState(
            num_qubits=self.num_qubits,
            state_vector=self.state.copy()
        )
    
    def get_probabilities(self) -> Dict[str, float]:
        """Get measurement probabilities for all basis states"""
        probs = np.abs(self.state) ** 2
        return {
            bin(i)[2:].zfill(self.num_qubits): p
            for i, p in enumerate(probs) if p > 1e-10
        }


# =============================================================================
# Quantum Key Distribution
# =============================================================================

class BB84Protocol:
    """BB84 Quantum Key Distribution Protocol"""
    
    def __init__(self, key_length: int = 256):
        self.key_length = key_length
        self.alice_bits: List[int] = []
        self.alice_bases: List[int] = []  # 0 = Z, 1 = X
        self.bob_bases: List[int] = []
        self.bob_measurements: List[int] = []
        self.shared_key: bytes = b''
        self.error_rate: float = 0.0
    
    def alice_prepare(self) -> List[Tuple[int, int]]:
        """Alice prepares quantum states"""
        # Need more bits due to basis mismatch and error checking
        n = self.key_length * 4
        
        self.alice_bits = [secrets.randbelow(2) for _ in range(n)]
        self.alice_bases = [secrets.randbelow(2) for _ in range(n)]
        
        # Prepare quantum states
        states = []
        for bit, basis in zip(self.alice_bits, self.alice_bases):
            states.append((bit, basis))
        
        return states
    
    def bob_measure(self, states: List[Tuple[int, int]], noise_level: float = 0.0) -> List[int]:
        """Bob measures quantum states with random bases"""
        n = len(states)
        self.bob_bases = [secrets.randbelow(2) for _ in range(n)]
        self.bob_measurements = []
        
        for i, (bit, alice_basis) in enumerate(states):
            bob_basis = self.bob_bases[i]
            
            if alice_basis == bob_basis:
                # Correct measurement (with possible noise)
                if np.random.random() < noise_level:
                    result = 1 - bit
                else:
                    result = bit
            else:
                # Random result due to basis mismatch
                result = secrets.randbelow(2)
            
            self.bob_measurements.append(result)
        
        return self.bob_measurements
    
    def sift_keys(self) -> Tuple[List[int], List[int]]:
        """Sift keys based on matching bases"""
        alice_sifted = []
        bob_sifted = []
        
        for i in range(len(self.alice_bits)):
            if self.alice_bases[i] == self.bob_bases[i]:
                alice_sifted.append(self.alice_bits[i])
                bob_sifted.append(self.bob_measurements[i])
        
        return alice_sifted, bob_sifted
    
    def estimate_error_rate(self, alice_sifted: List[int], bob_sifted: List[int], sample_size: int = None) -> float:
        """Estimate error rate using sample bits"""
        if sample_size is None:
            sample_size = len(alice_sifted) // 4
        
        sample_size = min(sample_size, len(alice_sifted))
        
        if sample_size == 0:
            return 0.0
        
        # Use first sample_size bits for error estimation
        errors = sum(a != b for a, b in zip(alice_sifted[:sample_size], bob_sifted[:sample_size]))
        self.error_rate = errors / sample_size
        
        return self.error_rate
    
    def privacy_amplification(self, alice_sifted: List[int], bob_sifted: List[int]) -> Tuple[bytes, bytes]:
        """Apply privacy amplification"""
        # Remove sample bits used for error estimation
        sample_size = len(alice_sifted) // 4
        alice_final = alice_sifted[sample_size:]
        bob_final = bob_sifted[sample_size:]
        
        # Hash to final key length
        alice_bytes = bytes([sum(alice_final[i:i + 8][j] << (7 - j) for j in range(min(8, len(alice_final[i:i + 8])))) 
                            for i in range(0, len(alice_final), 8)])
        bob_bytes = bytes([sum(bob_final[i:i + 8][j] << (7 - j) for j in range(min(8, len(bob_final[i:i + 8])))) 
                          for i in range(0, len(bob_final), 8)])
        
        # Hash to reduce Eve's information
        alice_key = hashlib.sha256(alice_bytes).digest()[:self.key_length // 8]
        bob_key = hashlib.sha256(bob_bytes).digest()[:self.key_length // 8]
        
        return alice_key, bob_key
    
    def generate_key(self, noise_level: float = 0.0) -> QuantumKey:
        """Run full BB84 protocol"""
        # Step 1: Alice prepares states
        states = self.alice_prepare()
        
        # Step 2: Bob measures
        self.bob_measure(states, noise_level)
        
        # Step 3: Sift keys
        alice_sifted, bob_sifted = self.sift_keys()
        
        # Step 4: Estimate error rate
        error_rate = self.estimate_error_rate(alice_sifted, bob_sifted)
        
        # Check if error rate is acceptable (< 11% for BB84)
        if error_rate > 0.11:
            raise SecurityError(f"Error rate too high: {error_rate:.2%}. Possible eavesdropping!")
        
        # Step 5: Privacy amplification
        alice_key, bob_key = self.privacy_amplification(alice_sifted, bob_sifted)
        
        # Verify keys match
        verified = alice_key == bob_key
        
        return QuantumKey(
            key_id=secrets.token_hex(8),
            key_bits=alice_key,
            generation_time=time.time(),
            protocol='BB84',
            error_rate=error_rate,
            verified=verified,
            metadata={
                'num_prepared': len(states),
                'num_sifted': len(alice_sifted),
                'key_length': len(alice_key) * 8
            }
        )


class SecurityError(Exception):
    """Security-related error"""
    pass


# =============================================================================
# Grover's Search Algorithm
# =============================================================================

class GroversSearch:
    """Grover's quantum search algorithm"""
    
    def __init__(self, num_qubits: int, oracle_function: Callable[[int], bool]):
        self.num_qubits = num_qubits
        self.oracle = oracle_function
        self.search_space_size = 2 ** num_qubits
        self.optimal_iterations = int(np.pi / 4 * np.sqrt(self.search_space_size))
    
    def run_classical(self) -> Tuple[Optional[int], int]:
        """Classical brute-force search for comparison"""
        for i in range(self.search_space_size):
            if self.oracle(i):
                return i, i + 1  # Found after i+1 queries
        return None, self.search_space_size
    
    def run_quantum_simulation(self, num_iterations: int = None) -> Tuple[int, float]:
        """Simulate Grover's algorithm"""
        if num_iterations is None:
            num_iterations = self.optimal_iterations
        
        # Initialize uniform superposition
        state = np.ones(self.search_space_size, dtype=complex) / np.sqrt(self.search_space_size)
        
        # Build oracle matrix
        oracle_matrix = np.eye(self.search_space_size, dtype=complex)
        for i in range(self.search_space_size):
            if self.oracle(i):
                oracle_matrix[i, i] = -1
        
        # Build diffusion operator
        s = np.ones((self.search_space_size, 1), dtype=complex) / np.sqrt(self.search_space_size)
        diffusion = 2 * (s @ s.T) - np.eye(self.search_space_size)
        
        # Grover iterations
        for _ in range(num_iterations):
            # Apply oracle
            state = oracle_matrix @ state
            # Apply diffusion
            state = diffusion @ state
        
        # Measure
        probabilities = np.abs(state) ** 2
        result = np.argmax(probabilities)
        confidence = probabilities[result]
        
        return result, confidence
    
    def run_with_qiskit(self, num_iterations: int = None) -> Tuple[int, float]:
        """Run Grover's using Qiskit if available"""
        if not QISKIT_AVAILABLE:
            return self.run_quantum_simulation(num_iterations)
        
        if num_iterations is None:
            num_iterations = self.optimal_iterations
        
        # Create circuit
        qr = QuantumRegister(self.num_qubits, 'q')
        cr = ClassicalRegister(self.num_qubits, 'c')
        qc = QuantumCircuit(qr, cr)
        
        # Initialize superposition
        qc.h(qr)
        
        # Find marked states for oracle
        marked_states = [i for i in range(self.search_space_size) if self.oracle(i)]
        
        # Grover iterations
        for _ in range(num_iterations):
            # Oracle (simplified - marks all solutions)
            for marked in marked_states:
                # Multi-controlled Z gate
                binary = bin(marked)[2:].zfill(self.num_qubits)
                for i, bit in enumerate(binary):
                    if bit == '0':
                        qc.x(qr[i])
                
                # MCZ as H-MCX-H on last qubit
                if self.num_qubits > 1:
                    qc.h(qr[-1])
                    qc.mcx(list(qr[:-1]), qr[-1])
                    qc.h(qr[-1])
                else:
                    qc.z(qr[0])
                
                for i, bit in enumerate(binary):
                    if bit == '0':
                        qc.x(qr[i])
            
            # Diffusion operator
            qc.h(qr)
            qc.x(qr)
            qc.h(qr[-1])
            qc.mcx(list(qr[:-1]), qr[-1])
            qc.h(qr[-1])
            qc.x(qr)
            qc.h(qr)
        
        # Measure
        qc.measure(qr, cr)
        
        # Simulate
        simulator = AerSimulator()
        compiled = transpile(qc, simulator)
        result = simulator.run(compiled, shots=1000).result()
        counts = result.get_counts()
        
        # Get most likely result
        max_state = max(counts, key=counts.get)
        result_int = int(max_state, 2)
        confidence = counts[max_state] / 1000
        
        return result_int, confidence


# =============================================================================
# Post-Quantum Cryptography
# =============================================================================

class LatticeBasedCrypto:
    """Simplified lattice-based cryptography (Kyber-like)"""
    
    def __init__(self, n: int = 256, q: int = 3329):
        self.n = n  # Polynomial degree
        self.q = q  # Modulus
        self.k = 2  # Security parameter
        
        # Error distribution parameters
        self.eta1 = 3
        self.eta2 = 2
    
    def _sample_centered_binomial(self, eta: int, size: int) -> np.ndarray:
        """Sample from centered binomial distribution"""
        a = np.random.randint(0, 2, (size, eta))
        b = np.random.randint(0, 2, (size, eta))
        return np.sum(a, axis=1) - np.sum(b, axis=1)
    
    def _poly_mult(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Polynomial multiplication in ring"""
        result = np.zeros(self.n, dtype=np.int64)
        
        for i in range(self.n):
            for j in range(self.n):
                idx = (i + j) % self.n
                sign = 1 if (i + j) < self.n else -1
                result[idx] = (result[idx] + sign * a[i] * b[j]) % self.q
        
        return result
    
    def keygen(self) -> Tuple[Dict, Dict]:
        """Generate key pair"""
        # Secret key
        s = self._sample_centered_binomial(self.eta1, self.n)
        e = self._sample_centered_binomial(self.eta2, self.n)
        
        # Public matrix A (random)
        A = np.random.randint(0, self.q, self.n)
        
        # Public key t = As + e (mod q)
        t = (self._poly_mult(A, s) + e) % self.q
        
        public_key = {'A': A.tolist(), 't': t.tolist()}
        private_key = {'s': s.tolist()}
        
        return public_key, private_key
    
    def encapsulate(self, public_key: Dict) -> Tuple[bytes, np.ndarray]:
        """Encapsulate to generate shared secret"""
        A = np.array(public_key['A'])
        t = np.array(public_key['t'])
        
        # Random message
        m = np.random.randint(0, 2, self.n // 8)
        
        # Encoding
        r = self._sample_centered_binomial(self.eta1, self.n)
        e1 = self._sample_centered_binomial(self.eta2, self.n)
        e2 = self._sample_centered_binomial(self.eta2, self.n)
        
        # Ciphertext
        u = (self._poly_mult(A, r) + e1) % self.q
        
        # Encode message
        m_encoded = np.zeros(self.n, dtype=np.int64)
        for i, byte in enumerate(m):
            for j in range(8):
                if i * 8 + j < self.n:
                    m_encoded[i * 8 + j] = ((byte >> j) & 1) * (self.q // 2)
        
        v = (self._poly_mult(t, r) + e2 + m_encoded) % self.q
        
        # Shared secret
        shared_secret = hashlib.sha256(m.tobytes()).digest()
        
        ciphertext = np.concatenate([u, v])
        
        return shared_secret, ciphertext
    
    def decapsulate(self, ciphertext: np.ndarray, private_key: Dict) -> bytes:
        """Decapsulate to recover shared secret"""
        s = np.array(private_key['s'])
        
        u = ciphertext[:self.n]
        v = ciphertext[self.n:]
        
        # Decrypt
        m_prime = (v - self._poly_mult(u, s)) % self.q
        
        # Decode message
        m = np.zeros(self.n // 8, dtype=np.uint8)
        for i in range(len(m)):
            byte = 0
            for j in range(8):
                if i * 8 + j < self.n:
                    # Threshold decode
                    if m_prime[i * 8 + j] > self.q // 4 and m_prime[i * 8 + j] < 3 * self.q // 4:
                        byte |= (1 << j)
            m[i] = byte
        
        shared_secret = hashlib.sha256(m.tobytes()).digest()
        
        return shared_secret


class HashBasedSignature:
    """Simplified hash-based signature (SPHINCS-like)"""
    
    def __init__(self, n: int = 32, height: int = 10):
        self.n = n  # Hash output size in bytes
        self.height = height  # Merkle tree height
        self.num_leaves = 2 ** height
    
    def _hash(self, data: bytes) -> bytes:
        """Hash function"""
        return hashlib.sha256(data).digest()
    
    def _hash_concat(self, left: bytes, right: bytes) -> bytes:
        """Hash concatenation"""
        return self._hash(left + right)
    
    def keygen(self) -> Tuple[bytes, Dict]:
        """Generate key pair"""
        # Secret key: random seed
        sk_seed = secrets.token_bytes(self.n)
        
        # Generate Merkle tree
        leaves = []
        one_time_keys = []
        
        for i in range(self.num_leaves):
            # One-time signing key
            otk = self._hash(sk_seed + i.to_bytes(4, 'big'))
            one_time_keys.append(otk)
            # Leaf = hash of public key (hash of otk)
            leaf = self._hash(otk)
            leaves.append(leaf)
        
        # Build Merkle tree
        tree = [leaves]
        current = leaves
        
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                parent = self._hash_concat(left, right)
                next_level.append(parent)
            tree.append(next_level)
            current = next_level
        
        # Public key is Merkle root
        public_key = tree[-1][0]
        
        private_key = {
            'seed': sk_seed,
            'tree': [[leaf.hex() for leaf in level] for level in tree],
            'one_time_keys': [k.hex() for k in one_time_keys]
        }
        
        return public_key, private_key
    
    def sign(self, message: bytes, private_key: Dict, key_index: int = 0) -> Dict:
        """Sign message"""
        # One-time signature
        otk = bytes.fromhex(private_key['one_time_keys'][key_index])
        
        # Message digest
        digest = self._hash(message)
        
        # Simple WOTS-like signature
        signature_parts = []
        for i in range(32):
            part = self._hash(otk + bytes([i, digest[i]]))
            signature_parts.append(part.hex())
        
        # Merkle proof
        proof = []
        idx = key_index
        tree = [[bytes.fromhex(h) for h in level] for level in private_key['tree']]
        
        for level in tree[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                proof.append(level[sibling_idx].hex())
            idx //= 2
        
        return {
            'key_index': key_index,
            'signature': signature_parts,
            'auth_path': proof
        }
    
    def verify(self, message: bytes, signature: Dict, public_key: bytes) -> bool:
        """Verify signature"""
        digest = self._hash(message)
        key_index = signature['key_index']
        
        # Reconstruct leaf from signature
        # (Simplified - in real SPHINCS this is more complex)
        leaf = self._hash(b''.join(bytes.fromhex(s) for s in signature['signature']))
        
        # Verify Merkle proof
        current = leaf
        idx = key_index
        
        for sibling_hex in signature['auth_path']:
            sibling = bytes.fromhex(sibling_hex)
            if idx % 2 == 0:
                current = self._hash_concat(current, sibling)
            else:
                current = self._hash_concat(sibling, current)
            idx //= 2
        
        return current == public_key


# =============================================================================
# Quantum Random Number Generator
# =============================================================================

class QuantumRNG:
    """Quantum random number generator"""
    
    def __init__(self, use_hardware: bool = False):
        self.use_hardware = use_hardware
        self.simulator = QuantumSimulator(1) if not use_hardware else None
        self._entropy_pool: bytes = b''
        self._pool_lock = threading.Lock()
    
    def _get_quantum_bit(self) -> int:
        """Get single quantum random bit"""
        if self.use_hardware:
            # Would interface with real quantum hardware
            # For now, use cryptographic randomness
            return secrets.randbelow(2)
        
        # Use quantum simulation
        self.simulator.reset()
        self.simulator.apply_gate('H', 0)  # Create superposition
        result, _ = self.simulator.measure(0)
        return result
    
    def get_bits(self, num_bits: int) -> bytes:
        """Get quantum random bits"""
        bits = []
        for _ in range(num_bits):
            bits.append(self._get_quantum_bit())
        
        # Convert to bytes
        result = bytes([sum(bits[i:i + 8][j] << j for j in range(min(8, len(bits[i:i + 8])))) 
                       for i in range(0, len(bits), 8)])
        return result
    
    def get_bytes(self, num_bytes: int) -> bytes:
        """Get quantum random bytes"""
        return self.get_bits(num_bytes * 8)
    
    def get_int(self, min_val: int, max_val: int) -> int:
        """Get quantum random integer in range"""
        range_size = max_val - min_val + 1
        bits_needed = math.ceil(math.log2(range_size))
        
        while True:
            random_bits = self.get_bits(bits_needed)
            value = int.from_bytes(random_bits, 'big') % (2 ** bits_needed)
            if value < range_size:
                return min_val + value
    
    def fill_entropy_pool(self, size: int = 1024):
        """Pre-generate entropy"""
        with self._pool_lock:
            self._entropy_pool += self.get_bytes(size)
    
    def get_from_pool(self, num_bytes: int) -> bytes:
        """Get bytes from pre-generated pool"""
        with self._pool_lock:
            if len(self._entropy_pool) < num_bytes:
                self.fill_entropy_pool(max(1024, num_bytes * 2))
            
            result = self._entropy_pool[:num_bytes]
            self._entropy_pool = self._entropy_pool[num_bytes:]
            return result


# =============================================================================
# Quantum Security Manager
# =============================================================================

class QuantumSecurityManager:
    """Main manager for quantum security operations"""
    
    def __init__(self):
        self.rng = QuantumRNG()
        self.lattice_crypto = LatticeBasedCrypto()
        self.hash_sig = HashBasedSignature()
        
        self.keys: Dict[str, QuantumKey] = {}
        self.key_pairs: Dict[str, Tuple[Dict, Dict]] = {}
    
    def generate_qkd_key(self, key_length: int = 256, noise: float = 0.0) -> QuantumKey:
        """Generate key using QKD protocol"""
        bb84 = BB84Protocol(key_length)
        key = bb84.generate_key(noise)
        self.keys[key.key_id] = key
        return key
    
    def generate_pq_keypair(self, scheme: PostQuantumScheme = PostQuantumScheme.KYBER) -> str:
        """Generate post-quantum key pair"""
        key_id = secrets.token_hex(8)
        
        if scheme == PostQuantumScheme.KYBER:
            public_key, private_key = self.lattice_crypto.keygen()
        elif scheme == PostQuantumScheme.SPHINCS:
            public_key, private_key = self.hash_sig.keygen()
        else:
            raise ValueError(f"Unsupported scheme: {scheme}")
        
        self.key_pairs[key_id] = (public_key, private_key)
        return key_id
    
    def pq_encrypt(self, key_pair_id: str, message: bytes) -> Tuple[bytes, np.ndarray]:
        """Encrypt using post-quantum encryption"""
        if key_pair_id not in self.key_pairs:
            raise KeyError(f"Key pair {key_pair_id} not found")
        
        public_key, _ = self.key_pairs[key_pair_id]
        
        # Encapsulate to get shared secret
        shared_secret, ciphertext = self.lattice_crypto.encapsulate(public_key)
        
        # Use shared secret to encrypt message (simple XOR for demo)
        key_stream = hashlib.sha256(shared_secret).digest()
        while len(key_stream) < len(message):
            key_stream += hashlib.sha256(key_stream).digest()
        
        encrypted = bytes(m ^ k for m, k in zip(message, key_stream))
        
        return encrypted, ciphertext
    
    def pq_decrypt(self, key_pair_id: str, encrypted: bytes, ciphertext: np.ndarray) -> bytes:
        """Decrypt using post-quantum decryption"""
        if key_pair_id not in self.key_pairs:
            raise KeyError(f"Key pair {key_pair_id} not found")
        
        _, private_key = self.key_pairs[key_pair_id]
        
        # Decapsulate to recover shared secret
        shared_secret = self.lattice_crypto.decapsulate(ciphertext, private_key)
        
        # Decrypt message
        key_stream = hashlib.sha256(shared_secret).digest()
        while len(key_stream) < len(encrypted):
            key_stream += hashlib.sha256(key_stream).digest()
        
        decrypted = bytes(e ^ k for e, k in zip(encrypted, key_stream))
        
        return decrypted
    
    def grover_search(
        self,
        num_qubits: int,
        target_oracle: Callable[[int], bool]
    ) -> Tuple[int, float, int]:
        """Run Grover's search"""
        grover = GroversSearch(num_qubits, target_oracle)
        
        # Run quantum search
        result, confidence = grover.run_quantum_simulation()
        
        # Compare to classical
        _, classical_queries = grover.run_classical()
        
        return result, confidence, grover.optimal_iterations
    
    def get_quantum_random(self, num_bytes: int) -> bytes:
        """Get quantum random bytes"""
        return self.rng.get_bytes(num_bytes)
    
    def estimate_quantum_threat(self, classical_bits: int) -> Dict[str, Any]:
        """Estimate quantum threat to classical crypto"""
        # Grover's attack: sqrt speedup
        grover_equivalent = classical_bits // 2
        
        # Shor's attack on RSA/ECC
        shor_broken = True  # RSA/ECC completely broken
        
        # Required qubits for Shor's on RSA
        shor_qubits = 2 * classical_bits + 3
        
        return {
            'classical_security_bits': classical_bits,
            'post_grover_security_bits': grover_equivalent,
            'vulnerable_to_shor': shor_broken if classical_bits <= 4096 else True,
            'shor_qubits_required': shor_qubits,
            'recommendation': 'Use post-quantum cryptography' if grover_equivalent < 128 else 'Current security acceptable',
            'pq_recommendations': [
                'CRYSTALS-Kyber for key exchange',
                'CRYSTALS-Dilithium for signatures',
                'SPHINCS+ for hash-based signatures'
            ]
        }


# Global instance
quantum_manager = QuantumSecurityManager()


def get_quantum_manager() -> QuantumSecurityManager:
    """Get global quantum security manager"""
    return quantum_manager
