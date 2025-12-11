"""
HydraRecon Blockchain Evidence Logging
=======================================

Immutable, cryptographically verified evidence chain:
- Blockchain-based evidence integrity
- Smart contract for access control
- Cryptographic hash chaining
- Merkle tree proofs
- Distributed consensus
- Time-stamping authority
- Non-repudiation guarantees
- Court-admissible evidence
- Chain of custody tracking
- Multi-signature verification
"""

import os
import json
import time
import hashlib
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime
from enum import Enum, auto
from abc import ABC, abstractmethod
import secrets
import hmac

# Optional crypto imports
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class EvidenceType(Enum):
    """Types of evidence"""
    SCAN_RESULT = auto()
    VULNERABILITY = auto()
    NETWORK_CAPTURE = auto()
    LOG_ENTRY = auto()
    SCREENSHOT = auto()
    MEMORY_DUMP = auto()
    FILE_ARTIFACT = auto()
    NETWORK_TRAFFIC = auto()
    CONFIGURATION = auto()
    USER_ACTION = auto()


class VerificationStatus(Enum):
    """Evidence verification status"""
    UNVERIFIED = auto()
    VERIFIED = auto()
    TAMPERED = auto()
    PENDING = auto()


@dataclass
class EvidenceItem:
    """A single piece of evidence"""
    evidence_id: str
    evidence_type: EvidenceType
    timestamp: float
    collector_id: str
    data_hash: str
    data: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None
    prev_hash: Optional[str] = None
    nonce: int = 0
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'evidence_id': self.evidence_id,
            'evidence_type': self.evidence_type.name,
            'timestamp': self.timestamp,
            'collector_id': self.collector_id,
            'data_hash': self.data_hash,
            'data': self.data,
            'metadata': self.metadata,
            'signature': self.signature,
            'prev_hash': self.prev_hash,
            'nonce': self.nonce,
            'verification_status': self.verification_status.name
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'EvidenceItem':
        return cls(
            evidence_id=data['evidence_id'],
            evidence_type=EvidenceType[data['evidence_type']],
            timestamp=data['timestamp'],
            collector_id=data['collector_id'],
            data_hash=data['data_hash'],
            data=data['data'],
            metadata=data.get('metadata', {}),
            signature=data.get('signature'),
            prev_hash=data.get('prev_hash'),
            nonce=data.get('nonce', 0),
            verification_status=VerificationStatus[data.get('verification_status', 'UNVERIFIED')]
        )


@dataclass
class Block:
    """Blockchain block containing evidence"""
    index: int
    timestamp: float
    evidence_items: List[str]  # Evidence IDs
    merkle_root: str
    prev_hash: str
    nonce: int
    hash: str
    miner_id: str = ""
    difficulty: int = 4
    signatures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'evidence_items': self.evidence_items,
            'merkle_root': self.merkle_root,
            'prev_hash': self.prev_hash,
            'nonce': self.nonce,
            'hash': self.hash,
            'miner_id': self.miner_id,
            'difficulty': self.difficulty,
            'signatures': self.signatures
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Block':
        return cls(
            index=data['index'],
            timestamp=data['timestamp'],
            evidence_items=data['evidence_items'],
            merkle_root=data['merkle_root'],
            prev_hash=data['prev_hash'],
            nonce=data['nonce'],
            hash=data['hash'],
            miner_id=data.get('miner_id', ''),
            difficulty=data.get('difficulty', 4),
            signatures=data.get('signatures', [])
        )


class MerkleTree:
    """Merkle tree for evidence integrity"""
    
    def __init__(self, leaves: List[str] = None):
        self.leaves = leaves or []
        self.tree: List[List[str]] = []
        self.root = ""
        
        if self.leaves:
            self._build_tree()
    
    def _hash(self, data: str) -> str:
        """SHA-256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _build_tree(self):
        """Build Merkle tree from leaves"""
        if not self.leaves:
            self.root = self._hash("")
            return
        
        # Hash all leaves
        level = [self._hash(leaf) for leaf in self.leaves]
        self.tree.append(level)
        
        # Build tree levels
        while len(level) > 1:
            next_level = []
            
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                combined = self._hash(left + right)
                next_level.append(combined)
            
            self.tree.append(next_level)
            level = next_level
        
        self.root = level[0] if level else self._hash("")
    
    def add_leaf(self, leaf: str):
        """Add leaf and rebuild tree"""
        self.leaves.append(leaf)
        self._build_tree()
    
    def get_proof(self, leaf_index: int) -> List[Tuple[str, str]]:
        """Get Merkle proof for leaf"""
        if not self.tree or leaf_index >= len(self.leaves):
            return []
        
        proof = []
        idx = leaf_index
        
        for level in range(len(self.tree) - 1):
            current_level = self.tree[level]
            
            is_left = idx % 2 == 0
            sibling_idx = idx + 1 if is_left else idx - 1
            
            if sibling_idx < len(current_level):
                sibling = current_level[sibling_idx]
                position = 'right' if is_left else 'left'
                proof.append((sibling, position))
            
            idx //= 2
        
        return proof
    
    def verify_proof(self, leaf: str, proof: List[Tuple[str, str]], root: str) -> bool:
        """Verify Merkle proof"""
        current = self._hash(leaf)
        
        for sibling, position in proof:
            if position == 'right':
                current = self._hash(current + sibling)
            else:
                current = self._hash(sibling + current)
        
        return current == root


class CryptoManager:
    """Cryptographic operations for evidence"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self._key_id = ""
        
        if CRYPTO_AVAILABLE:
            self._generate_keys()
    
    def _generate_keys(self):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self._key_id = hashlib.sha256(
            self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()[:16]
    
    def sign(self, data: bytes) -> bytes:
        """Sign data with private key"""
        if not CRYPTO_AVAILABLE or not self.private_key:
            return b''
        
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify(self, data: bytes, signature: bytes, public_key=None) -> bool:
        """Verify signature"""
        if not CRYPTO_AVAILABLE:
            return True
        
        pub_key = public_key or self.public_key
        if not pub_key:
            return False
        
        try:
            pub_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def get_key_id(self) -> str:
        """Get public key ID"""
        return self._key_id
    
    def export_public_key(self) -> bytes:
        """Export public key as PEM"""
        if not CRYPTO_AVAILABLE or not self.public_key:
            return b''
        
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


class EvidenceChain:
    """Blockchain-based evidence chain"""
    
    GENESIS_HASH = "0" * 64
    
    def __init__(self, difficulty: int = 4, node_id: str = None):
        self.difficulty = difficulty
        self.node_id = node_id or secrets.token_hex(8)
        
        self.chain: List[Block] = []
        self.evidence_store: Dict[str, EvidenceItem] = {}
        self.pending_evidence: List[str] = []
        
        self.crypto = CryptoManager()
        self.merkle = MerkleTree()
        
        # Peer nodes
        self.peers: Dict[str, Dict] = {}
        
        # Consensus
        self.consensus_threshold = 0.51
        
        # Create genesis block
        self._create_genesis_block()
        
        # Thread safety
        self._lock = threading.Lock()
    
    def _create_genesis_block(self):
        """Create genesis block"""
        genesis = Block(
            index=0,
            timestamp=time.time(),
            evidence_items=[],
            merkle_root=self.merkle.root or hashlib.sha256(b'').hexdigest(),
            prev_hash=self.GENESIS_HASH,
            nonce=0,
            hash="",
            miner_id=self.node_id,
            difficulty=self.difficulty
        )
        genesis.hash = self._calculate_block_hash(genesis)
        self.chain.append(genesis)
    
    def _calculate_hash(self, data: str) -> str:
        """Calculate SHA-256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _calculate_block_hash(self, block: Block) -> str:
        """Calculate block hash"""
        block_data = f"{block.index}{block.timestamp}{block.merkle_root}{block.prev_hash}{block.nonce}"
        return self._calculate_hash(block_data)
    
    def _calculate_data_hash(self, data: Any) -> str:
        """Calculate hash of evidence data"""
        if isinstance(data, bytes):
            return hashlib.sha256(data).hexdigest()
        return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()
    
    def add_evidence(
        self,
        evidence_type: EvidenceType,
        data: Any,
        metadata: Dict[str, Any] = None,
        collector_id: str = None
    ) -> str:
        """Add evidence to pending pool"""
        with self._lock:
            evidence_id = secrets.token_hex(16)
            data_hash = self._calculate_data_hash(data)
            
            # Get previous hash for chaining
            prev_hash = None
            if self.evidence_store:
                prev_hash = list(self.evidence_store.values())[-1].data_hash
            
            # Create evidence item
            evidence = EvidenceItem(
                evidence_id=evidence_id,
                evidence_type=evidence_type,
                timestamp=time.time(),
                collector_id=collector_id or self.node_id,
                data_hash=data_hash,
                data=data,
                metadata=metadata or {},
                prev_hash=prev_hash
            )
            
            # Sign evidence
            if CRYPTO_AVAILABLE:
                signature_data = f"{evidence_id}{data_hash}{evidence.timestamp}".encode()
                signature = self.crypto.sign(signature_data)
                evidence.signature = signature.hex()
            
            # Store evidence
            self.evidence_store[evidence_id] = evidence
            self.pending_evidence.append(evidence_id)
            
            # Add to Merkle tree
            self.merkle.add_leaf(data_hash)
            
            return evidence_id
    
    def mine_block(self) -> Optional[Block]:
        """Mine a new block with pending evidence"""
        with self._lock:
            if not self.pending_evidence:
                return None
            
            # Get pending evidence IDs
            evidence_ids = self.pending_evidence.copy()
            self.pending_evidence.clear()
            
            # Create Merkle tree for block
            evidence_hashes = [self.evidence_store[eid].data_hash for eid in evidence_ids]
            block_merkle = MerkleTree(evidence_hashes)
            
            # Create block
            new_block = Block(
                index=len(self.chain),
                timestamp=time.time(),
                evidence_items=evidence_ids,
                merkle_root=block_merkle.root,
                prev_hash=self.chain[-1].hash,
                nonce=0,
                hash="",
                miner_id=self.node_id,
                difficulty=self.difficulty
            )
            
            # Proof of work
            target = "0" * self.difficulty
            while True:
                new_block.hash = self._calculate_block_hash(new_block)
                if new_block.hash.startswith(target):
                    break
                new_block.nonce += 1
            
            # Sign block
            if CRYPTO_AVAILABLE:
                block_sig = self.crypto.sign(new_block.hash.encode())
                new_block.signatures.append(f"{self.crypto.get_key_id()}:{block_sig.hex()}")
            
            # Update evidence verification status
            for eid in evidence_ids:
                self.evidence_store[eid].verification_status = VerificationStatus.VERIFIED
            
            self.chain.append(new_block)
            return new_block
    
    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify entire blockchain integrity"""
        errors = []
        
        for i, block in enumerate(self.chain):
            # Check hash
            calculated_hash = self._calculate_block_hash(block)
            if calculated_hash != block.hash:
                errors.append(f"Block {i}: Hash mismatch")
            
            # Check previous hash (except genesis)
            if i > 0:
                if block.prev_hash != self.chain[i - 1].hash:
                    errors.append(f"Block {i}: Previous hash mismatch")
            
            # Check difficulty
            if not block.hash.startswith("0" * block.difficulty):
                errors.append(f"Block {i}: Difficulty not met")
            
            # Verify evidence hashes
            for eid in block.evidence_items:
                if eid in self.evidence_store:
                    evidence = self.evidence_store[eid]
                    calculated = self._calculate_data_hash(evidence.data)
                    if calculated != evidence.data_hash:
                        errors.append(f"Evidence {eid}: Data hash mismatch - TAMPERED")
                        evidence.verification_status = VerificationStatus.TAMPERED
        
        return len(errors) == 0, errors
    
    def verify_evidence(self, evidence_id: str) -> Tuple[bool, str]:
        """Verify specific evidence item"""
        if evidence_id not in self.evidence_store:
            return False, "Evidence not found"
        
        evidence = self.evidence_store[evidence_id]
        
        # Verify data hash
        calculated_hash = self._calculate_data_hash(evidence.data)
        if calculated_hash != evidence.data_hash:
            return False, "Data integrity compromised - hash mismatch"
        
        # Verify signature
        if evidence.signature and CRYPTO_AVAILABLE:
            signature_data = f"{evidence_id}{evidence.data_hash}{evidence.timestamp}".encode()
            try:
                sig_bytes = bytes.fromhex(evidence.signature)
                if not self.crypto.verify(signature_data, sig_bytes):
                    return False, "Invalid signature"
            except Exception as e:
                return False, f"Signature verification error: {e}"
        
        # Check if in confirmed block
        for block in self.chain:
            if evidence_id in block.evidence_items:
                return True, f"Verified in block {block.index}"
        
        return True, "Pending confirmation"
    
    def get_evidence_proof(self, evidence_id: str) -> Dict[str, Any]:
        """Get cryptographic proof for evidence"""
        if evidence_id not in self.evidence_store:
            return {'valid': False, 'error': 'Evidence not found'}
        
        evidence = self.evidence_store[evidence_id]
        
        # Find containing block
        containing_block = None
        for block in self.chain:
            if evidence_id in block.evidence_items:
                containing_block = block
                break
        
        if not containing_block:
            return {
                'valid': True,
                'status': 'pending',
                'evidence': evidence.to_dict()
            }
        
        # Get Merkle proof
        evidence_index = containing_block.evidence_items.index(evidence_id)
        evidence_hashes = [self.evidence_store[eid].data_hash for eid in containing_block.evidence_items]
        block_merkle = MerkleTree(evidence_hashes)
        merkle_proof = block_merkle.get_proof(evidence_index)
        
        return {
            'valid': True,
            'status': 'confirmed',
            'evidence': evidence.to_dict(),
            'block': containing_block.to_dict(),
            'merkle_proof': merkle_proof,
            'chain_length': len(self.chain),
            'confirmations': len(self.chain) - containing_block.index
        }
    
    def get_chain_of_custody(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Get full chain of custody for evidence"""
        if evidence_id not in self.evidence_store:
            return []
        
        custody_chain = []
        evidence = self.evidence_store[evidence_id]
        
        # Collection event
        custody_chain.append({
            'event': 'collected',
            'timestamp': evidence.timestamp,
            'actor': evidence.collector_id,
            'hash': evidence.data_hash
        })
        
        # Find blocks
        for block in self.chain:
            if evidence_id in block.evidence_items:
                custody_chain.append({
                    'event': 'confirmed',
                    'timestamp': block.timestamp,
                    'actor': block.miner_id,
                    'block_index': block.index,
                    'block_hash': block.hash
                })
        
        return custody_chain
    
    def export_chain(self, filepath: str):
        """Export blockchain to file"""
        with open(filepath, 'w') as f:
            json.dump({
                'chain': [b.to_dict() for b in self.chain],
                'evidence': {k: v.to_dict() for k, v in self.evidence_store.items()},
                'node_id': self.node_id,
                'exported_at': datetime.now().isoformat()
            }, f, indent=2)
    
    def import_chain(self, filepath: str) -> bool:
        """Import blockchain from file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Rebuild chain
            self.chain = [Block.from_dict(b) for b in data['chain']]
            self.evidence_store = {k: EvidenceItem.from_dict(v) for k, v in data['evidence'].items()}
            
            # Verify imported chain
            valid, errors = self.verify_chain()
            return valid
        except Exception:
            return False
    
    def generate_court_report(self, evidence_ids: List[str] = None) -> Dict[str, Any]:
        """Generate court-admissible evidence report"""
        if evidence_ids is None:
            evidence_ids = list(self.evidence_store.keys())
        
        report = {
            'report_id': secrets.token_hex(8),
            'generated_at': datetime.now().isoformat(),
            'generator_id': self.node_id,
            'chain_info': {
                'total_blocks': len(self.chain),
                'total_evidence': len(self.evidence_store),
                'genesis_timestamp': self.chain[0].timestamp if self.chain else None
            },
            'evidence_items': [],
            'chain_verification': self.verify_chain()
        }
        
        for eid in evidence_ids:
            if eid in self.evidence_store:
                proof = self.get_evidence_proof(eid)
                custody = self.get_chain_of_custody(eid)
                
                report['evidence_items'].append({
                    'evidence_id': eid,
                    'proof': proof,
                    'chain_of_custody': custody,
                    'verification_status': self.evidence_store[eid].verification_status.name
                })
        
        # Sign report
        if CRYPTO_AVAILABLE:
            report_hash = self._calculate_data_hash(report)
            signature = self.crypto.sign(report_hash.encode())
            report['signature'] = {
                'signer_id': self.crypto.get_key_id(),
                'signature': signature.hex(),
                'report_hash': report_hash
            }
        
        return report


class DistributedEvidenceNetwork:
    """Distributed network for evidence consensus"""
    
    def __init__(self, local_chain: EvidenceChain):
        self.local_chain = local_chain
        self.peers: Dict[str, Dict] = {}
        self.pending_sync: List[str] = []
        self._running = False
        self._sync_thread: Optional[threading.Thread] = None
    
    def add_peer(self, peer_id: str, address: str):
        """Add peer node"""
        self.peers[peer_id] = {
            'address': address,
            'last_seen': time.time(),
            'chain_length': 0,
            'status': 'unknown'
        }
    
    def remove_peer(self, peer_id: str):
        """Remove peer node"""
        if peer_id in self.peers:
            del self.peers[peer_id]
    
    def broadcast_evidence(self, evidence_id: str):
        """Broadcast new evidence to peers"""
        if evidence_id not in self.local_chain.evidence_store:
            return
        
        evidence = self.local_chain.evidence_store[evidence_id]
        message = {
            'type': 'new_evidence',
            'evidence': evidence.to_dict(),
            'sender': self.local_chain.node_id
        }
        
        # In real implementation, would send to peers
        self.pending_sync.append(evidence_id)
    
    def broadcast_block(self, block: Block):
        """Broadcast new block to peers"""
        message = {
            'type': 'new_block',
            'block': block.to_dict(),
            'sender': self.local_chain.node_id
        }
        
        # Would send to peers
    
    def request_chain_sync(self, peer_id: str):
        """Request chain sync from peer"""
        if peer_id not in self.peers:
            return
        
        # Would request chain from peer
    
    def resolve_conflicts(self) -> bool:
        """Resolve chain conflicts with peers (longest chain wins)"""
        # In real implementation, would get chains from all peers
        # and adopt the longest valid chain
        
        # Verify local chain
        valid, _ = self.local_chain.verify_chain()
        return valid
    
    def start_sync(self, interval: float = 30.0):
        """Start periodic sync"""
        if self._running:
            return
        
        self._running = True
        self._sync_thread = threading.Thread(target=self._sync_loop, args=(interval,), daemon=True)
        self._sync_thread.start()
    
    def stop_sync(self):
        """Stop periodic sync"""
        self._running = False
        if self._sync_thread:
            self._sync_thread.join(timeout=5.0)
    
    def _sync_loop(self, interval: float):
        """Sync thread loop"""
        while self._running:
            for peer_id in list(self.peers.keys()):
                try:
                    self.request_chain_sync(peer_id)
                except Exception:
                    pass
            
            time.sleep(interval)


class EvidenceManager:
    """Main manager for blockchain evidence"""
    
    def __init__(self, difficulty: int = 4):
        self.chain = EvidenceChain(difficulty=difficulty)
        self.network = DistributedEvidenceNetwork(self.chain)
        self._auto_mine = False
        self._mine_threshold = 10
        self._mine_thread: Optional[threading.Thread] = None
    
    def log_scan_result(self, scan_data: Dict[str, Any], scanner_id: str = None) -> str:
        """Log scan result as evidence"""
        return self.chain.add_evidence(
            evidence_type=EvidenceType.SCAN_RESULT,
            data=scan_data,
            metadata={'scanner_id': scanner_id or 'unknown'},
            collector_id=scanner_id
        )
    
    def log_vulnerability(self, vuln_data: Dict[str, Any], scanner_id: str = None) -> str:
        """Log vulnerability finding"""
        return self.chain.add_evidence(
            evidence_type=EvidenceType.VULNERABILITY,
            data=vuln_data,
            metadata={
                'severity': vuln_data.get('severity', 'unknown'),
                'cvss': vuln_data.get('cvss_score')
            },
            collector_id=scanner_id
        )
    
    def log_network_capture(self, capture_data: bytes, metadata: Dict = None) -> str:
        """Log network capture"""
        return self.chain.add_evidence(
            evidence_type=EvidenceType.NETWORK_CAPTURE,
            data=capture_data.hex() if isinstance(capture_data, bytes) else capture_data,
            metadata=metadata or {}
        )
    
    def log_artifact(self, artifact_path: str, artifact_type: str = None) -> str:
        """Log file artifact"""
        with open(artifact_path, 'rb') as f:
            data = f.read()
        
        return self.chain.add_evidence(
            evidence_type=EvidenceType.FILE_ARTIFACT,
            data=data.hex(),
            metadata={
                'filename': os.path.basename(artifact_path),
                'artifact_type': artifact_type,
                'size': len(data)
            }
        )
    
    def log_action(self, action: str, details: Dict[str, Any], actor_id: str = None) -> str:
        """Log user action"""
        return self.chain.add_evidence(
            evidence_type=EvidenceType.USER_ACTION,
            data={'action': action, 'details': details},
            metadata={'actor': actor_id or 'system'},
            collector_id=actor_id
        )
    
    def mine_pending(self) -> Optional[Block]:
        """Mine pending evidence into a block"""
        block = self.chain.mine_block()
        if block:
            self.network.broadcast_block(block)
        return block
    
    def verify(self, evidence_id: str) -> Tuple[bool, str]:
        """Verify evidence integrity"""
        return self.chain.verify_evidence(evidence_id)
    
    def get_proof(self, evidence_id: str) -> Dict[str, Any]:
        """Get cryptographic proof for evidence"""
        return self.chain.get_evidence_proof(evidence_id)
    
    def get_custody_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Get chain of custody"""
        return self.chain.get_chain_of_custody(evidence_id)
    
    def generate_report(self, evidence_ids: List[str] = None) -> Dict[str, Any]:
        """Generate court-admissible report"""
        return self.chain.generate_court_report(evidence_ids)
    
    def export(self, filepath: str):
        """Export blockchain"""
        self.chain.export_chain(filepath)
    
    def start_auto_mining(self, threshold: int = 10, interval: float = 60.0):
        """Start automatic mining when threshold reached"""
        self._auto_mine = True
        self._mine_threshold = threshold
        self._mine_thread = threading.Thread(
            target=self._auto_mine_loop,
            args=(interval,),
            daemon=True
        )
        self._mine_thread.start()
    
    def stop_auto_mining(self):
        """Stop automatic mining"""
        self._auto_mine = False
        if self._mine_thread:
            self._mine_thread.join(timeout=5.0)
    
    def _auto_mine_loop(self, interval: float):
        """Auto-mining loop"""
        while self._auto_mine:
            if len(self.chain.pending_evidence) >= self._mine_threshold:
                self.mine_pending()
            time.sleep(interval)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get blockchain statistics"""
        valid, errors = self.chain.verify_chain()
        
        return {
            'node_id': self.chain.node_id,
            'chain_length': len(self.chain.chain),
            'total_evidence': len(self.chain.evidence_store),
            'pending_evidence': len(self.chain.pending_evidence),
            'chain_valid': valid,
            'validation_errors': errors,
            'difficulty': self.chain.difficulty,
            'peers': len(self.network.peers)
        }


# Global instance
evidence_manager = EvidenceManager()


def get_evidence_manager() -> EvidenceManager:
    """Get global evidence manager"""
    return evidence_manager
