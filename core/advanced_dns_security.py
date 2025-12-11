#!/usr/bin/env python3
"""
HydraRecon Advanced DNS Security Module
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE DNS SECURITY - DNS Tunneling Detection, DNSSEC Analysis,        █
█  DNS Rebinding Protection, Threat Intelligence & DNS Forensics              █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import re


class DNSRecordType(Enum):
    """DNS record types"""
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NAPTR = 35
    DS = 43
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    NSEC3 = 50
    TLSA = 52
    CAA = 257


class ThreatType(Enum):
    """DNS threat types"""
    TUNNELING = "tunneling"
    REBINDING = "rebinding"
    EXFILTRATION = "exfiltration"
    DGA = "dga"
    FAST_FLUX = "fast_flux"
    CACHE_POISONING = "cache_poisoning"
    TYPOSQUATTING = "typosquatting"
    HOMOGRAPH = "homograph"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    DANGLING_DNS = "dangling_dns"


class SeverityLevel(Enum):
    """Security finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DNSRecord:
    """DNS record data"""
    name: str
    record_type: DNSRecordType
    value: str
    ttl: int
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = ""


@dataclass
class DNSQuery:
    """DNS query information"""
    query_id: int
    domain: str
    query_type: DNSRecordType
    timestamp: datetime
    source_ip: str
    dest_ip: str
    response_time_ms: float = 0
    response_code: int = 0


@dataclass
class DNSThreat:
    """DNS threat detection result"""
    threat_type: ThreatType
    domain: str
    severity: SeverityLevel
    confidence: float
    indicators: List[str]
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class DNSSECStatus:
    """DNSSEC validation status"""
    domain: str
    dnssec_enabled: bool
    valid: bool
    chain_of_trust: List[Dict[str, Any]]
    ds_records: List[str]
    dnskey_records: List[str]
    issues: List[str]


class DNSParser:
    """DNS packet parser"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_query(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNS query packet"""
        try:
            if len(data) < 12:
                return None
            
            # DNS header
            query_id = struct.unpack("!H", data[0:2])[0]
            flags = struct.unpack("!H", data[2:4])[0]
            qd_count = struct.unpack("!H", data[4:6])[0]
            an_count = struct.unpack("!H", data[6:8])[0]
            ns_count = struct.unpack("!H", data[8:10])[0]
            ar_count = struct.unpack("!H", data[10:12])[0]
            
            # Parse flags
            qr = (flags >> 15) & 0x1
            opcode = (flags >> 11) & 0xf
            aa = (flags >> 10) & 0x1
            tc = (flags >> 9) & 0x1
            rd = (flags >> 8) & 0x1
            ra = (flags >> 7) & 0x1
            rcode = flags & 0xf
            
            # Parse question section
            offset = 12
            questions = []
            
            for _ in range(qd_count):
                name, offset = self._parse_name(data, offset)
                if offset + 4 > len(data):
                    break
                qtype = struct.unpack("!H", data[offset:offset+2])[0]
                qclass = struct.unpack("!H", data[offset+2:offset+4])[0]
                offset += 4
                
                questions.append({
                    "name": name,
                    "type": qtype,
                    "class": qclass
                })
            
            return {
                "query_id": query_id,
                "is_response": bool(qr),
                "opcode": opcode,
                "authoritative": bool(aa),
                "truncated": bool(tc),
                "recursion_desired": bool(rd),
                "recursion_available": bool(ra),
                "response_code": rcode,
                "questions": questions,
                "answer_count": an_count,
                "authority_count": ns_count,
                "additional_count": ar_count
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing DNS query: {e}")
            return None
    
    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parse DNS name from packet"""
        labels = []
        original_offset = offset
        jumped = False
        
        while offset < len(data):
            length = data[offset]
            
            if length == 0:
                offset += 1
                break
            
            # Compression pointer
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                jumped = True
                offset = pointer
                continue
            
            offset += 1
            if offset + length > len(data):
                break
            
            labels.append(data[offset:offset + length].decode('utf-8', errors='ignore'))
            offset += length
        
        name = '.'.join(labels)
        return name, original_offset if jumped else offset


class DNSTunnelingDetector:
    """Detect DNS tunneling attempts"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.query_history: Dict[str, List[DNSQuery]] = {}
        
        # Detection thresholds
        self.entropy_threshold = 3.5
        self.label_length_threshold = 40
        self.query_frequency_threshold = 100  # queries per minute
        self.subdomain_depth_threshold = 5
    
    def analyze_query(self, query: DNSQuery) -> Optional[DNSThreat]:
        """Analyze DNS query for tunneling indicators"""
        indicators = []
        confidence = 0.0
        
        # Check subdomain entropy
        entropy = self._calculate_entropy(query.domain)
        if entropy > self.entropy_threshold:
            indicators.append(f"High subdomain entropy: {entropy:.2f}")
            confidence += 0.25
        
        # Check label length
        labels = query.domain.split('.')
        long_labels = [l for l in labels if len(l) > self.label_length_threshold]
        if long_labels:
            indicators.append(f"Long labels detected: {len(long_labels)}")
            confidence += 0.2
        
        # Check subdomain depth
        if len(labels) > self.subdomain_depth_threshold:
            indicators.append(f"Deep subdomain nesting: {len(labels)} levels")
            confidence += 0.15
        
        # Check for base64/hex encoding patterns
        if self._has_encoded_pattern(query.domain):
            indicators.append("Encoded data pattern detected")
            confidence += 0.3
        
        # Check query frequency
        freq = self._check_frequency(query)
        if freq > self.query_frequency_threshold:
            indicators.append(f"High query frequency: {freq}/min")
            confidence += 0.25
        
        # Check for TXT/NULL record requests (common in tunneling)
        if query.query_type in [DNSRecordType.TXT, DNSRecordType.MX]:
            indicators.append(f"Suspicious record type: {query.query_type.name}")
            confidence += 0.1
        
        if confidence > 0.5:
            severity = SeverityLevel.HIGH if confidence > 0.75 else SeverityLevel.MEDIUM
            return DNSThreat(
                threat_type=ThreatType.TUNNELING,
                domain=query.domain,
                severity=severity,
                confidence=min(confidence, 1.0),
                indicators=indicators,
                details={
                    "entropy": entropy,
                    "label_count": len(labels),
                    "query_type": query.query_type.name,
                    "source_ip": query.source_ip
                },
                mitre_techniques=["T1071.004"]  # Application Layer Protocol: DNS
            )
        
        return None
    
    def _calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain string"""
        # Remove TLD for entropy calculation
        parts = domain.split('.')
        if len(parts) > 1:
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else parts[0]
        else:
            subdomain = domain
        
        if not subdomain:
            return 0.0
        
        # Calculate frequency of each character
        freq = {}
        for char in subdomain.lower():
            if char != '.':
                freq[char] = freq.get(char, 0) + 1
        
        length = len(subdomain.replace('.', ''))
        if length == 0:
            return 0.0
        
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability ** 0.5 if probability else 0)
        
        # Use log2 for standard entropy
        import math
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_encoded_pattern(self, domain: str) -> bool:
        """Check for base64 or hex encoding patterns"""
        subdomain = domain.split('.')[0]
        
        # Check for base64 pattern
        base64_pattern = r'^[A-Za-z0-9+/=]{16,}$'
        if re.match(base64_pattern, subdomain.replace('-', '')):
            return True
        
        # Check for hex pattern
        hex_pattern = r'^[0-9a-fA-F]{16,}$'
        if re.match(hex_pattern, subdomain):
            return True
        
        # Check consonant-to-vowel ratio (encoded data is usually low)
        vowels = set('aeiouAEIOU')
        consonants = len([c for c in subdomain if c.isalpha() and c not in vowels])
        total_alpha = len([c for c in subdomain if c.isalpha()])
        
        if total_alpha > 10:
            vowel_ratio = (total_alpha - consonants) / total_alpha
            if vowel_ratio < 0.15:  # Very few vowels suggests encoded data
                return True
        
        return False
    
    def _check_frequency(self, query: DNSQuery) -> int:
        """Check query frequency for domain"""
        base_domain = '.'.join(query.domain.split('.')[-2:])
        
        if base_domain not in self.query_history:
            self.query_history[base_domain] = []
        
        # Add current query
        self.query_history[base_domain].append(query)
        
        # Remove queries older than 1 minute
        cutoff = datetime.now() - timedelta(minutes=1)
        self.query_history[base_domain] = [
            q for q in self.query_history[base_domain]
            if q.timestamp > cutoff
        ]
        
        return len(self.query_history[base_domain])


class DGADetector:
    """Detect Domain Generation Algorithm (DGA) domains"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common TLDs used by DGA
        self.dga_tlds = {'.com', '.net', '.org', '.info', '.biz', '.ru', '.cn', '.tk'}
        
        # Bigram frequencies for English
        self.common_bigrams = {
            'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
            'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar'
        }
    
    def analyze_domain(self, domain: str) -> Optional[DNSThreat]:
        """Analyze domain for DGA characteristics"""
        indicators = []
        confidence = 0.0
        
        # Extract main domain (without TLD)
        parts = domain.lower().split('.')
        if len(parts) < 2:
            return None
        
        main_domain = parts[-2] if len(parts) >= 2 else parts[0]
        
        # Check domain length
        if len(main_domain) > 15:
            indicators.append(f"Long domain name: {len(main_domain)} chars")
            confidence += 0.15
        
        # Check for all numeric
        if main_domain.isdigit():
            indicators.append("All numeric domain")
            confidence += 0.4
        
        # Check consonant ratio
        consonant_score = self._consonant_ratio(main_domain)
        if consonant_score > 0.75:
            indicators.append(f"High consonant ratio: {consonant_score:.2f}")
            confidence += 0.25
        
        # Check bigram frequency
        bigram_score = self._bigram_score(main_domain)
        if bigram_score < 0.1:
            indicators.append(f"Unusual character patterns (bigram: {bigram_score:.2f})")
            confidence += 0.25
        
        # Check for repeating patterns
        if self._has_repeating_pattern(main_domain):
            indicators.append("Repeating character patterns")
            confidence += 0.2
        
        # Check digit distribution
        digit_ratio = sum(1 for c in main_domain if c.isdigit()) / len(main_domain)
        if 0.2 < digit_ratio < 0.6:  # Mixed alphanumeric common in DGA
            indicators.append(f"Mixed alphanumeric pattern: {digit_ratio:.2f}")
            confidence += 0.2
        
        # Check for known DGA TLDs
        tld = '.' + parts[-1]
        if tld in self.dga_tlds:
            indicators.append(f"Common DGA TLD: {tld}")
            confidence += 0.1
        
        if confidence > 0.5:
            severity = SeverityLevel.HIGH if confidence > 0.75 else SeverityLevel.MEDIUM
            return DNSThreat(
                threat_type=ThreatType.DGA,
                domain=domain,
                severity=severity,
                confidence=min(confidence, 1.0),
                indicators=indicators,
                details={
                    "main_domain": main_domain,
                    "consonant_ratio": consonant_score,
                    "bigram_score": bigram_score,
                    "digit_ratio": digit_ratio
                },
                mitre_techniques=["T1568.002"]  # Dynamic Resolution: Domain Generation Algorithms
            )
        
        return None
    
    def _consonant_ratio(self, s: str) -> float:
        """Calculate consonant to total letter ratio"""
        vowels = set('aeiou')
        letters = [c for c in s.lower() if c.isalpha()]
        if not letters:
            return 0.0
        consonants = [c for c in letters if c not in vowels]
        return len(consonants) / len(letters)
    
    def _bigram_score(self, s: str) -> float:
        """Calculate how many common bigrams appear in string"""
        if len(s) < 2:
            return 0.0
        
        bigrams = [s[i:i+2].lower() for i in range(len(s) - 1)]
        common_count = sum(1 for b in bigrams if b in self.common_bigrams)
        return common_count / len(bigrams)
    
    def _has_repeating_pattern(self, s: str) -> bool:
        """Check for repeating character patterns"""
        for pattern_len in range(2, len(s) // 2 + 1):
            pattern = s[:pattern_len]
            if pattern * (len(s) // pattern_len) == s[:len(pattern) * (len(s) // pattern_len)]:
                return True
        return False


class DNSRebindingDetector:
    """Detect DNS rebinding attacks"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.dns_cache: Dict[str, List[Tuple[str, datetime]]] = {}
        self.ttl_cache: Dict[str, int] = {}
        
        # Private IP ranges
        self.private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),
            ('169.254.0.0', '169.254.255.255'),
        ]
    
    def check_rebinding(self, domain: str, ip: str, ttl: int) -> Optional[DNSThreat]:
        """Check for DNS rebinding attempt"""
        indicators = []
        
        # Track resolution history
        if domain not in self.dns_cache:
            self.dns_cache[domain] = []
        
        # Add current resolution
        self.dns_cache[domain].append((ip, datetime.now()))
        self.ttl_cache[domain] = ttl
        
        # Check for very low TTL (common in rebinding)
        if ttl < 60:
            indicators.append(f"Very low TTL: {ttl}s")
        
        # Check for IP changes
        recent_ips = [r[0] for r in self.dns_cache[domain][-10:]]
        unique_ips = set(recent_ips)
        
        if len(unique_ips) > 1:
            # Check if resolving to both public and private IPs
            has_public = False
            has_private = False
            
            for resolved_ip in unique_ips:
                if self._is_private_ip(resolved_ip):
                    has_private = True
                else:
                    has_public = True
            
            if has_public and has_private:
                indicators.append("Domain resolves to both public and private IPs")
                indicators.append(f"Observed IPs: {', '.join(unique_ips)}")
                
                return DNSThreat(
                    threat_type=ThreatType.REBINDING,
                    domain=domain,
                    severity=SeverityLevel.HIGH,
                    confidence=0.9,
                    indicators=indicators,
                    details={
                        "current_ip": ip,
                        "all_ips": list(unique_ips),
                        "ttl": ttl,
                        "has_private": has_private,
                        "has_public": has_public
                    },
                    mitre_techniques=["T1557"]  # Man-in-the-Middle
                )
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            octets = [int(o) for o in ip.split('.')]
            ip_int = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
            
            for start, end in self.private_ranges:
                start_octets = [int(o) for o in start.split('.')]
                end_octets = [int(o) for o in end.split('.')]
                
                start_int = (start_octets[0] << 24) + (start_octets[1] << 16) + (start_octets[2] << 8) + start_octets[3]
                end_int = (end_octets[0] << 24) + (end_octets[1] << 16) + (end_octets[2] << 8) + end_octets[3]
                
                if start_int <= ip_int <= end_int:
                    return True
            
            return False
        except (ValueError, IndexError):
            return False


class DNSSECValidator:
    """DNSSEC validation and analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def validate_domain(self, domain: str) -> DNSSECStatus:
        """Validate DNSSEC for a domain"""
        issues = []
        chain_of_trust = []
        ds_records = []
        dnskey_records = []
        dnssec_enabled = False
        valid = False
        
        try:
            # Query for DNSKEY records
            dnskey_result = await self._query_record(domain, DNSRecordType.DNSKEY)
            if dnskey_result:
                dnssec_enabled = True
                dnskey_records = dnskey_result
            
            # Query for DS records at parent
            parent_domain = '.'.join(domain.split('.')[1:])
            if parent_domain:
                ds_result = await self._query_record(domain, DNSRecordType.DS)
                if ds_result:
                    ds_records = ds_result
            
            # Query for RRSIG
            rrsig_result = await self._query_record(domain, DNSRecordType.RRSIG)
            if rrsig_result:
                chain_of_trust.append({
                    "type": "RRSIG",
                    "records": len(rrsig_result)
                })
            
            # Validate chain of trust
            if dnssec_enabled and dnskey_records and ds_records:
                # Simplified validation - in production, verify cryptographic signatures
                valid = True
                chain_of_trust.append({
                    "type": "DS",
                    "parent": parent_domain,
                    "count": len(ds_records)
                })
            elif dnssec_enabled and not ds_records:
                issues.append("DNSKEY present but no DS record at parent - chain broken")
            
            # Check for algorithm issues
            if dnskey_records:
                for record in dnskey_records:
                    if "algorithm=5" in record.lower() or "algorithm=7" in record.lower():
                        issues.append("Using deprecated RSA/SHA-1 algorithm")
            
        except Exception as e:
            self.logger.error(f"DNSSEC validation error: {e}")
            issues.append(f"Validation error: {str(e)}")
        
        return DNSSECStatus(
            domain=domain,
            dnssec_enabled=dnssec_enabled,
            valid=valid,
            chain_of_trust=chain_of_trust,
            ds_records=ds_records,
            dnskey_records=dnskey_records,
            issues=issues
        )
    
    async def _query_record(self, domain: str, record_type: DNSRecordType) -> List[str]:
        """Query DNS for specific record type"""
        # Placeholder for actual DNS query implementation
        # In production, use dnspython or similar library
        return []


class SubdomainTakeoverScanner:
    """Detect subdomain takeover vulnerabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Known vulnerable fingerprints
        self.takeover_fingerprints = {
            "github": {
                "cname": ["github.io", "github.com"],
                "response": "There isn't a GitHub Pages site here"
            },
            "heroku": {
                "cname": ["herokuapp.com", "herokussl.com"],
                "response": "No such app"
            },
            "aws_s3": {
                "cname": ["s3.amazonaws.com", "s3-website"],
                "response": "NoSuchBucket"
            },
            "azure": {
                "cname": ["azurewebsites.net", "cloudapp.net", "azure-api.net"],
                "response": "404 Web Site not found"
            },
            "shopify": {
                "cname": ["myshopify.com"],
                "response": "Sorry, this shop is currently unavailable"
            },
            "fastly": {
                "cname": ["fastly.net"],
                "response": "Fastly error: unknown domain"
            },
            "pantheon": {
                "cname": ["pantheonsite.io"],
                "response": "The gods are wise"
            },
            "tumblr": {
                "cname": ["tumblr.com"],
                "response": "There's nothing here"
            },
            "wordpress": {
                "cname": ["wordpress.com"],
                "response": "Do you want to register"
            },
            "ghost": {
                "cname": ["ghost.io"],
                "response": "The thing you were looking for is no longer here"
            },
            "surge": {
                "cname": ["surge.sh"],
                "response": "project not found"
            },
            "bitbucket": {
                "cname": ["bitbucket.io"],
                "response": "Repository not found"
            },
            "intercom": {
                "cname": ["custom.intercom.help"],
                "response": "This page is reserved for"
            },
            "zendesk": {
                "cname": ["zendesk.com"],
                "response": "Help Center Closed"
            }
        }
    
    async def check_subdomain(self, subdomain: str) -> Optional[DNSThreat]:
        """Check subdomain for takeover vulnerability"""
        try:
            # Resolve CNAME
            cname = await self._get_cname(subdomain)
            if not cname:
                return None
            
            # Check against fingerprints
            for service, fingerprint in self.takeover_fingerprints.items():
                for cname_pattern in fingerprint["cname"]:
                    if cname_pattern in cname.lower():
                        # Check HTTP response
                        vulnerable = await self._check_response(
                            subdomain, 
                            fingerprint["response"]
                        )
                        
                        if vulnerable:
                            return DNSThreat(
                                threat_type=ThreatType.SUBDOMAIN_TAKEOVER,
                                domain=subdomain,
                                severity=SeverityLevel.HIGH,
                                confidence=0.9,
                                indicators=[
                                    f"CNAME points to {service}: {cname}",
                                    f"Service responds with takeover indicator",
                                    f"Fingerprint: {fingerprint['response'][:50]}..."
                                ],
                                details={
                                    "service": service,
                                    "cname": cname,
                                    "fingerprint_matched": True
                                },
                                mitre_techniques=["T1584.001"]  # Compromise Infrastructure: Domains
                            )
            
            # Check for dangling CNAME (NXDOMAIN)
            if await self._is_dangling(cname):
                return DNSThreat(
                    threat_type=ThreatType.DANGLING_DNS,
                    domain=subdomain,
                    severity=SeverityLevel.HIGH,
                    confidence=0.95,
                    indicators=[
                        f"CNAME target does not resolve: {cname}",
                        "Dangling DNS record - potential takeover"
                    ],
                    details={
                        "cname": cname,
                        "status": "NXDOMAIN"
                    },
                    mitre_techniques=["T1584.001"]
                )
            
        except Exception as e:
            self.logger.error(f"Subdomain check error: {e}")
        
        return None
    
    async def _get_cname(self, domain: str) -> Optional[str]:
        """Get CNAME record for domain"""
        try:
            # Simplified - use actual DNS library in production
            import subprocess
            result = subprocess.run(
                ['dig', '+short', 'CNAME', domain],
                capture_output=True,
                text=True,
                timeout=5
            )
            cname = result.stdout.strip()
            return cname if cname else None
        except Exception:
            return None
    
    async def _check_response(self, domain: str, fingerprint: str) -> bool:
        """Check if HTTP response contains takeover fingerprint"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for protocol in ['https', 'http']:
                    try:
                        async with session.get(
                            f"{protocol}://{domain}",
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=True
                        ) as response:
                            text = await response.text()
                            if fingerprint.lower() in text.lower():
                                return True
                    except Exception:
                        continue
        except Exception:
            pass
        return False
    
    async def _is_dangling(self, cname: str) -> bool:
        """Check if CNAME target is dangling (NXDOMAIN)"""
        try:
            socket.gethostbyname(cname.rstrip('.'))
            return False
        except socket.gaierror:
            return True


class FastFluxDetector:
    """Detect fast-flux DNS networks"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.resolution_history: Dict[str, List[Tuple[Set[str], datetime]]] = {}
        
        # Detection parameters
        self.flux_threshold = 5  # Number of unique IPs
        self.time_window = timedelta(hours=1)
    
    def check_flux(self, domain: str, ips: List[str], ttl: int) -> Optional[DNSThreat]:
        """Check for fast-flux behavior"""
        indicators = []
        
        now = datetime.now()
        ip_set = set(ips)
        
        # Initialize history
        if domain not in self.resolution_history:
            self.resolution_history[domain] = []
        
        # Add current resolution
        self.resolution_history[domain].append((ip_set, now))
        
        # Clean old entries
        cutoff = now - self.time_window
        self.resolution_history[domain] = [
            (ips, ts) for ips, ts in self.resolution_history[domain]
            if ts > cutoff
        ]
        
        # Collect all unique IPs
        all_ips = set()
        for ip_set, _ in self.resolution_history[domain]:
            all_ips.update(ip_set)
        
        # Check for fast-flux indicators
        if len(all_ips) >= self.flux_threshold:
            indicators.append(f"High IP diversity: {len(all_ips)} unique IPs")
        
        # Check TTL
        if ttl < 300:
            indicators.append(f"Low TTL: {ttl}s")
        
        # Check for geographic diversity (simplified)
        if len(ips) > 3:
            indicators.append(f"Multiple A records: {len(ips)}")
        
        # Calculate flux score
        flux_score = 0
        if len(all_ips) >= self.flux_threshold:
            flux_score += 0.4
        if ttl < 300:
            flux_score += 0.3
        if len(ips) > 3:
            flux_score += 0.3
        
        if flux_score >= 0.6:
            return DNSThreat(
                threat_type=ThreatType.FAST_FLUX,
                domain=domain,
                severity=SeverityLevel.HIGH,
                confidence=flux_score,
                indicators=indicators,
                details={
                    "unique_ips": list(all_ips),
                    "ip_count": len(all_ips),
                    "current_ips": ips,
                    "ttl": ttl,
                    "observations": len(self.resolution_history[domain])
                },
                mitre_techniques=["T1568.001"]  # Dynamic Resolution: Fast Flux DNS
            )
        
        return None


class DNSThreatIntelligence:
    """DNS threat intelligence integration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Simulated threat feeds
        self.malicious_domains: Set[str] = set()
        self.malicious_ips: Set[str] = set()
        self.sinkhole_ips: Set[str] = {
            "0.0.0.0",
            "127.0.0.1",
            "::1"
        }
    
    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain against threat intelligence"""
        result = {
            "domain": domain,
            "malicious": False,
            "categories": [],
            "sources": []
        }
        
        # Check against known malicious domains
        base_domain = '.'.join(domain.split('.')[-2:])
        
        if domain in self.malicious_domains or base_domain in self.malicious_domains:
            result["malicious"] = True
            result["categories"].append("Known Malicious")
            result["sources"].append("Internal Blocklist")
        
        return result
    
    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP against threat intelligence"""
        result = {
            "ip": ip,
            "malicious": False,
            "sinkholed": False,
            "categories": [],
            "sources": []
        }
        
        if ip in self.sinkhole_ips:
            result["sinkholed"] = True
            result["categories"].append("Sinkhole")
        
        if ip in self.malicious_ips:
            result["malicious"] = True
            result["categories"].append("Known Malicious")
        
        return result
    
    def add_malicious_domain(self, domain: str):
        """Add domain to malicious list"""
        self.malicious_domains.add(domain.lower())
    
    def add_malicious_ip(self, ip: str):
        """Add IP to malicious list"""
        self.malicious_ips.add(ip)


class AdvancedDNSSecurity:
    """Main DNS security analysis engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.parser = DNSParser()
        self.tunneling_detector = DNSTunnelingDetector()
        self.dga_detector = DGADetector()
        self.rebinding_detector = DNSRebindingDetector()
        self.dnssec_validator = DNSSECValidator()
        self.takeover_scanner = SubdomainTakeoverScanner()
        self.fast_flux_detector = FastFluxDetector()
        self.threat_intel = DNSThreatIntelligence()
        
        # Statistics
        self.stats = {
            "queries_analyzed": 0,
            "threats_detected": 0,
            "tunneling_attempts": 0,
            "dga_domains": 0,
            "rebinding_attempts": 0,
            "takeover_vulnerabilities": 0
        }
    
    async def analyze_query(self, query: DNSQuery) -> List[DNSThreat]:
        """Comprehensive DNS query analysis"""
        threats = []
        
        self.stats["queries_analyzed"] += 1
        
        # Check for tunneling
        tunneling_threat = self.tunneling_detector.analyze_query(query)
        if tunneling_threat:
            threats.append(tunneling_threat)
            self.stats["tunneling_attempts"] += 1
        
        # Check for DGA
        dga_threat = self.dga_detector.analyze_domain(query.domain)
        if dga_threat:
            threats.append(dga_threat)
            self.stats["dga_domains"] += 1
        
        # Check threat intelligence
        ti_result = self.threat_intel.check_domain(query.domain)
        if ti_result and ti_result.get("malicious"):
            threats.append(DNSThreat(
                threat_type=ThreatType.EXFILTRATION,
                domain=query.domain,
                severity=SeverityLevel.CRITICAL,
                confidence=1.0,
                indicators=["Domain in threat intelligence feed"],
                details=ti_result,
                mitre_techniques=["T1048"]
            ))
        
        self.stats["threats_detected"] += len(threats)
        
        return threats
    
    async def analyze_resolution(
        self,
        domain: str,
        ips: List[str],
        ttl: int
    ) -> List[DNSThreat]:
        """Analyze DNS resolution results"""
        threats = []
        
        # Check for rebinding
        for ip in ips:
            rebinding_threat = self.rebinding_detector.check_rebinding(domain, ip, ttl)
            if rebinding_threat:
                threats.append(rebinding_threat)
                self.stats["rebinding_attempts"] += 1
        
        # Check for fast-flux
        flux_threat = self.fast_flux_detector.check_flux(domain, ips, ttl)
        if flux_threat:
            threats.append(flux_threat)
        
        # Check IP threat intel
        for ip in ips:
            ti_result = self.threat_intel.check_ip(ip)
            if ti_result and ti_result.get("malicious"):
                threats.append(DNSThreat(
                    threat_type=ThreatType.EXFILTRATION,
                    domain=domain,
                    severity=SeverityLevel.HIGH,
                    confidence=0.95,
                    indicators=[f"IP {ip} in threat feed"],
                    details=ti_result,
                    mitre_techniques=["T1071.004"]
                ))
        
        return threats
    
    async def check_subdomain_takeover(
        self,
        subdomains: List[str]
    ) -> List[DNSThreat]:
        """Check multiple subdomains for takeover vulnerabilities"""
        threats = []
        
        for subdomain in subdomains:
            threat = await self.takeover_scanner.check_subdomain(subdomain)
            if threat:
                threats.append(threat)
                self.stats["takeover_vulnerabilities"] += 1
        
        return threats
    
    async def validate_dnssec(self, domain: str) -> DNSSECStatus:
        """Validate DNSSEC for domain"""
        return await self.dnssec_validator.validate_domain(domain)
    
    async def full_domain_audit(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS security audit"""
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "threats": [],
            "dnssec": None,
            "subdomains": [],
            "recommendations": []
        }
        
        # Check DGA
        dga_threat = self.dga_detector.analyze_domain(domain)
        if dga_threat:
            results["threats"].append({
                "type": dga_threat.threat_type.value,
                "severity": dga_threat.severity.value,
                "confidence": dga_threat.confidence,
                "indicators": dga_threat.indicators
            })
        
        # Validate DNSSEC
        dnssec_status = await self.validate_dnssec(domain)
        results["dnssec"] = {
            "enabled": dnssec_status.dnssec_enabled,
            "valid": dnssec_status.valid,
            "issues": dnssec_status.issues
        }
        
        if not dnssec_status.dnssec_enabled:
            results["recommendations"].append(
                "Enable DNSSEC to protect against cache poisoning"
            )
        
        # Check threat intelligence
        ti_result = self.threat_intel.check_domain(domain)
        if ti_result:
            results["threat_intel"] = ti_result
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return {
            **self.stats,
            "cache_size": {
                "tunneling_history": len(self.tunneling_detector.query_history),
                "rebinding_cache": len(self.rebinding_detector.dns_cache),
                "flux_history": len(self.fast_flux_detector.resolution_history)
            }
        }
    
    def export_threats(self, threats: List[DNSThreat]) -> str:
        """Export threats to JSON"""
        return json.dumps([
            {
                "threat_type": t.threat_type.value,
                "domain": t.domain,
                "severity": t.severity.value,
                "confidence": t.confidence,
                "indicators": t.indicators,
                "details": t.details,
                "timestamp": t.timestamp.isoformat(),
                "mitre_techniques": t.mitre_techniques
            }
            for t in threats
        ], indent=2)


# Main execution
if __name__ == "__main__":
    import asyncio
    
    async def main():
        dns_security = AdvancedDNSSecurity()
        
        # Test DGA detection
        print("Testing DGA Detection...")
        test_domains = [
            "a3f8k2j1h5g9.com",
            "xyzqwertyu123.net",
            "google.com",
            "facebook.com",
            "randomstring123abc.org"
        ]
        
        for domain in test_domains:
            threat = dns_security.dga_detector.analyze_domain(domain)
            if threat:
                print(f"  DGA detected: {domain} (confidence: {threat.confidence:.2f})")
        
        # Test tunneling detection
        print("\nTesting Tunneling Detection...")
        test_query = DNSQuery(
            query_id=12345,
            domain="aGVsbG8gd29ybGQ.exfil.example.com",
            query_type=DNSRecordType.TXT,
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="8.8.8.8"
        )
        
        threats = await dns_security.analyze_query(test_query)
        for threat in threats:
            print(f"  {threat.threat_type.value}: {threat.domain}")
        
        # Print statistics
        print("\nStatistics:")
        stats = dns_security.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    asyncio.run(main())
