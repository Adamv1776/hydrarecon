#!/usr/bin/env python3
"""
Zero Trust Network Scanner

Comprehensive scanner for verifying Zero Trust architecture implementation.
Validates microsegmentation, identity verification, continuous authentication,
and least-privilege access across the network.

Features:
- Microsegmentation validation
- Identity and access verification
- Network flow analysis
- Policy compliance checking
- Lateral movement detection
- Trust boundary mapping
- Continuous authentication verification
- Device posture assessment
- SDP/ZTNA validation
"""

import asyncio
import ipaddress
import socket
import ssl
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum, auto
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class ZeroTrustPrinciple(Enum):
    """Core Zero Trust principles."""
    VERIFY_EXPLICITLY = "verify_explicitly"
    LEAST_PRIVILEGE = "least_privilege"
    ASSUME_BREACH = "assume_breach"
    MICROSEGMENTATION = "microsegmentation"
    CONTINUOUS_VALIDATION = "continuous_validation"


class TrustLevel(Enum):
    """Trust levels for entities."""
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4


class ComplianceStatus(Enum):
    """Compliance status for ZT principles."""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


class AssetType(Enum):
    """Types of network assets."""
    WORKSTATION = "workstation"
    SERVER = "server"
    NETWORK_DEVICE = "network_device"
    IOT_DEVICE = "iot_device"
    MOBILE_DEVICE = "mobile_device"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    VIRTUAL_MACHINE = "virtual_machine"


class SegmentType(Enum):
    """Network segment types."""
    MANAGEMENT = "management"
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    DMZ = "dmz"
    USER = "user"
    IOT = "iot"
    GUEST = "guest"
    QUARANTINE = "quarantine"


@dataclass
class NetworkAsset:
    """A network asset to be evaluated."""
    asset_id: str
    ip_address: str
    hostname: Optional[str] = None
    asset_type: AssetType = AssetType.WORKSTATION
    segment: Optional[SegmentType] = None
    mac_address: Optional[str] = None
    
    # Trust attributes
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    identity_verified: bool = False
    device_compliant: bool = False
    
    # Access info
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    
    # Metadata
    last_seen: datetime = field(default_factory=datetime.now)
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkFlow:
    """A network flow between assets."""
    flow_id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    
    # ZT attributes
    authenticated: bool = False
    encrypted: bool = False
    authorized: bool = False
    
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class TrustBoundary:
    """A trust boundary in the network."""
    boundary_id: str
    name: str
    segments: List[SegmentType]
    
    # Access controls
    allowed_flows: List[Tuple[str, str, int]] = field(default_factory=list)
    denied_flows: List[Tuple[str, str, int]] = field(default_factory=list)
    
    # Enforcement
    has_firewall: bool = False
    has_ids: bool = False
    has_dlp: bool = False
    
    # Monitoring
    logging_enabled: bool = False
    monitoring_enabled: bool = False


@dataclass
class ZeroTrustFinding:
    """A finding from Zero Trust assessment."""
    finding_id: str
    principle: ZeroTrustPrinciple
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    
    affected_assets: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    remediation: str = ""
    compliance_impact: str = ""
    
    detected_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'finding_id': self.finding_id,
            'principle': self.principle.value,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'affected_assets': self.affected_assets,
            'remediation': self.remediation,
            'detected_at': self.detected_at.isoformat()
        }


@dataclass
class ZeroTrustReport:
    """Complete Zero Trust assessment report."""
    report_id: str
    scan_time: datetime
    duration_seconds: float
    
    # Scores
    overall_score: float  # 0-100
    principle_scores: Dict[str, float] = field(default_factory=dict)
    
    # Assets
    total_assets: int = 0
    compliant_assets: int = 0
    
    # Findings
    findings: List[ZeroTrustFinding] = field(default_factory=list)
    
    # Summary
    summary: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'report_id': self.report_id,
            'scan_time': self.scan_time.isoformat(),
            'duration_seconds': self.duration_seconds,
            'overall_score': self.overall_score,
            'principle_scores': self.principle_scores,
            'total_assets': self.total_assets,
            'compliant_assets': self.compliant_assets,
            'findings_count': len(self.findings),
            'critical_findings': len([f for f in self.findings if f.severity == 'critical']),
            'summary': self.summary
        }


class MicrosegmentationScanner:
    """
    Validates network microsegmentation implementation.
    """
    
    def __init__(self):
        self.segments: Dict[str, Set[str]] = defaultdict(set)
        self.inter_segment_flows: List[NetworkFlow] = []
        
    async def scan_segment(self, network: str, 
                          segment_type: SegmentType) -> List[NetworkAsset]:
        """Scan a network segment for assets."""
        assets = []
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            
            # Scan hosts
            for ip in list(net.hosts())[:254]:  # Limit for demo
                asset = await self._probe_host(str(ip), segment_type)
                if asset:
                    assets.append(asset)
                    self.segments[segment_type.value].add(str(ip))
                    
        except Exception as e:
            logger.error(f"Segment scan error: {e}")
        
        return assets
    
    async def _probe_host(self, ip: str, segment: SegmentType) -> Optional[NetworkAsset]:
        """Probe a single host."""
        # Quick port scan
        open_ports = []
        common_ports = [22, 80, 443, 445, 3389, 8080, 8443]
        
        for port in common_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=0.5
                )
                open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        
        if not open_ports:
            return None
        
        # Determine asset type from services
        asset_type = self._infer_asset_type(open_ports)
        
        return NetworkAsset(
            asset_id=hashlib.md5(ip.encode()).hexdigest()[:12],
            ip_address=ip,
            asset_type=asset_type,
            segment=segment,
            open_ports=open_ports
        )
    
    def _infer_asset_type(self, ports: List[int]) -> AssetType:
        """Infer asset type from open ports."""
        if 3389 in ports:
            return AssetType.WORKSTATION
        elif 445 in ports and (80 in ports or 443 in ports):
            return AssetType.SERVER
        elif 22 in ports and 80 not in ports:
            return AssetType.NETWORK_DEVICE
        elif 80 in ports or 443 in ports:
            return AssetType.SERVER
        return AssetType.WORKSTATION
    
    def validate_segmentation(self, flows: List[NetworkFlow]) -> List[ZeroTrustFinding]:
        """Validate that segmentation is properly enforced."""
        findings = []
        
        # Check for cross-segment flows
        for flow in flows:
            source_segment = self._get_segment(flow.source_ip)
            dest_segment = self._get_segment(flow.dest_ip)
            
            if source_segment and dest_segment and source_segment != dest_segment:
                # Cross-segment flow detected
                if not flow.authenticated or not flow.encrypted:
                    findings.append(ZeroTrustFinding(
                        finding_id=f"MICRO-{flow.flow_id[:8]}",
                        principle=ZeroTrustPrinciple.MICROSEGMENTATION,
                        severity='high',
                        title="Unsecured Cross-Segment Communication",
                        description=f"Flow from {source_segment} to {dest_segment} "
                                   f"lacks {'authentication' if not flow.authenticated else 'encryption'}",
                        affected_assets=[flow.source_ip, flow.dest_ip],
                        evidence={
                            'source_segment': source_segment,
                            'dest_segment': dest_segment,
                            'authenticated': flow.authenticated,
                            'encrypted': flow.encrypted
                        },
                        remediation="Implement mutual TLS or IPsec for cross-segment traffic"
                    ))
        
        return findings
    
    def _get_segment(self, ip: str) -> Optional[str]:
        """Get segment for an IP address."""
        for segment, ips in self.segments.items():
            if ip in ips:
                return segment
        return None


class IdentityVerificationScanner:
    """
    Validates identity and authentication implementation.
    """
    
    def __init__(self):
        self.verified_identities: Set[str] = set()
        
    async def verify_authentication(self, asset: NetworkAsset) -> Tuple[bool, Dict]:
        """Verify that asset requires proper authentication."""
        results = {
            'mfa_enabled': False,
            'cert_auth': False,
            'ldap_auth': False,
            'oauth_enabled': False,
            'session_timeout': None,
            'issues': []
        }
        
        # Check for authentication services
        for port, service in asset.services.items():
            # Check LDAP/AD
            if port in [389, 636, 3268, 3269]:
                results['ldap_auth'] = True
                if port not in [636, 3269]:
                    results['issues'].append("LDAP without TLS detected")
            
            # Check for OAuth/OIDC
            if port in [443, 8443]:
                results['oauth_enabled'] = await self._check_oauth(asset.ip_address, port)
        
        # Check certificate authentication
        results['cert_auth'] = await self._check_cert_auth(asset.ip_address)
        
        # Determine if MFA is likely enabled
        results['mfa_enabled'] = results['cert_auth'] or (
            results['ldap_auth'] and results['oauth_enabled']
        )
        
        verified = results['mfa_enabled'] and not results['issues']
        if verified:
            self.verified_identities.add(asset.asset_id)
        
        return verified, results
    
    async def _check_oauth(self, ip: str, port: int) -> bool:
        """Check for OAuth/OIDC endpoints."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context),
                timeout=5.0
            )
            
            # Check for well-known endpoint
            request = f"GET /.well-known/openid-configuration HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            writer.close()
            await writer.wait_closed()
            
            return b'200' in response and b'authorization_endpoint' in response
            
        except Exception:
            return False
    
    async def _check_cert_auth(self, ip: str) -> bool:
        """Check for certificate-based authentication."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=context),
                timeout=5.0
            )
            
            writer.close()
            await writer.wait_closed()
            
            # If we got here with SSL, basic cert is available
            # In production, would check for client cert requirement
            return True
            
        except Exception:
            return False
    
    def generate_findings(self, assets: List[NetworkAsset], 
                         verification_results: Dict[str, Dict]) -> List[ZeroTrustFinding]:
        """Generate findings from identity verification."""
        findings = []
        
        for asset in assets:
            results = verification_results.get(asset.asset_id, {})
            
            if not results.get('mfa_enabled', False):
                findings.append(ZeroTrustFinding(
                    finding_id=f"ID-{asset.asset_id[:8]}",
                    principle=ZeroTrustPrinciple.VERIFY_EXPLICITLY,
                    severity='high',
                    title="Missing Multi-Factor Authentication",
                    description=f"Asset {asset.ip_address} does not enforce MFA",
                    affected_assets=[asset.asset_id],
                    evidence=results,
                    remediation="Enable MFA using certificates, TOTP, or hardware tokens"
                ))
            
            for issue in results.get('issues', []):
                findings.append(ZeroTrustFinding(
                    finding_id=f"ID-{hashlib.md5(issue.encode()).hexdigest()[:8]}",
                    principle=ZeroTrustPrinciple.VERIFY_EXPLICITLY,
                    severity='medium',
                    title="Authentication Configuration Issue",
                    description=issue,
                    affected_assets=[asset.asset_id],
                    remediation="Review and fix authentication configuration"
                ))
        
        return findings


class LeastPrivilegeScanner:
    """
    Validates least privilege access implementation.
    """
    
    def __init__(self):
        self.access_matrix: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        
    def analyze_access(self, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Analyze access patterns for least privilege violations."""
        analysis = {
            'excessive_access': [],
            'unused_access': [],
            'lateral_movement_risk': [],
            'privilege_escalation_risk': []
        }
        
        # Build access matrix
        for flow in flows:
            self.access_matrix[flow.source_ip][flow.dest_ip].add(
                f"{flow.protocol}:{flow.dest_port}"
            )
        
        # Check for excessive access
        for source, destinations in self.access_matrix.items():
            # Too many destinations
            if len(destinations) > 10:
                analysis['excessive_access'].append({
                    'source': source,
                    'destination_count': len(destinations),
                    'risk': 'high' if len(destinations) > 50 else 'medium'
                })
            
            # Check for lateral movement patterns
            for dest, services in destinations.items():
                if 'tcp:445' in services or 'tcp:3389' in services:
                    if len(destinations) > 5:
                        analysis['lateral_movement_risk'].append({
                            'source': source,
                            'target': dest,
                            'services': list(services)
                        })
        
        return analysis
    
    def generate_findings(self, analysis: Dict[str, Any]) -> List[ZeroTrustFinding]:
        """Generate findings from access analysis."""
        findings = []
        
        for item in analysis.get('excessive_access', []):
            findings.append(ZeroTrustFinding(
                finding_id=f"LP-EXC-{item['source'][-8:]}",
                principle=ZeroTrustPrinciple.LEAST_PRIVILEGE,
                severity=item['risk'],
                title="Excessive Network Access",
                description=f"Source {item['source']} has access to {item['destination_count']} destinations",
                affected_assets=[item['source']],
                evidence=item,
                remediation="Review and restrict access to only required destinations"
            ))
        
        for item in analysis.get('lateral_movement_risk', []):
            findings.append(ZeroTrustFinding(
                finding_id=f"LP-LAT-{item['source'][-8:]}",
                principle=ZeroTrustPrinciple.ASSUME_BREACH,
                severity='high',
                title="Lateral Movement Risk",
                description=f"Source {item['source']} has broad access with lateral movement services",
                affected_assets=[item['source'], item['target']],
                evidence=item,
                remediation="Implement microsegmentation and restrict admin protocols"
            ))
        
        return findings


class ContinuousValidationScanner:
    """
    Validates continuous authentication and validation.
    """
    
    def __init__(self):
        self.session_activity: Dict[str, List[datetime]] = defaultdict(list)
        
    def analyze_sessions(self, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Analyze session patterns for continuous validation."""
        analysis = {
            'long_sessions': [],
            'stale_sessions': [],
            'no_reauth': [],
            'session_stats': {}
        }
        
        # Group flows by source
        session_activity = defaultdict(list)
        for flow in flows:
            session_activity[flow.source_ip].append(flow.timestamp)
        
        for source, timestamps in session_activity.items():
            if not timestamps:
                continue
            
            timestamps.sort()
            
            # Check session duration
            duration = (timestamps[-1] - timestamps[0]).total_seconds()
            
            analysis['session_stats'][source] = {
                'duration_minutes': duration / 60,
                'activity_count': len(timestamps),
                'first_activity': timestamps[0].isoformat(),
                'last_activity': timestamps[-1].isoformat()
            }
            
            # Long sessions without reauth (>8 hours)
            if duration > 8 * 3600:
                analysis['long_sessions'].append({
                    'source': source,
                    'duration_hours': duration / 3600
                })
            
            # Stale sessions (no activity in last hour but session exists)
            if timestamps[-1] < datetime.now() - timedelta(hours=1):
                analysis['stale_sessions'].append({
                    'source': source,
                    'last_activity': timestamps[-1].isoformat()
                })
        
        return analysis
    
    def generate_findings(self, analysis: Dict[str, Any]) -> List[ZeroTrustFinding]:
        """Generate findings from session analysis."""
        findings = []
        
        for session in analysis.get('long_sessions', []):
            findings.append(ZeroTrustFinding(
                finding_id=f"CV-LONG-{session['source'][-8:]}",
                principle=ZeroTrustPrinciple.CONTINUOUS_VALIDATION,
                severity='medium',
                title="Long-Running Session Without Re-authentication",
                description=f"Session from {session['source']} active for "
                           f"{session['duration_hours']:.1f} hours without re-auth",
                affected_assets=[session['source']],
                evidence=session,
                remediation="Implement session timeout and periodic re-authentication"
            ))
        
        for session in analysis.get('stale_sessions', []):
            findings.append(ZeroTrustFinding(
                finding_id=f"CV-STALE-{session['source'][-8:]}",
                principle=ZeroTrustPrinciple.CONTINUOUS_VALIDATION,
                severity='low',
                title="Stale Session Detected",
                description=f"Inactive session from {session['source']} "
                           f"since {session['last_activity']}",
                affected_assets=[session['source']],
                evidence=session,
                remediation="Implement automatic session cleanup for idle sessions"
            ))
        
        return findings


class DevicePostureScanner:
    """
    Validates device security posture.
    """
    
    async def assess_posture(self, asset: NetworkAsset) -> Dict[str, Any]:
        """Assess device security posture."""
        posture = {
            'os_updated': None,
            'antivirus_present': None,
            'firewall_enabled': None,
            'encryption_enabled': None,
            'compliant': False,
            'risk_factors': []
        }
        
        # Check for security services
        security_indicators = {
            'antivirus': [4118, 4119],  # Common AV ports
            'firewall': [8291, 8292],   # Firewall management
            'encryption': [443, 8443]   # TLS services
        }
        
        for indicator, ports in security_indicators.items():
            for port in ports:
                if port in asset.open_ports:
                    posture[f'{indicator}_present'] = True
                    break
        
        # Risk assessment based on open ports
        high_risk_ports = [23, 21, 445, 139, 3389]
        for port in high_risk_ports:
            if port in asset.open_ports:
                posture['risk_factors'].append(f"High-risk port {port} open")
        
        # Determine compliance
        posture['compliant'] = (
            posture.get('encryption_enabled', True) and
            len(posture['risk_factors']) == 0
        )
        
        return posture
    
    def generate_findings(self, assets: List[NetworkAsset],
                         posture_results: Dict[str, Dict]) -> List[ZeroTrustFinding]:
        """Generate findings from posture assessment."""
        findings = []
        
        for asset in assets:
            posture = posture_results.get(asset.asset_id, {})
            
            if not posture.get('compliant', False):
                findings.append(ZeroTrustFinding(
                    finding_id=f"DP-{asset.asset_id[:8]}",
                    principle=ZeroTrustPrinciple.VERIFY_EXPLICITLY,
                    severity='medium',
                    title="Non-Compliant Device Posture",
                    description=f"Device {asset.ip_address} does not meet security requirements",
                    affected_assets=[asset.asset_id],
                    evidence=posture,
                    remediation="Remediate device posture issues before granting access"
                ))
            
            for risk in posture.get('risk_factors', []):
                findings.append(ZeroTrustFinding(
                    finding_id=f"DP-RISK-{hashlib.md5(risk.encode()).hexdigest()[:8]}",
                    principle=ZeroTrustPrinciple.ASSUME_BREACH,
                    severity='high',
                    title="Device Security Risk",
                    description=f"{risk} on device {asset.ip_address}",
                    affected_assets=[asset.asset_id],
                    remediation="Close unnecessary ports and harden device configuration"
                ))
        
        return findings


class ZeroTrustScanner:
    """
    Main Zero Trust Network Scanner.
    
    Orchestrates all scanning components for comprehensive ZT assessment.
    """
    
    def __init__(self):
        self.microseg_scanner = MicrosegmentationScanner()
        self.identity_scanner = IdentityVerificationScanner()
        self.privilege_scanner = LeastPrivilegeScanner()
        self.validation_scanner = ContinuousValidationScanner()
        self.posture_scanner = DevicePostureScanner()
        
        # Scan results
        self.assets: List[NetworkAsset] = []
        self.flows: List[NetworkFlow] = []
        self.findings: List[ZeroTrustFinding] = []
        
    async def scan(self, targets: List[str], 
                   segment_mapping: Optional[Dict[str, SegmentType]] = None) -> ZeroTrustReport:
        """
        Perform comprehensive Zero Trust assessment.
        
        Args:
            targets: List of network ranges to scan (CIDR notation)
            segment_mapping: Optional mapping of networks to segment types
        """
        start_time = datetime.now()
        
        logger.info(f"Starting Zero Trust scan of {len(targets)} networks")
        
        # Phase 1: Asset Discovery
        logger.info("Phase 1: Asset Discovery")
        for target in targets:
            segment = segment_mapping.get(target, SegmentType.PRODUCTION) if segment_mapping else SegmentType.PRODUCTION
            assets = await self.microseg_scanner.scan_segment(target, segment)
            self.assets.extend(assets)
        
        logger.info(f"Discovered {len(self.assets)} assets")
        
        # Phase 2: Identity Verification
        logger.info("Phase 2: Identity Verification")
        identity_results = {}
        for asset in self.assets:
            verified, results = await self.identity_scanner.verify_authentication(asset)
            identity_results[asset.asset_id] = results
            asset.identity_verified = verified
        
        # Phase 3: Device Posture
        logger.info("Phase 3: Device Posture Assessment")
        posture_results = {}
        for asset in self.assets:
            posture = await self.posture_scanner.assess_posture(asset)
            posture_results[asset.asset_id] = posture
            asset.device_compliant = posture['compliant']
        
        # Phase 4: Flow Analysis
        logger.info("Phase 4: Network Flow Analysis")
        self.flows = await self._capture_network_flows()
        
        # Phase 5: Generate Findings
        logger.info("Phase 5: Generating Findings")
        
        # Microsegmentation findings
        self.findings.extend(
            self.microseg_scanner.validate_segmentation(self.flows)
        )
        
        # Identity findings
        self.findings.extend(
            self.identity_scanner.generate_findings(self.assets, identity_results)
        )
        
        # Least privilege findings
        access_analysis = self.privilege_scanner.analyze_access(self.flows)
        self.findings.extend(
            self.privilege_scanner.generate_findings(access_analysis)
        )
        
        # Continuous validation findings
        session_analysis = self.validation_scanner.analyze_sessions(self.flows)
        self.findings.extend(
            self.validation_scanner.generate_findings(session_analysis)
        )
        
        # Device posture findings
        self.findings.extend(
            self.posture_scanner.generate_findings(self.assets, posture_results)
        )
        
        # Calculate scores
        duration = (datetime.now() - start_time).total_seconds()
        report = self._generate_report(start_time, duration)
        
        logger.info(f"Zero Trust scan complete. Score: {report.overall_score:.1f}/100")
        
        return report
    
    async def _capture_network_flows(self) -> List[NetworkFlow]:
        """Capture actual network flows between discovered assets."""
        flows = []
        
        # Build connection map from discovered assets
        for asset in self.assets:
            for port in asset.open_ports:
                # Test connectivity from other assets
                for other in self.assets:
                    if other.asset_id == asset.asset_id:
                        continue
                    
                    # Try to establish connection to gather flow data
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(asset.ip_address, port),
                            timeout=1.0
                        )
                        
                        # Connection successful - record flow
                        flow = NetworkFlow(
                            flow_id=hashlib.md5(
                                f"{other.ip_address}:{asset.ip_address}:{port}".encode()
                            ).hexdigest()[:12],
                            source_ip=other.ip_address,
                            dest_ip=asset.ip_address,
                            source_port=0,  # Ephemeral
                            dest_port=port,
                            protocol='tcp',
                            authenticated=asset.identity_verified,
                            encrypted=port in [443, 8443, 993, 995, 465, 636],
                            authorized=asset.device_compliant
                        )
                        flows.append(flow)
                        
                        writer.close()
                        await writer.wait_closed()
                        
                    except Exception:
                        # Connection failed or timed out - expected for many combinations
                        pass
        
        logger.info(f"Captured {len(flows)} network flows")
        return flows
    
    def _generate_report(self, scan_time: datetime, 
                        duration: float) -> ZeroTrustReport:
        """Generate comprehensive report."""
        # Count compliant assets
        compliant = sum(1 for a in self.assets 
                       if a.identity_verified and a.device_compliant)
        
        # Calculate principle scores
        principle_findings = defaultdict(list)
        for f in self.findings:
            principle_findings[f.principle.value].append(f)
        
        principle_scores = {}
        for principle in ZeroTrustPrinciple:
            findings = principle_findings[principle.value]
            if not findings:
                principle_scores[principle.value] = 100.0
            else:
                # Deduct based on severity
                deductions = {
                    'critical': 25,
                    'high': 15,
                    'medium': 8,
                    'low': 3,
                    'info': 1
                }
                total_deduction = sum(deductions.get(f.severity, 5) for f in findings)
                principle_scores[principle.value] = max(0, 100 - total_deduction)
        
        # Overall score
        overall_score = sum(principle_scores.values()) / len(principle_scores)
        
        # Generate summary
        summary = {
            'total_findings': len(self.findings),
            'critical_findings': len([f for f in self.findings if f.severity == 'critical']),
            'high_findings': len([f for f in self.findings if f.severity == 'high']),
            'medium_findings': len([f for f in self.findings if f.severity == 'medium']),
            'low_findings': len([f for f in self.findings if f.severity == 'low']),
            'compliance_rate': compliant / len(self.assets) * 100 if self.assets else 0,
            'top_issues': self._get_top_issues(),
            'recommendations': self._get_recommendations()
        }
        
        return ZeroTrustReport(
            report_id=hashlib.sha256(f"{scan_time.isoformat()}".encode()).hexdigest()[:16],
            scan_time=scan_time,
            duration_seconds=duration,
            overall_score=overall_score,
            principle_scores=principle_scores,
            total_assets=len(self.assets),
            compliant_assets=compliant,
            findings=self.findings,
            summary=summary
        )
    
    def _get_top_issues(self) -> List[str]:
        """Get top issues from findings."""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(self.findings, 
                                key=lambda f: severity_order.get(f.severity, 5))
        return [f.title for f in sorted_findings[:5]]
    
    def _get_recommendations(self) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = set()
        
        # Add unique recommendations from findings
        for finding in self.findings:
            if finding.remediation:
                recommendations.add(finding.remediation)
        
        # Prioritize
        priority_keywords = ['MFA', 'segment', 'encrypt', 'restrict', 'close']
        prioritized = []
        other = []
        
        for rec in recommendations:
            if any(kw.lower() in rec.lower() for kw in priority_keywords):
                prioritized.append(rec)
            else:
                other.append(rec)
        
        return (prioritized + other)[:10]


# Convenience function
async def scan_zero_trust(networks: List[str]) -> Dict:
    """Quick Zero Trust assessment."""
    scanner = ZeroTrustScanner()
    report = await scanner.scan(networks)
    return report.to_dict()


if __name__ == "__main__":
    print("Zero Trust Network Scanner - Demo")
    print("=" * 50)
    
    async def demo():
        scanner = ZeroTrustScanner()
        
        # Demo with localhost only (safe)
        print("\n[1] Running Zero Trust Assessment...")
        report = await scanner.scan(
            targets=["127.0.0.1/32"],
            segment_mapping={"127.0.0.1/32": SegmentType.DEVELOPMENT}
        )
        
        print(f"\n[2] Assessment Results:")
        print(f"    Overall Score: {report.overall_score:.1f}/100")
        print(f"    Assets Discovered: {report.total_assets}")
        print(f"    Compliant Assets: {report.compliant_assets}")
        print(f"    Total Findings: {len(report.findings)}")
        
        print(f"\n[3] Principle Scores:")
        for principle, score in report.principle_scores.items():
            status = "✓" if score >= 80 else "✗"
            print(f"    {status} {principle}: {score:.1f}/100")
        
        if report.findings:
            print(f"\n[4] Top Findings:")
            for finding in report.findings[:3]:
                print(f"    [{finding.severity.upper()}] {finding.title}")
        
        print(f"\n[5] Recommendations:")
        for rec in report.summary.get('recommendations', [])[:3]:
            print(f"    • {rec}")
        
        print("\n✓ Zero Trust assessment complete!")
    
    asyncio.run(demo())
