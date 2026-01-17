"""
HydraRecon - Attack Path Analyzer
Identifies and visualizes potential attack paths through the network
"""

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import heapq


class NodeType(Enum):
    """Network node types"""
    INTERNET = "internet"
    FIREWALL = "firewall"
    DMZ = "dmz"
    WEB_SERVER = "web_server"
    APP_SERVER = "app_server"
    DATABASE = "database"
    DOMAIN_CONTROLLER = "domain_controller"
    FILE_SERVER = "file_server"
    WORKSTATION = "workstation"
    ADMIN_WORKSTATION = "admin_workstation"
    CLOUD_INSTANCE = "cloud_instance"
    VPN_GATEWAY = "vpn_gateway"
    MAIL_SERVER = "mail_server"
    CROWN_JEWEL = "crown_jewel"


class AttackTechnique(Enum):
    """Attack techniques for path traversal"""
    PHISHING = "phishing"
    EXPLOIT_VULN = "exploit_vulnerability"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RCE = "remote_code_execution"
    SQL_INJECTION = "sql_injection"
    PASS_THE_HASH = "pass_the_hash"
    KERBEROASTING = "kerberoasting"
    GOLDEN_TICKET = "golden_ticket"
    DEFAULT_CREDS = "default_credentials"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"


@dataclass
class PathNode:
    """Node in the network topology"""
    id: str
    name: str
    node_type: NodeType
    zone: str
    criticality: int  # 1-10
    vulnerabilities: List[str] = field(default_factory=list)
    credentials_available: bool = False
    is_target: bool = False
    is_entry_point: bool = False
    
    
@dataclass
class PathEdge:
    """Edge representing potential attack path"""
    source: str
    target: str
    technique: AttackTechnique
    difficulty: float  # 0-1 (higher = harder)
    detection_risk: float  # 0-1 (higher = more likely detected)
    mitre_id: str
    requirements: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """Complete attack path from entry to target"""
    id: str
    entry_point: str
    target: str
    nodes: List[str]
    edges: List[PathEdge]
    total_difficulty: float
    total_detection_risk: float
    techniques_used: List[str]
    mitre_techniques: List[str]
    estimated_time_hours: float
    risk_score: float


@dataclass
class CrownJewel:
    """High-value target asset"""
    id: str
    name: str
    description: str
    value_score: float  # 0-100
    data_classification: str
    business_impact: str


class AttackPathAnalyzer:
    """Attack path analysis engine"""
    
    def __init__(self):
        self.nodes: Dict[str, PathNode] = {}
        self.edges: List[PathEdge] = []
        self.adjacency: Dict[str, List[PathEdge]] = {}
        self.crown_jewels: Dict[str, CrownJewel] = {}
        self.attack_paths: List[AttackPath] = []
        
        self._initialize_network()
        self._generate_paths()
        
    def _initialize_network(self):
        """Initialize sample network topology"""
        nodes = [
            PathNode("N001", "Internet", NodeType.INTERNET, "External", 0, is_entry_point=True),
            PathNode("N002", "Perimeter Firewall", NodeType.FIREWALL, "DMZ", 8, ["CVE-2023-1234"]),
            PathNode("N003", "Web Server 1", NodeType.WEB_SERVER, "DMZ", 6, ["CVE-2021-44228", "CVE-2023-4567"], is_entry_point=True),
            PathNode("N004", "Web Server 2", NodeType.WEB_SERVER, "DMZ", 6, ["CVE-2022-22965"]),
            PathNode("N005", "Mail Gateway", NodeType.MAIL_SERVER, "DMZ", 7, [], is_entry_point=True),
            PathNode("N006", "VPN Gateway", NodeType.VPN_GATEWAY, "DMZ", 8, ["Weak MFA"]),
            PathNode("N007", "Internal Firewall", NodeType.FIREWALL, "Internal", 9),
            PathNode("N008", "App Server 1", NodeType.APP_SERVER, "Application", 7, ["CVE-2023-7890"]),
            PathNode("N009", "App Server 2", NodeType.APP_SERVER, "Application", 7),
            PathNode("N010", "Database Cluster", NodeType.DATABASE, "Data", 10, ["CVE-2021-2351"], is_target=True),
            PathNode("N011", "Domain Controller", NodeType.DOMAIN_CONTROLLER, "Core", 10, ["Zerologon Risk"], credentials_available=True),
            PathNode("N012", "File Server", NodeType.FILE_SERVER, "Data", 8, credentials_available=True),
            PathNode("N013", "Admin Workstation", NodeType.ADMIN_WORKSTATION, "User", 9, credentials_available=True),
            PathNode("N014", "User Workstation 1", NodeType.WORKSTATION, "User", 4, [], is_entry_point=True),
            PathNode("N015", "User Workstation 2", NodeType.WORKSTATION, "User", 4),
            PathNode("N016", "Cloud AWS", NodeType.CLOUD_INSTANCE, "Cloud", 9, ["S3 Misconfiguration"], is_entry_point=True),
            PathNode("N017", "Crown Jewels DB", NodeType.CROWN_JEWEL, "Vault", 10, is_target=True),
            PathNode("N018", "Backup Server", NodeType.FILE_SERVER, "Backup", 8, ["Default Creds"], credentials_available=True),
        ]
        
        for node in nodes:
            self.nodes[node.id] = node
            self.adjacency[node.id] = []
            
        # Define attack edges
        edges = [
            # Internet to DMZ
            PathEdge("N001", "N002", AttackTechnique.EXPLOIT_VULN, 0.8, 0.3, "T1190"),
            PathEdge("N001", "N003", AttackTechnique.EXPLOIT_VULN, 0.4, 0.5, "T1190", ["CVE-2021-44228"]),
            PathEdge("N001", "N005", AttackTechnique.PHISHING, 0.3, 0.4, "T1566"),
            PathEdge("N001", "N006", AttackTechnique.CREDENTIAL_THEFT, 0.6, 0.5, "T1078"),
            PathEdge("N001", "N016", AttackTechnique.CLOUD_MISCONFIGURATION, 0.3, 0.2, "T1530"),
            
            # DMZ to Internal
            PathEdge("N003", "N007", AttackTechnique.EXPLOIT_VULN, 0.6, 0.4, "T1210"),
            PathEdge("N004", "N007", AttackTechnique.EXPLOIT_VULN, 0.5, 0.4, "T1210"),
            PathEdge("N003", "N008", AttackTechnique.LATERAL_MOVEMENT, 0.4, 0.5, "T1021"),
            PathEdge("N005", "N014", AttackTechnique.PHISHING, 0.3, 0.3, "T1566.001"),
            PathEdge("N006", "N013", AttackTechnique.CREDENTIAL_THEFT, 0.5, 0.3, "T1078"),
            
            # Internal lateral movement
            PathEdge("N007", "N008", AttackTechnique.LATERAL_MOVEMENT, 0.3, 0.4, "T1021"),
            PathEdge("N008", "N009", AttackTechnique.LATERAL_MOVEMENT, 0.2, 0.3, "T1021"),
            PathEdge("N008", "N010", AttackTechnique.SQL_INJECTION, 0.5, 0.6, "T1190"),
            PathEdge("N009", "N010", AttackTechnique.LATERAL_MOVEMENT, 0.3, 0.4, "T1021"),
            
            # User zone
            PathEdge("N014", "N015", AttackTechnique.LATERAL_MOVEMENT, 0.2, 0.2, "T1021"),
            PathEdge("N014", "N012", AttackTechnique.LATERAL_MOVEMENT, 0.4, 0.3, "T1021"),
            PathEdge("N015", "N013", AttackTechnique.PRIVILEGE_ESCALATION, 0.6, 0.5, "T1068"),
            
            # Credential paths
            PathEdge("N013", "N011", AttackTechnique.PASS_THE_HASH, 0.4, 0.6, "T1550.002"),
            PathEdge("N012", "N011", AttackTechnique.KERBEROASTING, 0.5, 0.5, "T1558.003"),
            PathEdge("N018", "N011", AttackTechnique.DEFAULT_CREDS, 0.2, 0.3, "T1078"),
            
            # To crown jewels
            PathEdge("N011", "N017", AttackTechnique.GOLDEN_TICKET, 0.7, 0.8, "T1558.001"),
            PathEdge("N010", "N017", AttackTechnique.LATERAL_MOVEMENT, 0.5, 0.6, "T1021"),
            PathEdge("N016", "N010", AttackTechnique.CLOUD_MISCONFIGURATION, 0.4, 0.3, "T1530"),
            PathEdge("N018", "N017", AttackTechnique.LATERAL_MOVEMENT, 0.3, 0.4, "T1021"),
        ]
        
        for edge in edges:
            self.edges.append(edge)
            self.adjacency[edge.source].append(edge)
            
        # Crown jewels
        crown_jewels = [
            CrownJewel("CJ001", "Customer Database", "Contains PII for 5M customers", 95, "Confidential", "Critical - Regulatory Risk"),
            CrownJewel("CJ002", "Financial Records", "Corporate financial data", 90, "Restricted", "Critical - SEC Compliance"),
            CrownJewel("CJ003", "Trade Secrets", "Proprietary algorithms and IP", 100, "Top Secret", "Critical - Competitive Advantage"),
            CrownJewel("CJ004", "Authentication Keys", "Root certificates and API keys", 85, "Restricted", "High - System Integrity"),
        ]
        
        for cj in crown_jewels:
            self.crown_jewels[cj.id] = cj
            
    def _generate_paths(self):
        """Generate attack paths from entry points to targets"""
        entry_points = [n.id for n in self.nodes.values() if n.is_entry_point]
        targets = [n.id for n in self.nodes.values() if n.is_target]
        
        for entry in entry_points:
            for target in targets:
                paths = self._find_paths(entry, target, max_depth=8)
                self.attack_paths.extend(paths)
                
        # Sort by risk score
        self.attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
        
    def _find_paths(self, start: str, end: str, max_depth: int = 8) -> List[AttackPath]:
        """Find attack paths using modified Dijkstra"""
        paths = []
        
        # BFS to find multiple paths
        queue = [(0, [start], [])]  # (cost, path_nodes, path_edges)
        visited_paths: Set[tuple] = set()
        
        while queue and len(paths) < 5:
            cost, path_nodes, path_edges = heapq.heappop(queue)
            
            current = path_nodes[-1]
            
            if current == end:
                # Found a path
                attack_path = self._create_attack_path(path_nodes, path_edges)
                if attack_path:
                    paths.append(attack_path)
                continue
                
            if len(path_nodes) > max_depth:
                continue
                
            path_key = tuple(path_nodes)
            if path_key in visited_paths:
                continue
            visited_paths.add(path_key)
            
            for edge in self.adjacency.get(current, []):
                if edge.target not in path_nodes:  # Avoid cycles
                    new_cost = cost + edge.difficulty
                    new_path = path_nodes + [edge.target]
                    new_edges = path_edges + [edge]
                    heapq.heappush(queue, (new_cost, new_path, new_edges))
                    
        return paths
        
    def _create_attack_path(self, nodes: List[str], edges: List[PathEdge]) -> Optional[AttackPath]:
        """Create an attack path object"""
        if not edges:
            return None
            
        total_difficulty = sum(e.difficulty for e in edges) / len(edges)
        total_detection = 1 - (1 - sum(e.detection_risk for e in edges) / len(edges))
        
        techniques = list(set(e.technique.value for e in edges))
        mitre = list(set(e.mitre_id for e in edges))
        
        # Estimate time based on difficulty
        estimated_time = sum(e.difficulty * 4 for e in edges)  # hours
        
        # Calculate risk score
        target_node = self.nodes.get(nodes[-1])
        target_criticality = target_node.criticality if target_node else 5
        risk_score = (1 - total_difficulty) * target_criticality * 10 * (1 - total_detection * 0.3)
        
        return AttackPath(
            id=f"PATH-{uuid.uuid4().hex[:8].upper()}",
            entry_point=nodes[0],
            target=nodes[-1],
            nodes=nodes,
            edges=edges,
            total_difficulty=round(total_difficulty, 2),
            total_detection_risk=round(total_detection, 2),
            techniques_used=techniques,
            mitre_techniques=mitre,
            estimated_time_hours=round(estimated_time, 1),
            risk_score=round(risk_score, 1)
        )
        
    def get_all_paths(self) -> List[Dict]:
        """Get all attack paths"""
        return [
            {
                "id": p.id,
                "entry": self.nodes[p.entry_point].name if p.entry_point in self.nodes else p.entry_point,
                "target": self.nodes[p.target].name if p.target in self.nodes else p.target,
                "hops": len(p.nodes),
                "difficulty": p.total_difficulty,
                "detection_risk": p.total_detection_risk,
                "techniques": p.techniques_used,
                "mitre": p.mitre_techniques,
                "time_hours": p.estimated_time_hours,
                "risk_score": p.risk_score,
                "path": [self.nodes[n].name if n in self.nodes else n for n in p.nodes],
            }
            for p in self.attack_paths
        ]
        
    def get_path_details(self, path_id: str) -> Optional[Dict]:
        """Get detailed path information"""
        path = next((p for p in self.attack_paths if p.id == path_id), None)
        if not path:
            return None
            
        steps = []
        for i, edge in enumerate(path.edges):
            source_node = self.nodes.get(edge.source)
            target_node = self.nodes.get(edge.target)
            
            steps.append({
                "step": i + 1,
                "from": source_node.name if source_node else edge.source,
                "to": target_node.name if target_node else edge.target,
                "technique": edge.technique.value.replace("_", " ").title(),
                "mitre_id": edge.mitre_id,
                "difficulty": edge.difficulty,
                "detection_risk": edge.detection_risk,
                "requirements": edge.requirements,
            })
            
        return {
            "id": path.id,
            "entry": self.nodes[path.entry_point].name,
            "target": self.nodes[path.target].name,
            "risk_score": path.risk_score,
            "total_difficulty": path.total_difficulty,
            "detection_risk": path.total_detection_risk,
            "estimated_time": path.estimated_time_hours,
            "steps": steps,
            "mitre_techniques": path.mitre_techniques,
            "recommendations": self._get_path_recommendations(path),
        }
        
    def _get_path_recommendations(self, path: AttackPath) -> List[str]:
        """Generate recommendations to block attack path"""
        recommendations = []
        
        for edge in path.edges:
            if edge.technique == AttackTechnique.PHISHING:
                recommendations.append("Implement advanced email filtering and phishing simulation training")
            elif edge.technique == AttackTechnique.EXPLOIT_VULN:
                recommendations.append(f"Patch vulnerabilities on path (MITRE: {edge.mitre_id})")
            elif edge.technique == AttackTechnique.CREDENTIAL_THEFT:
                recommendations.append("Enable MFA and implement credential monitoring")
            elif edge.technique == AttackTechnique.LATERAL_MOVEMENT:
                recommendations.append("Implement network segmentation and micro-segmentation")
            elif edge.technique == AttackTechnique.PASS_THE_HASH:
                recommendations.append("Implement Credential Guard and limit admin privileges")
            elif edge.technique == AttackTechnique.KERBEROASTING:
                recommendations.append("Use long, complex service account passwords and AES encryption")
            elif edge.technique == AttackTechnique.DEFAULT_CREDS:
                recommendations.append("Audit and change default credentials across all systems")
            elif edge.technique == AttackTechnique.CLOUD_MISCONFIGURATION:
                recommendations.append("Implement CSPM and regular cloud security audits")
                
        return list(set(recommendations))[:5]
        
    def get_network_topology(self) -> Dict:
        """Get network topology for visualization"""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "type": n.node_type.value,
                    "zone": n.zone,
                    "criticality": n.criticality,
                    "is_entry": n.is_entry_point,
                    "is_target": n.is_target,
                    "has_vulns": len(n.vulnerabilities) > 0,
                    "vulns": n.vulnerabilities,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "technique": e.technique.value,
                    "difficulty": e.difficulty,
                }
                for e in self.edges
            ],
        }
        
    def get_high_risk_paths(self, min_score: float = 50) -> List[Dict]:
        """Get high-risk attack paths"""
        return [p for p in self.get_all_paths() if p["risk_score"] >= min_score]
        
    def get_attack_surface_summary(self) -> Dict:
        """Get attack surface summary"""
        entry_points = [n for n in self.nodes.values() if n.is_entry_point]
        targets = [n for n in self.nodes.values() if n.is_target]
        vulnerable = [n for n in self.nodes.values() if n.vulnerabilities]
        
        high_risk_paths = self.get_high_risk_paths(60)
        
        return {
            "entry_points": len(entry_points),
            "targets": len(targets),
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "vulnerable_nodes": len(vulnerable),
            "attack_paths": len(self.attack_paths),
            "high_risk_paths": len(high_risk_paths),
            "crown_jewels": len(self.crown_jewels),
            "avg_path_difficulty": round(
                sum(p.total_difficulty for p in self.attack_paths) / len(self.attack_paths), 2
            ) if self.attack_paths else 0,
            "max_risk_score": max(p.risk_score for p in self.attack_paths) if self.attack_paths else 0,
        }
        
    @property
    def stats(self) -> Dict:
        """Get analyzer statistics"""
        summary = self.get_attack_surface_summary()
        return {
            "nodes": summary["total_nodes"],
            "edges": summary["total_edges"],
            "paths": summary["attack_paths"],
            "high_risk": summary["high_risk_paths"],
            "entry_points": summary["entry_points"],
            "targets": summary["targets"],
        }


# Global instance
_analyzer_instance: Optional[AttackPathAnalyzer] = None


def get_attack_path_analyzer() -> AttackPathAnalyzer:
    """Get or create attack path analyzer"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = AttackPathAnalyzer()
    return _analyzer_instance
