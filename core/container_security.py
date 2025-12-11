"""
Container Security Scanner - Docker, Kubernetes, and container security analysis
Capabilities: Image scanning, runtime security, K8s audit, container escape detection
"""

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
import logging

logger = logging.getLogger(__name__)


class ContainerPlatform(Enum):
    """Container platforms"""
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    PODMAN = "podman"
    CONTAINERD = "containerd"


class VulnSeverity(Enum):
    """Vulnerability severity levels"""
    UNKNOWN = "unknown"
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MisconfigType(Enum):
    """Misconfiguration types"""
    PRIVILEGED = "privileged"
    ROOT_USER = "root_user"
    CAPABILITIES = "capabilities"
    NETWORK = "network"
    SECRETS = "secrets"
    RESOURCES = "resources"
    RBAC = "rbac"
    POD_SECURITY = "pod_security"


@dataclass
class ContainerVulnerability:
    """Container vulnerability finding"""
    vuln_id: str
    package: str
    version: str
    fixed_version: str
    severity: VulnSeverity
    description: str
    cvss_score: float = 0.0
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ImageLayer:
    """Container image layer"""
    layer_id: str
    created: datetime
    created_by: str
    size: int
    comment: str = ""


@dataclass
class ImageAnalysis:
    """Container image analysis results"""
    image_name: str
    image_id: str
    digest: str = ""
    created: Optional[datetime] = None
    size: int = 0
    os: str = ""
    architecture: str = ""
    layers: List[ImageLayer] = field(default_factory=list)
    packages: List[Dict[str, str]] = field(default_factory=list)
    vulnerabilities: List[ContainerVulnerability] = field(default_factory=list)
    misconfigurations: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    compliance_issues: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ContainerInfo:
    """Running container information"""
    container_id: str
    name: str
    image: str
    status: str
    created: datetime
    ports: List[str] = field(default_factory=list)
    mounts: List[Dict[str, str]] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    pid: int = 0
    privileged: bool = False
    capabilities: List[str] = field(default_factory=list)
    security_options: List[str] = field(default_factory=list)


@dataclass
class K8sResource:
    """Kubernetes resource"""
    kind: str
    name: str
    namespace: str
    uid: str
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    spec: Dict[str, Any] = field(default_factory=dict)


@dataclass
class K8sFinding:
    """Kubernetes security finding"""
    resource_type: str
    resource_name: str
    namespace: str
    finding_type: str
    severity: VulnSeverity
    description: str
    remediation: str
    cis_benchmark: str = ""
    mitre_attack: List[str] = field(default_factory=list)


@dataclass
class ContainerEscapeVector:
    """Container escape vector"""
    name: str
    description: str
    exploitable: bool
    severity: VulnSeverity
    requirements: List[str] = field(default_factory=list)
    technique: str = ""
    mitre_id: str = ""


@dataclass
class ScanReport:
    """Complete container security scan report"""
    scan_id: str
    platform: ContainerPlatform
    target: str
    timestamp: datetime
    images: List[ImageAnalysis] = field(default_factory=list)
    containers: List[ContainerInfo] = field(default_factory=list)
    k8s_findings: List[K8sFinding] = field(default_factory=list)
    escape_vectors: List[ContainerEscapeVector] = field(default_factory=list)
    total_vulns: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    compliance_score: float = 0.0
    scan_duration: float = 0.0


class ContainerSecurityScanner:
    """
    Container Security Scanner
    Comprehensive container and Kubernetes security analysis
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Callbacks
        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        
        # Detection patterns for secrets
        self.secret_patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
            "github_token": r"ghp_[a-zA-Z0-9]{36}",
            "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "generic_secret": r"(?i)(password|secret|token|api_key|apikey)(\s*[=:]\s*)['\"][^'\"]{8,}['\"]",
            "jwt_token": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
        }
        
        # Dangerous capabilities
        self.dangerous_capabilities = [
            "CAP_SYS_ADMIN",
            "CAP_NET_ADMIN",
            "CAP_SYS_PTRACE",
            "CAP_SYS_MODULE",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_SETUID",
            "CAP_SETGID",
            "CAP_NET_RAW",
            "CAP_SYS_CHROOT"
        ]
        
        # Container escape techniques
        self.escape_techniques = [
            {
                "name": "Privileged Container Escape",
                "check": self._check_privileged_escape,
                "mitre_id": "T1611",
                "requirements": ["privileged=true"]
            },
            {
                "name": "Docker Socket Mount",
                "check": self._check_docker_socket_escape,
                "mitre_id": "T1611",
                "requirements": ["/var/run/docker.sock mounted"]
            },
            {
                "name": "CAP_SYS_ADMIN Escape",
                "check": self._check_sysadmin_escape,
                "mitre_id": "T1611",
                "requirements": ["CAP_SYS_ADMIN capability"]
            },
            {
                "name": "cgroups Release Agent",
                "check": self._check_cgroups_escape,
                "mitre_id": "T1611",
                "requirements": ["cgroup v1", "CAP_SYS_ADMIN"]
            },
            {
                "name": "Kernel Exploit (CVE-based)",
                "check": self._check_kernel_escape,
                "mitre_id": "T1068",
                "requirements": ["vulnerable kernel"]
            },
            {
                "name": "Host PID Namespace",
                "check": self._check_host_pid_escape,
                "mitre_id": "T1611",
                "requirements": ["--pid=host"]
            }
        ]
        
        self._log("Container Security Scanner initialized")
    
    def _log(self, message: str, level: str = "info"):
        """Log message"""
        if self.log_callback:
            self.log_callback(message, level)
        logger.log(getattr(logging, level.upper(), logging.INFO), message)
    
    def _update_progress(self, progress: int, status: str):
        """Update progress"""
        if self.progress_callback:
            self.progress_callback(progress, status)
    
    async def scan_docker_environment(self) -> ScanReport:
        """Scan local Docker environment"""
        start_time = datetime.now()
        scan_id = f"docker_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        report = ScanReport(
            scan_id=scan_id,
            platform=ContainerPlatform.DOCKER,
            target="local",
            timestamp=start_time
        )
        
        try:
            self._update_progress(10, "Checking Docker daemon...")
            
            # Check if Docker is available
            if not await self._check_docker_available():
                self._log("Docker daemon not available", "error")
                return report
            
            self._update_progress(20, "Listing containers...")
            report.containers = await self._list_containers()
            
            self._update_progress(40, "Analyzing images...")
            images = await self._list_images()
            for i, image in enumerate(images[:10]):  # Limit to 10 images
                self._update_progress(40 + (i * 3), f"Scanning image: {image[:30]}...")
                analysis = await self.scan_image(image)
                if analysis:
                    report.images.append(analysis)
            
            self._update_progress(80, "Checking escape vectors...")
            report.escape_vectors = await self._check_escape_vectors(report.containers)
            
            self._update_progress(90, "Calculating statistics...")
            self._calculate_stats(report)
            
        except Exception as e:
            self._log(f"Docker scan error: {e}", "error")
        
        report.scan_duration = (datetime.now() - start_time).total_seconds()
        self._update_progress(100, "Scan complete")
        
        return report
    
    async def scan_image(self, image_name: str) -> Optional[ImageAnalysis]:
        """Scan a container image for vulnerabilities"""
        try:
            self._log(f"Scanning image: {image_name}")
            
            # Get image info
            cmd = ["docker", "inspect", image_name]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                self._log(f"Failed to inspect image: {stderr.decode()}", "error")
                return None
            
            inspect_data = json.loads(stdout.decode())[0]
            
            analysis = ImageAnalysis(
                image_name=image_name,
                image_id=inspect_data.get("Id", "")[:12],
                digest=inspect_data.get("RepoDigests", [""])[0],
                created=datetime.fromisoformat(inspect_data.get("Created", "").replace("Z", "+00:00")),
                size=inspect_data.get("Size", 0),
                os=inspect_data.get("Os", ""),
                architecture=inspect_data.get("Architecture", "")
            )
            
            # Get history/layers
            cmd = ["docker", "history", "--no-trunc", "--format", "{{json .}}", image_name]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        layer_data = json.loads(line)
                        analysis.layers.append(ImageLayer(
                            layer_id=layer_data.get("ID", "")[:12],
                            created=datetime.now(),  # Simplified
                            created_by=layer_data.get("CreatedBy", ""),
                            size=self._parse_size(layer_data.get("Size", "0"))
                        ))
                    except json.JSONDecodeError:
                        pass
            
            # Scan for vulnerabilities using built-in analysis
            analysis.vulnerabilities = await self._scan_for_vulns(image_name)
            
            # Scan for misconfigurations
            analysis.misconfigurations = await self._check_image_misconfigs(inspect_data)
            
            # Scan for secrets in image
            analysis.secrets = await self._scan_secrets_in_image(image_name)
            
            return analysis
            
        except Exception as e:
            self._log(f"Image scan error: {e}", "error")
            return None
    
    async def scan_kubernetes_cluster(self, kubeconfig: Optional[str] = None) -> ScanReport:
        """Scan Kubernetes cluster for security issues"""
        start_time = datetime.now()
        scan_id = f"k8s_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        report = ScanReport(
            scan_id=scan_id,
            platform=ContainerPlatform.KUBERNETES,
            target=kubeconfig or "default",
            timestamp=start_time
        )
        
        try:
            self._update_progress(10, "Connecting to cluster...")
            
            # Check kubectl availability
            if not await self._check_kubectl_available():
                self._log("kubectl not available", "error")
                return report
            
            # Scan namespaces
            self._update_progress(20, "Scanning namespaces...")
            namespaces = await self._get_namespaces()
            
            for i, ns in enumerate(namespaces):
                progress = 20 + int((i / len(namespaces)) * 60)
                self._update_progress(progress, f"Scanning namespace: {ns}...")
                
                # Scan pods
                findings = await self._scan_namespace_pods(ns)
                report.k8s_findings.extend(findings)
                
                # Scan RBAC
                rbac_findings = await self._scan_rbac(ns)
                report.k8s_findings.extend(rbac_findings)
                
                # Scan network policies
                netpol_findings = await self._scan_network_policies(ns)
                report.k8s_findings.extend(netpol_findings)
            
            # Scan cluster-level resources
            self._update_progress(85, "Scanning cluster resources...")
            cluster_findings = await self._scan_cluster_resources()
            report.k8s_findings.extend(cluster_findings)
            
            self._update_progress(95, "Calculating compliance...")
            self._calculate_k8s_compliance(report)
            
        except Exception as e:
            self._log(f"Kubernetes scan error: {e}", "error")
        
        report.scan_duration = (datetime.now() - start_time).total_seconds()
        self._update_progress(100, "Scan complete")
        
        return report
    
    async def _check_docker_available(self) -> bool:
        """Check if Docker daemon is available"""
        try:
            result = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0
        except:
            return False
    
    async def _check_kubectl_available(self) -> bool:
        """Check if kubectl is available"""
        try:
            result = await asyncio.create_subprocess_exec(
                "kubectl", "version", "--client",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0
        except:
            return False
    
    async def _list_containers(self) -> List[ContainerInfo]:
        """List all running containers"""
        containers = []
        
        try:
            cmd = ["docker", "ps", "-a", "--format", "{{json .}}"]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        container_id = data.get("ID", "")
                        
                        # Get detailed info
                        inspect_cmd = ["docker", "inspect", container_id]
                        inspect_result = await asyncio.create_subprocess_exec(
                            *inspect_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                        )
                        inspect_out, _ = await inspect_result.communicate()
                        inspect_data = json.loads(inspect_out.decode())[0]
                        
                        host_config = inspect_data.get("HostConfig", {})
                        
                        container = ContainerInfo(
                            container_id=container_id,
                            name=data.get("Names", ""),
                            image=data.get("Image", ""),
                            status=data.get("Status", ""),
                            created=datetime.now(),
                            ports=data.get("Ports", "").split(",") if data.get("Ports") else [],
                            privileged=host_config.get("Privileged", False),
                            capabilities=host_config.get("CapAdd", []) or [],
                            pid=inspect_data.get("State", {}).get("Pid", 0)
                        )
                        
                        # Get mounts
                        for mount in inspect_data.get("Mounts", []):
                            container.mounts.append({
                                "source": mount.get("Source", ""),
                                "destination": mount.get("Destination", ""),
                                "type": mount.get("Type", ""),
                                "rw": mount.get("RW", True)
                            })
                        
                        containers.append(container)
                    except json.JSONDecodeError:
                        pass
                    except Exception as e:
                        self._log(f"Container parse error: {e}", "warning")
        except Exception as e:
            self._log(f"List containers error: {e}", "error")
        
        return containers
    
    async def _list_images(self) -> List[str]:
        """List all Docker images"""
        images = []
        
        try:
            cmd = ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            for line in stdout.decode().strip().split('\n'):
                if line and line != "<none>:<none>":
                    images.append(line)
        except Exception as e:
            self._log(f"List images error: {e}", "error")
        
        return images
    
    async def _scan_for_vulns(self, image_name: str) -> List[ContainerVulnerability]:
        """Scan image for vulnerabilities (simulated - real implementation would use Trivy/Grype)"""
        vulns = []
        
        # Common vulnerable packages to check for
        known_vulns = {
            "openssl": [
                ("CVE-2021-3711", "1.1.1k", "HIGH", "Buffer overflow in SM2 decryption", 7.5),
                ("CVE-2021-3712", "1.1.1l", "MEDIUM", "Buffer overflow in X.509 name constraint", 5.3)
            ],
            "libssl": [
                ("CVE-2022-0778", "1.1.1n", "HIGH", "Infinite loop in certificate parsing", 7.5)
            ],
            "curl": [
                ("CVE-2023-27533", "7.88.0", "MEDIUM", "TELNET protocol injection", 6.5)
            ],
            "log4j": [
                ("CVE-2021-44228", "2.17.0", "CRITICAL", "Remote code execution (Log4Shell)", 10.0)
            ],
            "spring": [
                ("CVE-2022-22965", "5.3.18", "CRITICAL", "Spring4Shell RCE", 9.8)
            ]
        }
        
        # Simulate package detection
        for pkg, pkg_vulns in known_vulns.items():
            for vuln_id, fixed_ver, severity, desc, cvss in pkg_vulns:
                # Randomly include some vulns for demo
                import random
                if random.random() > 0.7:
                    vulns.append(ContainerVulnerability(
                        vuln_id=vuln_id,
                        package=pkg,
                        version="<vulnerable>",
                        fixed_version=fixed_ver,
                        severity=VulnSeverity[severity],
                        description=desc,
                        cvss_score=cvss
                    ))
        
        return vulns
    
    async def _check_image_misconfigs(self, inspect_data: Dict) -> List[Dict[str, Any]]:
        """Check image for misconfigurations"""
        misconfigs = []
        config = inspect_data.get("Config", {})
        
        # Check for root user
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            misconfigs.append({
                "type": MisconfigType.ROOT_USER.value,
                "severity": "high",
                "description": "Container runs as root user",
                "remediation": "Add USER instruction in Dockerfile to run as non-root"
            })
        
        # Check for exposed ports
        exposed_ports = config.get("ExposedPorts", {})
        if exposed_ports:
            for port in exposed_ports.keys():
                if "22" in port:
                    misconfigs.append({
                        "type": MisconfigType.NETWORK.value,
                        "severity": "medium",
                        "description": f"SSH port {port} exposed",
                        "remediation": "Avoid exposing SSH in containers"
                    })
        
        # Check environment for secrets
        env = config.get("Env", [])
        for e in env:
            lower_e = e.lower()
            if any(kw in lower_e for kw in ["password", "secret", "token", "key", "api"]):
                misconfigs.append({
                    "type": MisconfigType.SECRETS.value,
                    "severity": "high",
                    "description": "Potential secrets in environment variables",
                    "remediation": "Use secrets management (Docker secrets, K8s secrets, vault)"
                })
                break
        
        return misconfigs
    
    async def _scan_secrets_in_image(self, image_name: str) -> List[Dict[str, str]]:
        """Scan image filesystem for secrets"""
        secrets = []
        
        # This would normally extract and scan the image filesystem
        # Simplified version that checks env and labels
        try:
            cmd = ["docker", "inspect", "--format", "{{json .Config.Env}}", image_name]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            env_vars = json.loads(stdout.decode())
            for env in env_vars or []:
                for pattern_name, pattern in self.secret_patterns.items():
                    if re.search(pattern, env):
                        secrets.append({
                            "type": pattern_name,
                            "location": "environment variable",
                            "value": env[:50] + "..." if len(env) > 50 else env
                        })
                        break
        except:
            pass
        
        return secrets
    
    async def _check_escape_vectors(self, containers: List[ContainerInfo]) -> List[ContainerEscapeVector]:
        """Check for container escape vectors"""
        vectors = []
        
        for container in containers:
            for technique in self.escape_techniques:
                result = await technique["check"](container)
                if result["exploitable"]:
                    vectors.append(ContainerEscapeVector(
                        name=technique["name"],
                        description=result["description"],
                        exploitable=True,
                        severity=VulnSeverity.CRITICAL,
                        requirements=technique["requirements"],
                        technique=result.get("technique", ""),
                        mitre_id=technique["mitre_id"]
                    ))
        
        return vectors
    
    async def _check_privileged_escape(self, container: ContainerInfo) -> Dict:
        """Check for privileged container escape"""
        if container.privileged:
            return {
                "exploitable": True,
                "description": f"Container {container.name} runs in privileged mode",
                "technique": "mount host filesystem, load kernel modules"
            }
        return {"exploitable": False, "description": ""}
    
    async def _check_docker_socket_escape(self, container: ContainerInfo) -> Dict:
        """Check for Docker socket mount escape"""
        for mount in container.mounts:
            if "/var/run/docker.sock" in mount.get("source", ""):
                return {
                    "exploitable": True,
                    "description": f"Container {container.name} has Docker socket mounted",
                    "technique": "Create privileged container from within"
                }
        return {"exploitable": False, "description": ""}
    
    async def _check_sysadmin_escape(self, container: ContainerInfo) -> Dict:
        """Check for CAP_SYS_ADMIN escape"""
        if "CAP_SYS_ADMIN" in container.capabilities or "SYS_ADMIN" in container.capabilities:
            return {
                "exploitable": True,
                "description": f"Container {container.name} has CAP_SYS_ADMIN",
                "technique": "Mount host filesystem, abuse namespaces"
            }
        return {"exploitable": False, "description": ""}
    
    async def _check_cgroups_escape(self, container: ContainerInfo) -> Dict:
        """Check for cgroups release_agent escape"""
        # Would check cgroup version and capabilities
        return {"exploitable": False, "description": ""}
    
    async def _check_kernel_escape(self, container: ContainerInfo) -> Dict:
        """Check for kernel-based escapes"""
        # Would check kernel version against known CVEs
        return {"exploitable": False, "description": ""}
    
    async def _check_host_pid_escape(self, container: ContainerInfo) -> Dict:
        """Check for host PID namespace escape"""
        # Would check if container shares host PID namespace
        return {"exploitable": False, "description": ""}
    
    async def _get_namespaces(self) -> List[str]:
        """Get Kubernetes namespaces"""
        try:
            cmd = ["kubectl", "get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            return stdout.decode().split()
        except:
            return ["default"]
    
    async def _scan_namespace_pods(self, namespace: str) -> List[K8sFinding]:
        """Scan pods in namespace for security issues"""
        findings = []
        
        try:
            cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            pods_data = json.loads(stdout.decode())
            
            for pod in pods_data.get("items", []):
                pod_name = pod.get("metadata", {}).get("name", "")
                spec = pod.get("spec", {})
                
                # Check security context
                for container in spec.get("containers", []):
                    security_ctx = container.get("securityContext", {})
                    
                    # Privileged container
                    if security_ctx.get("privileged"):
                        findings.append(K8sFinding(
                            resource_type="Pod",
                            resource_name=pod_name,
                            namespace=namespace,
                            finding_type="Privileged Container",
                            severity=VulnSeverity.CRITICAL,
                            description=f"Container {container.get('name')} runs in privileged mode",
                            remediation="Set privileged: false in securityContext",
                            cis_benchmark="5.2.1",
                            mitre_attack=["T1611"]
                        ))
                    
                    # Root user
                    if security_ctx.get("runAsUser", 0) == 0:
                        findings.append(K8sFinding(
                            resource_type="Pod",
                            resource_name=pod_name,
                            namespace=namespace,
                            finding_type="Root User",
                            severity=VulnSeverity.HIGH,
                            description=f"Container {container.get('name')} runs as root",
                            remediation="Set runAsNonRoot: true and specify runAsUser",
                            cis_benchmark="5.2.6"
                        ))
                    
                    # Host network
                    if spec.get("hostNetwork"):
                        findings.append(K8sFinding(
                            resource_type="Pod",
                            resource_name=pod_name,
                            namespace=namespace,
                            finding_type="Host Network",
                            severity=VulnSeverity.HIGH,
                            description="Pod uses host network namespace",
                            remediation="Set hostNetwork: false unless absolutely necessary",
                            cis_benchmark="5.2.4"
                        ))
                    
                    # Host PID
                    if spec.get("hostPID"):
                        findings.append(K8sFinding(
                            resource_type="Pod",
                            resource_name=pod_name,
                            namespace=namespace,
                            finding_type="Host PID",
                            severity=VulnSeverity.HIGH,
                            description="Pod shares host PID namespace",
                            remediation="Set hostPID: false",
                            cis_benchmark="5.2.2",
                            mitre_attack=["T1611"]
                        ))
                    
                    # No resource limits
                    resources = container.get("resources", {})
                    if not resources.get("limits"):
                        findings.append(K8sFinding(
                            resource_type="Pod",
                            resource_name=pod_name,
                            namespace=namespace,
                            finding_type="No Resource Limits",
                            severity=VulnSeverity.MEDIUM,
                            description=f"Container {container.get('name')} has no resource limits",
                            remediation="Set CPU and memory limits",
                            cis_benchmark="5.4.1"
                        ))
        except Exception as e:
            self._log(f"Pod scan error: {e}", "error")
        
        return findings
    
    async def _scan_rbac(self, namespace: str) -> List[K8sFinding]:
        """Scan RBAC configuration"""
        findings = []
        
        try:
            # Check RoleBindings
            cmd = ["kubectl", "get", "rolebindings", "-n", namespace, "-o", "json"]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            bindings = json.loads(stdout.decode())
            
            for binding in bindings.get("items", []):
                name = binding.get("metadata", {}).get("name", "")
                role_ref = binding.get("roleRef", {})
                
                # Check for cluster-admin binding
                if role_ref.get("name") == "cluster-admin":
                    findings.append(K8sFinding(
                        resource_type="RoleBinding",
                        resource_name=name,
                        namespace=namespace,
                        finding_type="Cluster Admin Binding",
                        severity=VulnSeverity.CRITICAL,
                        description="RoleBinding grants cluster-admin privileges",
                        remediation="Use least privilege principle, avoid cluster-admin",
                        cis_benchmark="5.1.1"
                    ))
        except Exception as e:
            self._log(f"RBAC scan error: {e}", "warning")
        
        return findings
    
    async def _scan_network_policies(self, namespace: str) -> List[K8sFinding]:
        """Scan network policies"""
        findings = []
        
        try:
            cmd = ["kubectl", "get", "networkpolicies", "-n", namespace, "-o", "json"]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            policies = json.loads(stdout.decode())
            
            if not policies.get("items"):
                findings.append(K8sFinding(
                    resource_type="Namespace",
                    resource_name=namespace,
                    namespace=namespace,
                    finding_type="No Network Policy",
                    severity=VulnSeverity.MEDIUM,
                    description="Namespace has no network policies",
                    remediation="Implement default deny network policies",
                    cis_benchmark="5.3.2"
                ))
        except Exception as e:
            self._log(f"Network policy scan error: {e}", "warning")
        
        return findings
    
    async def _scan_cluster_resources(self) -> List[K8sFinding]:
        """Scan cluster-level resources"""
        findings = []
        
        try:
            # Check ClusterRoleBindings
            cmd = ["kubectl", "get", "clusterrolebindings", "-o", "json"]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            bindings = json.loads(stdout.decode())
            
            for binding in bindings.get("items", []):
                name = binding.get("metadata", {}).get("name", "")
                subjects = binding.get("subjects", [])
                role_ref = binding.get("roleRef", {})
                
                # Check for default service account with elevated privileges
                for subject in subjects:
                    if subject.get("name") == "default" and subject.get("kind") == "ServiceAccount":
                        if role_ref.get("name") in ["cluster-admin", "admin", "edit"]:
                            findings.append(K8sFinding(
                                resource_type="ClusterRoleBinding",
                                resource_name=name,
                                namespace="cluster",
                                finding_type="Default SA Elevated Privileges",
                                severity=VulnSeverity.HIGH,
                                description=f"Default service account has {role_ref.get('name')} privileges",
                                remediation="Don't grant elevated privileges to default service account",
                                cis_benchmark="5.1.5"
                            ))
        except Exception as e:
            self._log(f"Cluster scan error: {e}", "warning")
        
        return findings
    
    def _calculate_stats(self, report: ScanReport):
        """Calculate vulnerability statistics"""
        for image in report.images:
            for vuln in image.vulnerabilities:
                report.total_vulns += 1
                if vuln.severity == VulnSeverity.CRITICAL:
                    report.critical_vulns += 1
                elif vuln.severity == VulnSeverity.HIGH:
                    report.high_vulns += 1
    
    def _calculate_k8s_compliance(self, report: ScanReport):
        """Calculate Kubernetes compliance score"""
        if not report.k8s_findings:
            report.compliance_score = 100.0
            return
        
        severity_weights = {
            VulnSeverity.CRITICAL: 10,
            VulnSeverity.HIGH: 5,
            VulnSeverity.MEDIUM: 2,
            VulnSeverity.LOW: 1
        }
        
        total_deductions = sum(
            severity_weights.get(f.severity, 1) 
            for f in report.k8s_findings
        )
        
        report.compliance_score = max(0, 100 - total_deductions)
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes"""
        try:
            if not size_str or size_str == "0B":
                return 0
            
            units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
            
            for unit, multiplier in units.items():
                if unit in size_str.upper():
                    num = float(re.sub(r'[^\d.]', '', size_str))
                    return int(num * multiplier)
            
            return int(float(re.sub(r'[^\d.]', '', size_str)))
        except:
            return 0
    
    async def generate_report(self, scan: ScanReport, format: str = "json") -> str:
        """Generate scan report"""
        if format == "json":
            return json.dumps(self._report_to_dict(scan), indent=2, default=str)
        elif format == "markdown":
            return self._report_to_markdown(scan)
        else:
            return json.dumps(self._report_to_dict(scan), indent=2, default=str)
    
    def _report_to_dict(self, report: ScanReport) -> Dict:
        """Convert report to dictionary"""
        return {
            "scan_id": report.scan_id,
            "platform": report.platform.value,
            "target": report.target,
            "timestamp": report.timestamp.isoformat(),
            "statistics": {
                "total_vulnerabilities": report.total_vulns,
                "critical": report.critical_vulns,
                "high": report.high_vulns,
                "compliance_score": report.compliance_score
            },
            "images": len(report.images),
            "containers": len(report.containers),
            "escape_vectors": [
                {"name": e.name, "severity": e.severity.value}
                for e in report.escape_vectors
            ],
            "k8s_findings": len(report.k8s_findings),
            "scan_duration": report.scan_duration
        }
    
    def _report_to_markdown(self, report: ScanReport) -> str:
        """Generate markdown report"""
        md = f"""# Container Security Scan Report

## Overview
- **Scan ID:** {report.scan_id}
- **Platform:** {report.platform.value}
- **Target:** {report.target}
- **Timestamp:** {report.timestamp}
- **Duration:** {report.scan_duration:.2f}s

## Statistics
- **Total Vulnerabilities:** {report.total_vulns}
- **Critical:** {report.critical_vulns}
- **High:** {report.high_vulns}
- **Compliance Score:** {report.compliance_score:.1f}%

## Container Escape Vectors ({len(report.escape_vectors)})
"""
        for escape in report.escape_vectors:
            md += f"- **{escape.name}** ({escape.severity.value}): {escape.description}\n"
        
        md += f"\n## Kubernetes Findings ({len(report.k8s_findings)})\n"
        for finding in report.k8s_findings[:20]:
            md += f"- [{finding.severity.value}] {finding.resource_type}/{finding.resource_name}: {finding.description}\n"
        
        return md
