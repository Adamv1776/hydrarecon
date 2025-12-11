"""
Advanced Network Pivoting Module
Multi-hop tunneling, port forwarding, and lateral movement for HydraRecon
"""

import asyncio
import base64
import hashlib
import json
import os
import random
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Tuple
import ipaddress


class TunnelType(Enum):
    """Types of tunnels"""
    SSH = "ssh"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    HTTP_PROXY = "http_proxy"
    HTTPS_PROXY = "https_proxy"
    DNS_TUNNEL = "dns_tunnel"
    ICMP_TUNNEL = "icmp_tunnel"
    TCP_RELAY = "tcp_relay"
    UDP_RELAY = "udp_relay"
    REVERSE_SSH = "reverse_ssh"
    CHISEL = "chisel"
    LIGOLO = "ligolo"


class PivotStatus(Enum):
    """Pivot point status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    CONNECTING = "connecting"
    ERROR = "error"
    AUTHENTICATED = "authenticated"


class RouteType(Enum):
    """Network route types"""
    DIRECT = "direct"
    TUNNELED = "tunneled"
    MULTI_HOP = "multi_hop"
    LOAD_BALANCED = "load_balanced"


@dataclass
class PivotHost:
    """Represents a pivot point in the network"""
    host_id: str
    ip_address: str
    hostname: str = ""
    username: str = ""
    credentials: Dict = field(default_factory=dict)
    status: PivotStatus = PivotStatus.INACTIVE
    tunnel_type: TunnelType = TunnelType.SSH
    local_port: int = 0
    remote_port: int = 22
    accessible_networks: List[str] = field(default_factory=list)
    discovered_hosts: List[str] = field(default_factory=list)
    hop_count: int = 0
    parent_pivot: Optional[str] = None
    child_pivots: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    latency_ms: float = 0.0
    bandwidth_kbps: float = 0.0


@dataclass
class NetworkRoute:
    """Represents a route through the pivot network"""
    route_id: str
    destination: str
    destination_port: int
    route_type: RouteType
    pivot_chain: List[str] = field(default_factory=list)
    local_bind_port: int = 0
    is_active: bool = False
    bytes_transferred: int = 0
    connections: int = 0


@dataclass
class PortForward:
    """Port forwarding configuration"""
    forward_id: str
    direction: str  # "local" or "remote"
    local_host: str
    local_port: int
    remote_host: str
    remote_port: int
    pivot_id: str
    is_active: bool = False
    process: Optional[Any] = None


@dataclass
class SOCKSProxy:
    """SOCKS proxy configuration"""
    proxy_id: str
    proxy_type: str  # "socks4" or "socks5"
    bind_address: str
    bind_port: int
    pivot_id: str
    auth_required: bool = False
    username: str = ""
    password: str = ""
    is_active: bool = False


class NetworkPivotingModule:
    """
    Advanced Network Pivoting Framework
    Enables multi-hop tunneling and lateral movement
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.pivots: Dict[str, PivotHost] = {}
        self.routes: Dict[str, NetworkRoute] = {}
        self.port_forwards: Dict[str, PortForward] = {}
        self.socks_proxies: Dict[str, SOCKSProxy] = {}
        self.active_tunnels: Dict[str, Any] = {}
        self.network_map: Dict[str, List[str]] = {}  # network -> hosts
        
        self.base_local_port = 10000
        self.next_local_port = self.base_local_port
        
        # Tunnel handlers
        self.tunnel_handlers = {
            TunnelType.SSH: self._create_ssh_tunnel,
            TunnelType.SOCKS5: self._create_socks5_proxy,
            TunnelType.REVERSE_SSH: self._create_reverse_ssh,
            TunnelType.TCP_RELAY: self._create_tcp_relay,
            TunnelType.DNS_TUNNEL: self._create_dns_tunnel,
            TunnelType.CHISEL: self._create_chisel_tunnel,
        }
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:12]
    
    def _get_next_port(self) -> int:
        """Get next available local port"""
        port = self.next_local_port
        self.next_local_port += 1
        return port
    
    async def add_pivot(self, ip_address: str, username: str = "", 
                        password: str = "", ssh_key: str = "",
                        tunnel_type: TunnelType = TunnelType.SSH,
                        remote_port: int = 22,
                        parent_pivot_id: Optional[str] = None) -> PivotHost:
        """Add a new pivot point to the network"""
        pivot_id = self._generate_id()
        local_port = self._get_next_port()
        
        credentials = {}
        if password:
            credentials['password'] = password
        if ssh_key:
            credentials['ssh_key'] = ssh_key
        
        # Calculate hop count
        hop_count = 0
        if parent_pivot_id and parent_pivot_id in self.pivots:
            hop_count = self.pivots[parent_pivot_id].hop_count + 1
        
        pivot = PivotHost(
            host_id=pivot_id,
            ip_address=ip_address,
            username=username,
            credentials=credentials,
            tunnel_type=tunnel_type,
            local_port=local_port,
            remote_port=remote_port,
            hop_count=hop_count,
            parent_pivot=parent_pivot_id
        )
        
        # Update parent's child list
        if parent_pivot_id and parent_pivot_id in self.pivots:
            self.pivots[parent_pivot_id].child_pivots.append(pivot_id)
        
        self.pivots[pivot_id] = pivot
        
        return pivot
    
    async def connect_pivot(self, pivot_id: str) -> bool:
        """Establish connection to a pivot point"""
        if pivot_id not in self.pivots:
            raise ValueError(f"Pivot not found: {pivot_id}")
        
        pivot = self.pivots[pivot_id]
        pivot.status = PivotStatus.CONNECTING
        
        try:
            # Get tunnel handler
            handler = self.tunnel_handlers.get(pivot.tunnel_type)
            if not handler:
                raise ValueError(f"Unsupported tunnel type: {pivot.tunnel_type}")
            
            # Create tunnel (potentially through parent pivots)
            proxy_command = None
            if pivot.parent_pivot:
                proxy_command = self._build_proxy_chain(pivot.parent_pivot)
            
            success = await handler(pivot, proxy_command)
            
            if success:
                pivot.status = PivotStatus.ACTIVE
                pivot.last_seen = datetime.now().isoformat()
                
                # Discover accessible networks
                await self._discover_networks(pivot)
                
                return True
            else:
                pivot.status = PivotStatus.ERROR
                return False
                
        except Exception as e:
            pivot.status = PivotStatus.ERROR
            raise
    
    def _build_proxy_chain(self, pivot_id: str) -> str:
        """Build ProxyCommand chain for multi-hop SSH"""
        chain = []
        current_id = pivot_id
        
        while current_id:
            if current_id in self.pivots:
                pivot = self.pivots[current_id]
                chain.insert(0, pivot)
                current_id = pivot.parent_pivot
            else:
                break
        
        if not chain:
            return ""
        
        # Build nested ProxyCommand
        commands = []
        for pivot in chain:
            cmd = f"ssh -W %h:%p -p {pivot.remote_port} {pivot.username}@{pivot.ip_address}"
            commands.append(cmd)
        
        # Nest commands for multi-hop
        if len(commands) == 1:
            return f"-o ProxyCommand='{commands[0]}'"
        else:
            # Build nested proxy chain
            proxy_cmd = commands[0]
            for cmd in commands[1:]:
                proxy_cmd = f"{cmd} -o ProxyCommand='{proxy_cmd}'"
            return f"-o ProxyCommand='{proxy_cmd}'"
    
    async def _create_ssh_tunnel(self, pivot: PivotHost, 
                                  proxy_command: Optional[str] = None) -> bool:
        """Create SSH tunnel to pivot"""
        try:
            # Build SSH command
            ssh_args = [
                'ssh',
                '-N',  # Don't execute remote command
                '-f',  # Background
                '-D', f'127.0.0.1:{pivot.local_port}',  # Dynamic SOCKS proxy
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=10',
            ]
            
            # Add proxy command for multi-hop
            if proxy_command:
                ssh_args.extend(proxy_command.split())
            
            # Add authentication
            if pivot.credentials.get('ssh_key'):
                ssh_args.extend(['-i', pivot.credentials['ssh_key']])
            
            # Add port if not default
            if pivot.remote_port != 22:
                ssh_args.extend(['-p', str(pivot.remote_port)])
            
            # Add host
            ssh_args.append(f'{pivot.username}@{pivot.ip_address}')
            
            # For password auth, we'd use sshpass or expect
            if pivot.credentials.get('password'):
                ssh_args = ['sshpass', '-p', pivot.credentials['password']] + ssh_args
            
            # Execute (in real implementation)
            # process = subprocess.Popen(ssh_args, ...)
            
            # Store tunnel info
            self.active_tunnels[pivot.host_id] = {
                'type': 'ssh',
                'command': ssh_args,
                'local_port': pivot.local_port,
                'started': datetime.now().isoformat()
            }
            
            # Create corresponding SOCKS proxy entry
            await self.create_socks_proxy(pivot.host_id, pivot.local_port)
            
            return True
            
        except Exception as e:
            return False
    
    async def _create_socks5_proxy(self, pivot: PivotHost,
                                    proxy_command: Optional[str] = None) -> bool:
        """Create SOCKS5 proxy through pivot"""
        try:
            # Similar to SSH but with SOCKS5 specific handling
            return await self._create_ssh_tunnel(pivot, proxy_command)
        except Exception:
            return False
    
    async def _create_reverse_ssh(self, pivot: PivotHost,
                                   proxy_command: Optional[str] = None) -> bool:
        """Create reverse SSH tunnel"""
        try:
            ssh_args = [
                'ssh',
                '-N', '-f',
                '-R', f'{pivot.remote_port}:localhost:{pivot.local_port}',
                '-o', 'StrictHostKeyChecking=no',
            ]
            
            if pivot.credentials.get('ssh_key'):
                ssh_args.extend(['-i', pivot.credentials['ssh_key']])
            
            ssh_args.append(f'{pivot.username}@{pivot.ip_address}')
            
            self.active_tunnels[pivot.host_id] = {
                'type': 'reverse_ssh',
                'command': ssh_args,
                'local_port': pivot.local_port,
                'remote_port': pivot.remote_port,
                'started': datetime.now().isoformat()
            }
            
            return True
        except Exception:
            return False
    
    async def _create_tcp_relay(self, pivot: PivotHost,
                                 proxy_command: Optional[str] = None) -> bool:
        """Create TCP relay/port forward"""
        try:
            # Use socat or custom TCP relay
            self.active_tunnels[pivot.host_id] = {
                'type': 'tcp_relay',
                'local_port': pivot.local_port,
                'remote': f'{pivot.ip_address}:{pivot.remote_port}',
                'started': datetime.now().isoformat()
            }
            return True
        except Exception:
            return False
    
    async def _create_dns_tunnel(self, pivot: PivotHost,
                                  proxy_command: Optional[str] = None) -> bool:
        """Create DNS tunnel for covert communication"""
        try:
            # Would use tools like dnscat2, iodine
            self.active_tunnels[pivot.host_id] = {
                'type': 'dns_tunnel',
                'local_port': pivot.local_port,
                'dns_domain': pivot.credentials.get('dns_domain', ''),
                'started': datetime.now().isoformat()
            }
            return True
        except Exception:
            return False
    
    async def _create_chisel_tunnel(self, pivot: PivotHost,
                                     proxy_command: Optional[str] = None) -> bool:
        """Create Chisel tunnel"""
        try:
            # Chisel is a fast TCP/UDP tunnel over HTTP
            chisel_args = [
                'chisel', 'client',
                f'{pivot.ip_address}:{pivot.remote_port}',
                f'socks:127.0.0.1:{pivot.local_port}'
            ]
            
            self.active_tunnels[pivot.host_id] = {
                'type': 'chisel',
                'command': chisel_args,
                'local_port': pivot.local_port,
                'started': datetime.now().isoformat()
            }
            return True
        except Exception:
            return False
    
    async def _discover_networks(self, pivot: PivotHost):
        """Discover networks accessible from pivot"""
        try:
            # Commands to run on pivot to discover networks
            discovery_commands = [
                # Get network interfaces
                "ip addr show 2>/dev/null || ifconfig",
                # Get routing table
                "ip route show 2>/dev/null || netstat -rn",
                # Get ARP table
                "arp -a 2>/dev/null || ip neigh show",
            ]
            
            networks = []
            hosts = []
            
            # Parse interface info to find connected networks
            # This would execute commands through the tunnel
            
            # Example discovered networks
            if pivot.ip_address.startswith("192.168."):
                networks.append("192.168.0.0/16")
            elif pivot.ip_address.startswith("10."):
                networks.append("10.0.0.0/8")
            elif pivot.ip_address.startswith("172."):
                networks.append("172.16.0.0/12")
            
            pivot.accessible_networks = networks
            
            # Update network map
            for network in networks:
                if network not in self.network_map:
                    self.network_map[network] = []
                if pivot.ip_address not in self.network_map[network]:
                    self.network_map[network].append(pivot.ip_address)
                    
        except Exception:
            pass
    
    async def create_port_forward(self, pivot_id: str, direction: str,
                                   local_host: str, local_port: int,
                                   remote_host: str, remote_port: int) -> PortForward:
        """Create port forward through pivot"""
        if pivot_id not in self.pivots:
            raise ValueError(f"Pivot not found: {pivot_id}")
        
        forward_id = self._generate_id()
        pivot = self.pivots[pivot_id]
        
        forward = PortForward(
            forward_id=forward_id,
            direction=direction,
            local_host=local_host,
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            pivot_id=pivot_id
        )
        
        # Build port forward command
        if direction == "local":
            # Local port forward: -L local:remote
            ssh_arg = f"-L {local_host}:{local_port}:{remote_host}:{remote_port}"
        else:
            # Remote port forward: -R remote:local
            ssh_arg = f"-R {remote_host}:{remote_port}:{local_host}:{local_port}"
        
        forward.is_active = True
        self.port_forwards[forward_id] = forward
        
        return forward
    
    async def create_socks_proxy(self, pivot_id: str, bind_port: int,
                                  proxy_type: str = "socks5",
                                  bind_address: str = "127.0.0.1") -> SOCKSProxy:
        """Create SOCKS proxy through pivot"""
        if pivot_id not in self.pivots:
            raise ValueError(f"Pivot not found: {pivot_id}")
        
        proxy_id = self._generate_id()
        
        proxy = SOCKSProxy(
            proxy_id=proxy_id,
            proxy_type=proxy_type,
            bind_address=bind_address,
            bind_port=bind_port,
            pivot_id=pivot_id,
            is_active=True
        )
        
        self.socks_proxies[proxy_id] = proxy
        
        return proxy
    
    async def create_route(self, destination: str, destination_port: int,
                           pivot_chain: List[str]) -> NetworkRoute:
        """Create route to destination through pivot chain"""
        route_id = self._generate_id()
        local_port = self._get_next_port()
        
        # Validate pivot chain
        for pivot_id in pivot_chain:
            if pivot_id not in self.pivots:
                raise ValueError(f"Pivot not found in chain: {pivot_id}")
        
        route = NetworkRoute(
            route_id=route_id,
            destination=destination,
            destination_port=destination_port,
            route_type=RouteType.MULTI_HOP if len(pivot_chain) > 1 else RouteType.TUNNELED,
            pivot_chain=pivot_chain,
            local_bind_port=local_port,
            is_active=True
        )
        
        self.routes[route_id] = route
        
        return route
    
    async def scan_through_pivot(self, pivot_id: str, target_network: str,
                                  scan_type: str = "ping") -> List[str]:
        """Scan network through pivot point"""
        if pivot_id not in self.pivots:
            raise ValueError(f"Pivot not found: {pivot_id}")
        
        pivot = self.pivots[pivot_id]
        discovered_hosts = []
        
        try:
            network = ipaddress.ip_network(target_network, strict=False)
            
            if scan_type == "ping":
                # Ping sweep through tunnel
                for ip in network.hosts():
                    # Would execute ping through SOCKS proxy
                    pass
            
            elif scan_type == "arp":
                # ARP scan (requires same L2 network)
                pass
            
            elif scan_type == "tcp_syn":
                # TCP SYN scan through tunnel
                common_ports = [22, 80, 443, 445, 3389, 8080]
                for ip in list(network.hosts())[:256]:  # Limit for demo
                    for port in common_ports:
                        # Would scan through SOCKS proxy
                        pass
            
            pivot.discovered_hosts.extend(discovered_hosts)
            
        except Exception as e:
            pass
        
        return discovered_hosts
    
    async def execute_through_pivot(self, pivot_id: str, command: str) -> str:
        """Execute command through pivot"""
        if pivot_id not in self.pivots:
            raise ValueError(f"Pivot not found: {pivot_id}")
        
        pivot = self.pivots[pivot_id]
        
        # Build command to execute through SSH tunnel
        ssh_cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=10',
        ]
        
        if pivot.credentials.get('ssh_key'):
            ssh_cmd.extend(['-i', pivot.credentials['ssh_key']])
        
        if pivot.remote_port != 22:
            ssh_cmd.extend(['-p', str(pivot.remote_port)])
        
        ssh_cmd.append(f'{pivot.username}@{pivot.ip_address}')
        ssh_cmd.append(command)
        
        # Execute command through SSH
        try:
            # Try using paramiko first for better control
            try:
                import paramiko
                
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_kwargs = {
                    'hostname': pivot.ip_address,
                    'port': pivot.remote_port or 22,
                    'username': pivot.username,
                    'timeout': 10
                }
                
                if pivot.credentials.get('ssh_key'):
                    key_path = pivot.credentials['ssh_key']
                    if os.path.exists(key_path):
                        connect_kwargs['key_filename'] = key_path
                elif pivot.credentials.get('password'):
                    connect_kwargs['password'] = pivot.credentials['password']
                
                client.connect(**connect_kwargs)
                
                stdin, stdout, stderr = client.exec_command(command, timeout=30)
                output = stdout.read().decode('utf-8', errors='replace')
                error = stderr.read().decode('utf-8', errors='replace')
                
                client.close()
                
                if error and not output:
                    return f"Error: {error}"
                return output if output else error
                
            except ImportError:
                # Fallback to subprocess
                proc = await asyncio.create_subprocess_exec(
                    *ssh_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.DEVNULL
                )
                
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                
                output = stdout.decode('utf-8', errors='replace')
                error = stderr.decode('utf-8', errors='replace')
                
                if proc.returncode != 0 and not output:
                    return f"Error (exit {proc.returncode}): {error}"
                return output if output else error
                
        except asyncio.TimeoutError:
            return "Error: Command timed out after 30 seconds"
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    async def lateral_move(self, source_pivot_id: str, target_ip: str,
                           username: str, credential_type: str,
                           credential: str) -> Optional[PivotHost]:
        """Perform lateral movement to new host"""
        if source_pivot_id not in self.pivots:
            raise ValueError(f"Source pivot not found: {source_pivot_id}")
        
        # Add new pivot with source as parent
        new_pivot = await self.add_pivot(
            ip_address=target_ip,
            username=username,
            password=credential if credential_type == "password" else "",
            ssh_key=credential if credential_type == "key" else "",
            parent_pivot_id=source_pivot_id
        )
        
        # Try to connect
        try:
            success = await self.connect_pivot(new_pivot.host_id)
            if success:
                return new_pivot
        except Exception:
            # Clean up failed pivot
            del self.pivots[new_pivot.host_id]
        
        return None
    
    def get_pivot_chain_to_host(self, target_ip: str) -> List[str]:
        """Find optimal pivot chain to reach target host"""
        # BFS to find shortest path through pivots
        for pivot_id, pivot in self.pivots.items():
            if pivot.ip_address == target_ip:
                # Build chain from this pivot back to root
                chain = [pivot_id]
                current = pivot
                while current.parent_pivot:
                    chain.insert(0, current.parent_pivot)
                    current = self.pivots.get(current.parent_pivot)
                    if not current:
                        break
                return chain
        
        return []
    
    def get_network_topology(self) -> Dict:
        """Get network topology from discovered pivots"""
        nodes = []
        edges = []
        
        for pivot_id, pivot in self.pivots.items():
            nodes.append({
                'id': pivot_id,
                'ip': pivot.ip_address,
                'hostname': pivot.hostname,
                'status': pivot.status.value,
                'hop_count': pivot.hop_count,
                'networks': pivot.accessible_networks
            })
            
            if pivot.parent_pivot:
                edges.append({
                    'source': pivot.parent_pivot,
                    'target': pivot_id,
                    'type': pivot.tunnel_type.value
                })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'networks': self.network_map
        }
    
    def get_pivot_stats(self, pivot_id: str) -> Dict:
        """Get statistics for a pivot"""
        if pivot_id not in self.pivots:
            return {}
        
        pivot = self.pivots[pivot_id]
        tunnel = self.active_tunnels.get(pivot_id, {})
        
        return {
            'host_id': pivot_id,
            'ip_address': pivot.ip_address,
            'status': pivot.status.value,
            'tunnel_type': pivot.tunnel_type.value,
            'hop_count': pivot.hop_count,
            'local_port': pivot.local_port,
            'accessible_networks': pivot.accessible_networks,
            'discovered_hosts': len(pivot.discovered_hosts),
            'child_pivots': len(pivot.child_pivots),
            'latency_ms': pivot.latency_ms,
            'uptime': tunnel.get('started', '')
        }
    
    def disconnect_pivot(self, pivot_id: str) -> bool:
        """Disconnect a pivot point"""
        if pivot_id not in self.pivots:
            return False
        
        pivot = self.pivots[pivot_id]
        
        # Disconnect all child pivots first (recursively)
        for child_id in pivot.child_pivots.copy():
            self.disconnect_pivot(child_id)
        
        # Stop tunnel
        if pivot_id in self.active_tunnels:
            # Would terminate the process
            del self.active_tunnels[pivot_id]
        
        # Remove associated resources
        for proxy_id, proxy in list(self.socks_proxies.items()):
            if proxy.pivot_id == pivot_id:
                del self.socks_proxies[proxy_id]
        
        for forward_id, forward in list(self.port_forwards.items()):
            if forward.pivot_id == pivot_id:
                del self.port_forwards[forward_id]
        
        pivot.status = PivotStatus.INACTIVE
        
        return True
    
    def get_all_socks_proxies(self) -> List[Dict]:
        """Get all active SOCKS proxies"""
        return [
            {
                'proxy_id': p.proxy_id,
                'type': p.proxy_type,
                'address': f"{p.bind_address}:{p.bind_port}",
                'pivot': self.pivots[p.pivot_id].ip_address if p.pivot_id in self.pivots else '',
                'active': p.is_active
            }
            for p in self.socks_proxies.values()
        ]
    
    def get_all_port_forwards(self) -> List[Dict]:
        """Get all port forwards"""
        return [
            {
                'forward_id': f.forward_id,
                'direction': f.direction,
                'local': f"{f.local_host}:{f.local_port}",
                'remote': f"{f.remote_host}:{f.remote_port}",
                'pivot': self.pivots[f.pivot_id].ip_address if f.pivot_id in self.pivots else '',
                'active': f.is_active
            }
            for f in self.port_forwards.values()
        ]
    
    def generate_proxychains_config(self) -> str:
        """Generate proxychains configuration for the pivot chain"""
        config = """# ProxyChains configuration generated by HydraRecon
# This config routes traffic through the pivot chain

dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
"""
        
        # Add SOCKS proxies in order
        for proxy in sorted(self.socks_proxies.values(), 
                           key=lambda p: self.pivots.get(p.pivot_id, PivotHost("", "")).hop_count):
            if proxy.is_active:
                config += f"{proxy.proxy_type} {proxy.bind_address} {proxy.bind_port}\n"
        
        return config
    
    def generate_ssh_config(self) -> str:
        """Generate SSH config for pivot hosts"""
        config = "# SSH configuration generated by HydraRecon\n\n"
        
        for pivot_id, pivot in self.pivots.items():
            config += f"""Host pivot_{pivot_id}
    HostName {pivot.ip_address}
    User {pivot.username}
    Port {pivot.remote_port}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
"""
            
            if pivot.credentials.get('ssh_key'):
                config += f"    IdentityFile {pivot.credentials['ssh_key']}\n"
            
            if pivot.parent_pivot:
                parent = self.pivots.get(pivot.parent_pivot)
                if parent:
                    config += f"    ProxyJump pivot_{pivot.parent_pivot}\n"
            
            config += "\n"
        
        return config
