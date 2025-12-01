#!/usr/bin/env python3
"""
HydraRecon Attack Automation Engine
████████████████████████████████████████████████████████████████████████████████
█  AUTOMATED ATTACK WORKFLOWS - Chained Scans, Auto-Exploitation, Playbooks    █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum
import uuid


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class TaskType(Enum):
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CREDENTIAL_TEST = "credential_test"
    REPORT = "report"
    CUSTOM = "custom"
    WAIT = "wait"
    CONDITION = "condition"


@dataclass
class WorkflowTask:
    """Individual task in a workflow"""
    id: str
    name: str
    task_type: TaskType
    module: str
    options: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    conditions: List[Dict] = field(default_factory=list)
    on_success: List[str] = field(default_factory=list)
    on_failure: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class Workflow:
    """Automated attack workflow/playbook"""
    id: str
    name: str
    description: str = ""
    tasks: List[WorkflowTask] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: TaskStatus = TaskStatus.PENDING
    author: str = ""
    tags: List[str] = field(default_factory=list)


class AutomationEngine:
    """
    Advanced workflow automation engine
    Orchestrates complex multi-stage attacks
    """
    
    # Built-in workflow templates
    TEMPLATES = {
        "full_pentest": {
            "name": "Full Penetration Test",
            "description": "Complete automated penetration test workflow",
            "tasks": [
                {
                    "name": "Host Discovery",
                    "type": "scan",
                    "module": "nmap.host_discovery",
                    "options": {"args": "-sn"}
                },
                {
                    "name": "Port Scan",
                    "type": "scan",
                    "module": "nmap.full_scan",
                    "options": {"args": "-sS -sV -O -A"},
                    "dependencies": ["Host Discovery"]
                },
                {
                    "name": "Vulnerability Scan",
                    "type": "scan",
                    "module": "nmap.vuln_scan",
                    "options": {"args": "--script vuln"},
                    "dependencies": ["Port Scan"]
                },
                {
                    "name": "Web Application Scan",
                    "type": "scan",
                    "module": "web.nikto",
                    "conditions": [{"check": "port_open", "port": 80}],
                    "dependencies": ["Port Scan"]
                },
                {
                    "name": "Credential Attack",
                    "type": "exploit",
                    "module": "hydra.brute_force",
                    "conditions": [{"check": "service_found", "service": "ssh"}],
                    "dependencies": ["Port Scan"]
                },
                {
                    "name": "Generate Report",
                    "type": "report",
                    "module": "report.generate",
                    "dependencies": ["Vulnerability Scan", "Web Application Scan", "Credential Attack"]
                }
            ]
        },
        "quick_recon": {
            "name": "Quick Reconnaissance",
            "description": "Fast reconnaissance workflow",
            "tasks": [
                {
                    "name": "Fast Port Scan",
                    "type": "scan",
                    "module": "nmap.quick_scan",
                    "options": {"args": "-T4 -F"}
                },
                {
                    "name": "OSINT Lookup",
                    "type": "scan",
                    "module": "osint.domain_info"
                },
                {
                    "name": "Generate Summary",
                    "type": "report",
                    "module": "report.summary",
                    "dependencies": ["Fast Port Scan", "OSINT Lookup"]
                }
            ]
        },
        "credential_spray": {
            "name": "Credential Spray Attack",
            "description": "Multi-service credential testing",
            "tasks": [
                {
                    "name": "Service Discovery",
                    "type": "scan",
                    "module": "nmap.service_scan",
                    "options": {"args": "-sV -p 21,22,23,25,110,143,445,3389,5900"}
                },
                {
                    "name": "SSH Brute Force",
                    "type": "exploit",
                    "module": "hydra.ssh",
                    "conditions": [{"check": "port_open", "port": 22}],
                    "dependencies": ["Service Discovery"]
                },
                {
                    "name": "FTP Brute Force",
                    "type": "exploit",
                    "module": "hydra.ftp",
                    "conditions": [{"check": "port_open", "port": 21}],
                    "dependencies": ["Service Discovery"]
                },
                {
                    "name": "SMB Brute Force",
                    "type": "exploit",
                    "module": "hydra.smb",
                    "conditions": [{"check": "port_open", "port": 445}],
                    "dependencies": ["Service Discovery"]
                },
                {
                    "name": "RDP Brute Force",
                    "type": "exploit",
                    "module": "hydra.rdp",
                    "conditions": [{"check": "port_open", "port": 3389}],
                    "dependencies": ["Service Discovery"]
                }
            ]
        },
        "web_app_test": {
            "name": "Web Application Test",
            "description": "Comprehensive web application security test",
            "tasks": [
                {
                    "name": "Port Discovery",
                    "type": "scan",
                    "module": "nmap.web_ports",
                    "options": {"args": "-sV -p 80,443,8080,8443,8000,8888"}
                },
                {
                    "name": "Web Fingerprint",
                    "type": "scan",
                    "module": "web.fingerprint",
                    "dependencies": ["Port Discovery"]
                },
                {
                    "name": "Directory Brute Force",
                    "type": "scan",
                    "module": "web.dirb",
                    "dependencies": ["Web Fingerprint"]
                },
                {
                    "name": "SQL Injection Test",
                    "type": "scan",
                    "module": "web.sqli",
                    "dependencies": ["Directory Brute Force"]
                },
                {
                    "name": "XSS Test",
                    "type": "scan",
                    "module": "web.xss",
                    "dependencies": ["Directory Brute Force"]
                }
            ]
        },
        "internal_pentest": {
            "name": "Internal Network Penetration Test",
            "description": "Internal network assessment workflow",
            "tasks": [
                {
                    "name": "Network Discovery",
                    "type": "scan",
                    "module": "nmap.ping_sweep",
                    "options": {"args": "-sn"}
                },
                {
                    "name": "Full Port Scan",
                    "type": "scan",
                    "module": "nmap.full_ports",
                    "options": {"args": "-p- --min-rate 1000"},
                    "dependencies": ["Network Discovery"]
                },
                {
                    "name": "Service Enumeration",
                    "type": "scan",
                    "module": "nmap.service_enum",
                    "options": {"args": "-sV -sC"},
                    "dependencies": ["Full Port Scan"]
                },
                {
                    "name": "SMB Enumeration",
                    "type": "scan",
                    "module": "smb.enum",
                    "conditions": [{"check": "port_open", "port": 445}],
                    "dependencies": ["Service Enumeration"]
                },
                {
                    "name": "LDAP Enumeration",
                    "type": "scan",
                    "module": "ldap.enum",
                    "conditions": [{"check": "port_open", "port": 389}],
                    "dependencies": ["Service Enumeration"]
                },
                {
                    "name": "Credential Attack",
                    "type": "exploit",
                    "module": "hydra.multi",
                    "dependencies": ["Service Enumeration"]
                },
                {
                    "name": "Pass the Hash",
                    "type": "exploit",
                    "module": "pth.attack",
                    "conditions": [{"check": "credentials_found"}],
                    "dependencies": ["Credential Attack"]
                }
            ]
        }
    }
    
    def __init__(self, config=None):
        self.config = config
        self.active_workflows: Dict[str, Workflow] = {}
        self.completed_workflows: List[Workflow] = []
        self.task_handlers: Dict[str, Callable] = {}
        self.results_cache: Dict[str, Any] = {}
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default task handlers"""
        # These would be implemented to call actual scanner modules
        self.task_handlers = {
            "nmap.host_discovery": self._nmap_scan,
            "nmap.full_scan": self._nmap_scan,
            "nmap.quick_scan": self._nmap_scan,
            "nmap.vuln_scan": self._nmap_scan,
            "nmap.service_scan": self._nmap_scan,
            "nmap.web_ports": self._nmap_scan,
            "nmap.ping_sweep": self._nmap_scan,
            "nmap.full_ports": self._nmap_scan,
            "nmap.service_enum": self._nmap_scan,
            "hydra.brute_force": self._hydra_attack,
            "hydra.ssh": self._hydra_attack,
            "hydra.ftp": self._hydra_attack,
            "hydra.smb": self._hydra_attack,
            "hydra.rdp": self._hydra_attack,
            "hydra.multi": self._hydra_attack,
            "osint.domain_info": self._osint_scan,
            "web.nikto": self._web_scan,
            "web.fingerprint": self._web_scan,
            "web.dirb": self._web_scan,
            "web.sqli": self._web_scan,
            "web.xss": self._web_scan,
            "smb.enum": self._smb_enum,
            "ldap.enum": self._ldap_enum,
            "pth.attack": self._pth_attack,
            "report.generate": self._generate_report,
            "report.summary": self._generate_report,
        }
    
    async def _nmap_scan(self, task: WorkflowTask, context: Dict) -> Dict:
        """Execute nmap scan"""
        # This would integrate with the actual NmapScanner
        target = context.get("target", "")
        args = task.options.get("args", "-sV")
        
        # Placeholder - would call actual nmap scanner
        return {
            "scanner": "nmap",
            "target": target,
            "args": args,
            "status": "completed",
            "hosts_found": [],
            "ports_found": []
        }
    
    async def _hydra_attack(self, task: WorkflowTask, context: Dict) -> Dict:
        """Execute Hydra attack"""
        # This would integrate with the actual HydraScanner
        return {
            "scanner": "hydra",
            "status": "completed",
            "credentials_found": []
        }
    
    async def _osint_scan(self, task: WorkflowTask, context: Dict) -> Dict:
        """Execute OSINT scan"""
        return {
            "scanner": "osint",
            "status": "completed",
            "findings": []
        }
    
    async def _web_scan(self, task: WorkflowTask, context: Dict) -> Dict:
        """Execute web scan"""
        return {
            "scanner": "web",
            "status": "completed",
            "findings": []
        }
    
    async def _smb_enum(self, task: WorkflowTask, context: Dict) -> Dict:
        """Execute SMB enumeration"""
        return {
            "scanner": "smb",
            "status": "completed",
            "shares": [],
            "users": []
        }
    
    async def _ldap_enum(self, task: WorkflowTask, context: Dict) -> Dict:
        """Execute LDAP enumeration"""
        return {
            "scanner": "ldap",
            "status": "completed",
            "users": [],
            "groups": []
        }
    
    async def _pth_attack(self, task: WorkflowTask, context: Dict) -> Dict:
        """Execute Pass-the-Hash attack"""
        return {
            "attack": "pth",
            "status": "completed",
            "sessions": []
        }
    
    async def _generate_report(self, task: WorkflowTask, context: Dict) -> Dict:
        """Generate report"""
        return {
            "report": "generated",
            "format": "html",
            "path": ""
        }
    
    def create_workflow_from_template(self, template_name: str, 
                                     variables: Dict[str, Any] = None) -> Workflow:
        """Create a workflow from a template"""
        if template_name not in self.TEMPLATES:
            raise ValueError(f"Unknown template: {template_name}")
        
        template = self.TEMPLATES[template_name]
        
        tasks = []
        for i, task_def in enumerate(template.get("tasks", [])):
            task = WorkflowTask(
                id=str(uuid.uuid4()),
                name=task_def.get("name", f"Task {i+1}"),
                task_type=TaskType(task_def.get("type", "scan")),
                module=task_def.get("module", ""),
                options=task_def.get("options", {}),
                dependencies=task_def.get("dependencies", []),
                conditions=task_def.get("conditions", []),
                on_success=task_def.get("on_success", []),
                on_failure=task_def.get("on_failure", [])
            )
            tasks.append(task)
        
        workflow = Workflow(
            id=str(uuid.uuid4()),
            name=template.get("name", template_name),
            description=template.get("description", ""),
            tasks=tasks,
            variables=variables or {}
        )
        
        return workflow
    
    def create_custom_workflow(self, name: str, description: str = "",
                              tasks: List[Dict] = None) -> Workflow:
        """Create a custom workflow"""
        workflow_tasks = []
        
        for i, task_def in enumerate(tasks or []):
            task = WorkflowTask(
                id=str(uuid.uuid4()),
                name=task_def.get("name", f"Task {i+1}"),
                task_type=TaskType(task_def.get("type", "custom")),
                module=task_def.get("module", ""),
                options=task_def.get("options", {}),
                dependencies=task_def.get("dependencies", []),
                conditions=task_def.get("conditions", [])
            )
            workflow_tasks.append(task)
        
        return Workflow(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            tasks=workflow_tasks
        )
    
    def _check_conditions(self, task: WorkflowTask, context: Dict) -> bool:
        """Check if task conditions are met"""
        for condition in task.conditions:
            check_type = condition.get("check")
            
            if check_type == "port_open":
                port = condition.get("port")
                open_ports = context.get("open_ports", [])
                if port not in open_ports:
                    return False
            
            elif check_type == "service_found":
                service = condition.get("service")
                services = context.get("services", [])
                if service not in services:
                    return False
            
            elif check_type == "credentials_found":
                creds = context.get("credentials", [])
                if not creds:
                    return False
            
            elif check_type == "host_count_gt":
                count = condition.get("count", 0)
                hosts = context.get("hosts", [])
                if len(hosts) <= count:
                    return False
        
        return True
    
    def _check_dependencies(self, task: WorkflowTask, 
                           completed_tasks: Dict[str, TaskStatus]) -> bool:
        """Check if task dependencies are met"""
        for dep_name in task.dependencies:
            status = completed_tasks.get(dep_name)
            if status != TaskStatus.COMPLETED:
                return False
        return True
    
    async def execute_task(self, task: WorkflowTask, context: Dict) -> Tuple[bool, Any]:
        """Execute a single task"""
        handler = self.task_handlers.get(task.module)
        
        if not handler:
            return False, f"No handler for module: {task.module}"
        
        try:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            
            result = await handler(task, context)
            
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            task.result = result
            
            return True, result
            
        except Exception as e:
            task.error = str(e)
            task.retry_count += 1
            
            if task.retry_count < task.max_retries:
                # Retry
                return await self.execute_task(task, context)
            else:
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now()
                return False, str(e)
    
    async def execute_workflow(self, workflow: Workflow, 
                              initial_context: Dict = None,
                              progress_callback: Callable = None) -> Dict:
        """Execute a complete workflow"""
        workflow.status = TaskStatus.RUNNING
        workflow.started_at = datetime.now()
        
        self.active_workflows[workflow.id] = workflow
        
        context = initial_context or {}
        context["workflow_id"] = workflow.id
        
        completed_tasks: Dict[str, TaskStatus] = {}
        results: Dict[str, Any] = {}
        
        # Create task name to task mapping
        task_map = {task.name: task for task in workflow.tasks}
        
        # Track pending tasks
        pending = list(workflow.tasks)
        
        while pending:
            # Find tasks ready to run
            ready_tasks = []
            
            for task in pending:
                if self._check_dependencies(task, completed_tasks):
                    if self._check_conditions(task, context):
                        ready_tasks.append(task)
                    else:
                        # Conditions not met - skip
                        task.status = TaskStatus.SKIPPED
                        completed_tasks[task.name] = TaskStatus.SKIPPED
                        pending.remove(task)
            
            if not ready_tasks:
                if pending:
                    # Deadlock - remaining tasks have unmet dependencies
                    for task in pending:
                        task.status = TaskStatus.FAILED
                        task.error = "Unmet dependencies"
                        completed_tasks[task.name] = TaskStatus.FAILED
                break
            
            # Execute ready tasks in parallel
            tasks_to_run = [self.execute_task(task, context) for task in ready_tasks]
            task_results = await asyncio.gather(*tasks_to_run, return_exceptions=True)
            
            # Process results
            for task, (success, result) in zip(ready_tasks, task_results):
                if success:
                    completed_tasks[task.name] = TaskStatus.COMPLETED
                    results[task.name] = result
                    
                    # Update context with results
                    if isinstance(result, dict):
                        context.update(result)
                    
                    # Execute on_success tasks
                    for success_task_name in task.on_success:
                        if success_task_name in task_map:
                            pending.append(task_map[success_task_name])
                else:
                    completed_tasks[task.name] = TaskStatus.FAILED
                    results[task.name] = {"error": result}
                    
                    # Execute on_failure tasks
                    for failure_task_name in task.on_failure:
                        if failure_task_name in task_map:
                            pending.append(task_map[failure_task_name])
                
                pending.remove(task)
                
                # Progress callback
                if progress_callback:
                    progress = len(completed_tasks) / len(workflow.tasks) * 100
                    progress_callback(workflow.id, task.name, task.status, progress)
        
        # Workflow complete
        workflow.status = TaskStatus.COMPLETED
        workflow.completed_at = datetime.now()
        
        # Move to completed
        del self.active_workflows[workflow.id]
        self.completed_workflows.append(workflow)
        
        return {
            "workflow_id": workflow.id,
            "status": workflow.status.value,
            "duration": (workflow.completed_at - workflow.started_at).total_seconds(),
            "tasks_completed": sum(1 for s in completed_tasks.values() if s == TaskStatus.COMPLETED),
            "tasks_failed": sum(1 for s in completed_tasks.values() if s == TaskStatus.FAILED),
            "tasks_skipped": sum(1 for s in completed_tasks.values() if s == TaskStatus.SKIPPED),
            "results": results
        }
    
    def cancel_workflow(self, workflow_id: str):
        """Cancel a running workflow"""
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            workflow.status = TaskStatus.CANCELLED
            
            for task in workflow.tasks:
                if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]:
                    task.status = TaskStatus.CANCELLED
    
    def save_workflow(self, workflow: Workflow, filepath: str):
        """Save workflow to file"""
        data = {
            "id": workflow.id,
            "name": workflow.name,
            "description": workflow.description,
            "variables": workflow.variables,
            "author": workflow.author,
            "tags": workflow.tags,
            "tasks": [
                {
                    "name": task.name,
                    "type": task.task_type.value,
                    "module": task.module,
                    "options": task.options,
                    "dependencies": task.dependencies,
                    "conditions": task.conditions,
                    "on_success": task.on_success,
                    "on_failure": task.on_failure
                }
                for task in workflow.tasks
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_workflow(self, filepath: str) -> Workflow:
        """Load workflow from file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        tasks = []
        for task_def in data.get("tasks", []):
            task = WorkflowTask(
                id=str(uuid.uuid4()),
                name=task_def.get("name", ""),
                task_type=TaskType(task_def.get("type", "custom")),
                module=task_def.get("module", ""),
                options=task_def.get("options", {}),
                dependencies=task_def.get("dependencies", []),
                conditions=task_def.get("conditions", []),
                on_success=task_def.get("on_success", []),
                on_failure=task_def.get("on_failure", [])
            )
            tasks.append(task)
        
        return Workflow(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", "Loaded Workflow"),
            description=data.get("description", ""),
            tasks=tasks,
            variables=data.get("variables", {}),
            author=data.get("author", ""),
            tags=data.get("tags", [])
        )
    
    def get_available_templates(self) -> List[Dict]:
        """Get list of available workflow templates"""
        return [
            {
                "name": name,
                "display_name": template.get("name", name),
                "description": template.get("description", ""),
                "task_count": len(template.get("tasks", []))
            }
            for name, template in self.TEMPLATES.items()
        ]
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict]:
        """Get status of a workflow"""
        workflow = self.active_workflows.get(workflow_id)
        
        if not workflow:
            # Check completed
            for w in self.completed_workflows:
                if w.id == workflow_id:
                    workflow = w
                    break
        
        if not workflow:
            return None
        
        return {
            "id": workflow.id,
            "name": workflow.name,
            "status": workflow.status.value,
            "started_at": workflow.started_at.isoformat() if workflow.started_at else None,
            "completed_at": workflow.completed_at.isoformat() if workflow.completed_at else None,
            "tasks": [
                {
                    "name": task.name,
                    "status": task.status.value,
                    "module": task.module,
                    "error": task.error
                }
                for task in workflow.tasks
            ]
        }
