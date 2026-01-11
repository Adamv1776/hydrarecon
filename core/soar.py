
#!/usr/bin/env python3
"""
HydraRecon SOAR Module - Security Orchestration, Automation & Response
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE SOAR - Automated Security Operations, Workflow Orchestration,    █
█  Integration Hub, Case Management & Threat Response - NEXT-GEN SECURITY OPS  █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import json
import os
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, Awaitable
from enum import Enum
import hashlib


class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TriggerType(Enum):
    """Workflow trigger types"""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    ALERT = "alert"
    INCIDENT = "incident"
    API = "api"
    WEBHOOK = "webhook"
    FILE_CHANGE = "file_change"
    THRESHOLD = "threshold"


class ActionType(Enum):
    """SOAR action types"""
    # Investigation Actions
    ENRICH_IP = "enrich_ip"
    ENRICH_DOMAIN = "enrich_domain"
    ENRICH_HASH = "enrich_hash"
    ENRICH_URL = "enrich_url"
    LOOKUP_USER = "lookup_user"
    QUERY_SIEM = "query_siem"
    GET_HOST_INFO = "get_host_info"
    
    # OSINT Person/Address Search Actions
    ENRICH_PERSON = "enrich_person"
    SEARCH_ADDRESS = "search_address"
    SEARCH_PHONE = "search_phone"
    SEARCH_SOCIAL = "search_social"
    SEARCH_BREACH = "search_breach"
    OSINT_DEEP_SEARCH = "osint_deep_search"
    SEARCH_EMAIL = "search_email"
    SEARCH_USERNAME = "search_username"
    
    # Response Actions
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_HOST = "quarantine_host"
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    QUARANTINE_EMAIL = "quarantine_email"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    
    # Communication Actions
    SEND_EMAIL = "send_email"
    SEND_SLACK = "send_slack"
    CREATE_TICKET = "create_ticket"
    UPDATE_TICKET = "update_ticket"
    NOTIFY_TEAM = "notify_team"
    
    # Integration Actions
    RUN_SCRIPT = "run_script"
    HTTP_REQUEST = "http_request"
    EXECUTE_COMMAND = "execute_command"
    CALL_API = "call_api"
    
    # Case Management
    CREATE_CASE = "create_case"
    UPDATE_CASE = "update_case"
    ADD_EVIDENCE = "add_evidence"
    ESCALATE = "escalate"
    
    # Utilities
    WAIT = "wait"
    CONDITION = "condition"
    PARALLEL = "parallel"
    LOOP = "loop"
    SET_VARIABLE = "set_variable"
    CUSTOM = "custom"


class IntegrationType(Enum):
    """Integration types"""
    SIEM = "siem"
    EDR = "edr"
    FIREWALL = "firewall"
    EMAIL_GATEWAY = "email_gateway"
    IAM = "iam"
    TICKETING = "ticketing"
    THREAT_INTEL = "threat_intel"
    SANDBOX = "sandbox"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    CLOUD = "cloud"
    CUSTOM = "custom"


@dataclass
class Integration:
    """External integration configuration"""
    integration_id: str
    name: str
    integration_type: IntegrationType
    description: str
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    credentials: Dict[str, str] = field(default_factory=dict)
    is_enabled: bool = True
    last_tested: Optional[datetime] = None
    test_status: str = "untested"
    capabilities: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowAction:
    """Individual action in a workflow"""
    action_id: str
    name: str
    action_type: ActionType
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    retry_count: int = 0
    continue_on_failure: bool = False
    condition: Optional[str] = None  # Execute only if condition is met
    integration_id: Optional[str] = None
    outputs: Dict[str, str] = field(default_factory=dict)


@dataclass
class WorkflowTrigger:
    """Workflow trigger configuration"""
    trigger_id: str
    trigger_type: TriggerType
    name: str
    description: str
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    schedule: Optional[str] = None  # Cron expression for scheduled triggers
    is_enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """SOAR workflow definition"""
    workflow_id: str
    name: str
    description: str
    version: str
    triggers: List[WorkflowTrigger] = field(default_factory=list)
    actions: List[WorkflowAction] = field(default_factory=list)
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    author: str = "HydraRecon"
    is_enabled: bool = True
    tags: List[str] = field(default_factory=list)
    category: str = "general"


@dataclass
class WorkflowExecution:
    """Workflow execution instance"""
    execution_id: str
    workflow_id: str
    workflow_name: str
    status: WorkflowStatus
    trigger_type: TriggerType
    trigger_data: Dict[str, Any]
    started_at: datetime
    completed_at: Optional[datetime] = None
    current_action: Optional[str] = None
    actions_completed: List[Dict[str, Any]] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class Case:
    """SOAR case for investigation"""
    case_id: str
    title: str
    description: str
    status: str  # open, investigating, pending, resolved, closed
    priority: str  # critical, high, medium, low
    assignee: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    closed_at: Optional[datetime] = None
    source: str = "manual"  # manual, workflow, alert
    source_id: Optional[str] = None
    related_alerts: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


class ActionExecutor:
    """Execute SOAR actions"""
    
    def __init__(self, integrations: Dict[str, Integration] = None):
        self.logger = logging.getLogger("ActionExecutor")
        self.integrations = integrations or {}
        self.action_handlers: Dict[ActionType, Callable] = {}
        self._register_handlers()
    
    def _register_handlers(self):
        """Register action handlers"""
        self.action_handlers = {
            ActionType.ENRICH_IP: self._enrich_ip,
            ActionType.ENRICH_DOMAIN: self._enrich_domain,
            ActionType.ENRICH_HASH: self._enrich_hash,
            ActionType.BLOCK_IP: self._block_ip,
            ActionType.BLOCK_DOMAIN: self._block_domain,
            ActionType.QUARANTINE_HOST: self._quarantine_host,
            ActionType.DISABLE_USER: self._disable_user,
            ActionType.SEND_EMAIL: self._send_email,
            ActionType.SEND_SLACK: self._send_slack,
            ActionType.CREATE_TICKET: self._create_ticket,
            ActionType.RUN_SCRIPT: self._run_script,
            ActionType.HTTP_REQUEST: self._http_request,
            ActionType.WAIT: self._wait,
            ActionType.CONDITION: self._evaluate_condition,
            ActionType.SET_VARIABLE: self._set_variable,
            ActionType.CREATE_CASE: self._create_case,
            ActionType.NOTIFY_TEAM: self._notify_team,
            # OSINT Person/Address Search Actions
            ActionType.ENRICH_PERSON: self._enrich_person,
            ActionType.SEARCH_ADDRESS: self._search_address,
            ActionType.SEARCH_PHONE: self._search_phone,
            ActionType.SEARCH_SOCIAL: self._search_social,
            ActionType.SEARCH_BREACH: self._search_breach_data,
            ActionType.OSINT_DEEP_SEARCH: self._osint_deep_search,
            ActionType.SEARCH_EMAIL: self._search_email,
            ActionType.SEARCH_USERNAME: self._search_username,
        }
    
    async def execute(self, action: WorkflowAction, 
                     variables: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a workflow action"""
        self.logger.info(f"Executing action: {action.name} ({action.action_type.value})")
        
        # Substitute variables in parameters
        params = self._substitute_variables(action.parameters, variables)
        
        handler = self.action_handlers.get(action.action_type)
        if not handler:
            return {
                "success": False,
                "error": f"No handler for action type: {action.action_type.value}",
                "outputs": {}
            }
        
        try:
            result = await handler(params, variables)
            return {
                "success": True,
                "outputs": result,
                "action_id": action.action_id
            }
        except Exception as e:
            self.logger.error(f"Action {action.name} failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "outputs": {}
            }
    
    def _substitute_variables(self, params: Dict, variables: Dict) -> Dict:
        """Substitute variable placeholders in parameters"""
        result = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("{{") and value.endswith("}}"):
                var_name = value[2:-2].strip()
                result[key] = variables.get(var_name, value)
            elif isinstance(value, dict):
                result[key] = self._substitute_variables(value, variables)
            else:
                result[key] = value
        return result
    
    async def _enrich_ip(self, params: Dict, variables: Dict) -> Dict:
        """Enrich IP address with threat intelligence"""
        import aiohttp
        
        ip = params.get("ip")
        enrichment = {
            "ip": ip,
            "asn": "",
            "org": "",
            "country": "",
            "reputation_score": 0,
            "is_malicious": False,
            "categories": [],
            "first_seen": None,
            "last_seen": datetime.now().isoformat(),
            "related_domains": [],
            "source": "unknown"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try VirusTotal first (requires API key in env)
                vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
                if vt_key:
                    async with session.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": vt_key},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            attrs = data.get("data", {}).get("attributes", {})
                            enrichment["asn"] = str(attrs.get("asn", ""))
                            enrichment["org"] = attrs.get("as_owner", "")
                            enrichment["country"] = attrs.get("country", "")
                            stats = attrs.get("last_analysis_stats", {})
                            malicious = stats.get("malicious", 0)
                            enrichment["is_malicious"] = malicious > 3
                            enrichment["reputation_score"] = max(0, 100 - malicious * 5)
                            enrichment["source"] = "VirusTotal"
                            return {"enrichment": enrichment}
                
                # Try AbuseIPDB (requires API key in env)
                abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
                if abuse_key:
                    async with session.get(
                        f"https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": abuse_key, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            info = data.get("data", {})
                            enrichment["country"] = info.get("countryCode", "")
                            enrichment["org"] = info.get("isp", "")
                            abuse_score = info.get("abuseConfidenceScore", 0)
                            enrichment["is_malicious"] = abuse_score > 50
                            enrichment["reputation_score"] = 100 - abuse_score
                            enrichment["categories"] = [str(c) for c in info.get("usageType", "").split(",") if c]
                            enrichment["source"] = "AbuseIPDB"
                            return {"enrichment": enrichment}
                
                # Fallback to ip-api.com (free, no key required)
                async with session.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            enrichment["country"] = data.get("countryCode", "")
                            enrichment["org"] = data.get("org", data.get("isp", ""))
                            enrichment["asn"] = data.get("as", "").split()[0] if data.get("as") else ""
                            enrichment["source"] = "ip-api.com"
                            
        except Exception:
            pass
        
        return {"enrichment": enrichment}
    
    async def _enrich_domain(self, params: Dict, variables: Dict) -> Dict:
        """Enrich domain with threat intelligence"""
        import aiohttp
        
        domain = params.get("domain")
        enrichment = {
            "domain": domain,
            "registrar": "",
            "created": "",
            "expires": "",
            "reputation_score": 0,
            "is_malicious": False,
            "categories": [],
            "dns_records": {},
            "source": "unknown"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try VirusTotal first
                vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
                if vt_key:
                    async with session.get(
                        f"https://www.virustotal.com/api/v3/domains/{domain}",
                        headers={"x-apikey": vt_key},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            attrs = data.get("data", {}).get("attributes", {})
                            enrichment["registrar"] = attrs.get("registrar", "")
                            enrichment["created"] = attrs.get("creation_date", "")
                            stats = attrs.get("last_analysis_stats", {})
                            malicious = stats.get("malicious", 0)
                            enrichment["is_malicious"] = malicious > 3
                            enrichment["reputation_score"] = max(0, 100 - malicious * 5)
                            enrichment["categories"] = list(attrs.get("categories", {}).values())
                            enrichment["source"] = "VirusTotal"
                            return {"enrichment": enrichment}
                
                # Fallback: DNS resolution
                import socket
                try:
                    ips = socket.gethostbyname_ex(domain)[2]
                    enrichment["dns_records"]["A"] = ips
                except Exception:
                    pass
                
                # Try to get MX records
                import subprocess
                try:
                    result = subprocess.run(
                        ["dig", "+short", "MX", domain],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        mx_records = [line.split()[-1].rstrip('.') for line in result.stdout.strip().split('\n') if line]
                        if mx_records:
                            enrichment["dns_records"]["MX"] = mx_records
                except Exception:
                    pass
                
                enrichment["source"] = "DNS lookup"
                
        except Exception:
            pass
        
        return {"enrichment": enrichment}
    
    async def _enrich_hash(self, params: Dict, variables: Dict) -> Dict:
        """Enrich file hash with threat intelligence"""
        import aiohttp
        
        file_hash = params.get("hash")
        enrichment = {
            "hash": file_hash,
            "type": "sha256" if len(file_hash) == 64 else ("sha1" if len(file_hash) == 40 else "md5"),
            "file_name": "",
            "file_type": "",
            "file_size": 0,
            "is_malicious": False,
            "detection_ratio": "0/0",
            "first_seen": None,
            "last_seen": None,
            "tags": [],
            "source": "unknown"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try VirusTotal
                vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
                if vt_key:
                    async with session.get(
                        f"https://www.virustotal.com/api/v3/files/{file_hash}",
                        headers={"x-apikey": vt_key},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            attrs = data.get("data", {}).get("attributes", {})
                            
                            enrichment["file_name"] = attrs.get("meaningful_name", "")
                            enrichment["file_type"] = attrs.get("type_description", "")
                            enrichment["file_size"] = attrs.get("size", 0)
                            
                            stats = attrs.get("last_analysis_stats", {})
                            malicious = stats.get("malicious", 0)
                            total = sum(stats.values())
                            
                            enrichment["is_malicious"] = malicious > 5
                            enrichment["detection_ratio"] = f"{malicious}/{total}"
                            enrichment["tags"] = attrs.get("tags", [])
                            enrichment["first_seen"] = attrs.get("first_submission_date", "")
                            enrichment["last_seen"] = attrs.get("last_analysis_date", "")
                            enrichment["source"] = "VirusTotal"
                            
                            return {"enrichment": enrichment}
                
                # Try MalwareBazaar
                async with session.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_info", "hash": file_hash},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("query_status") == "ok":
                            info = data.get("data", [{}])[0]
                            enrichment["file_name"] = info.get("file_name", "")
                            enrichment["file_type"] = info.get("file_type_mime", "")
                            enrichment["file_size"] = info.get("file_size", 0)
                            enrichment["is_malicious"] = True
                            enrichment["tags"] = info.get("tags", [])
                            enrichment["first_seen"] = info.get("first_seen", "")
                            enrichment["source"] = "MalwareBazaar"
                            return {"enrichment": enrichment}
                            
        except Exception:
            pass
        
        return {"enrichment": enrichment}
    
    async def _enrich_person(self, params: Dict, variables: Dict) -> Dict:
        """Enrich person information using OSINT sources"""
        import aiohttp
        import urllib.parse
        
        name = params.get("name", "")
        email = params.get("email", "")
        phone = params.get("phone", "")
        location = params.get("location", "")
        
        enrichment = {
            "query": {"name": name, "email": email, "phone": phone, "location": location},
            "profiles": [],
            "emails": [],
            "phones": [],
            "addresses": [],
            "social_media": [],
            "associated_domains": [],
            "data_breaches": [],
            "professional_info": [],
            "sources": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Hunter.io for email discovery (if we have domain or name)
                hunter_key = os.environ.get("HUNTER_API_KEY", "")
                if hunter_key and email:
                    domain = email.split("@")[1] if "@" in email else ""
                    if domain:
                        async with session.get(
                            f"https://api.hunter.io/v2/email-verifier",
                            params={"email": email, "api_key": hunter_key},
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                result = data.get("data", {})
                                if result:
                                    enrichment["emails"].append({
                                        "email": email,
                                        "status": result.get("status", ""),
                                        "score": result.get("score", 0),
                                        "disposable": result.get("disposable", False),
                                        "webmail": result.get("webmail", False),
                                        "sources": result.get("sources", [])
                                    })
                                    enrichment["sources"].append("Hunter.io")
                
                # Have I Been Pwned for breach data
                hibp_key = os.environ.get("HIBP_API_KEY", "")
                if hibp_key and email:
                    async with session.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
                        headers={"hibp-api-key": hibp_key, "User-Agent": "HydraRecon-SOAR"},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            breaches = await resp.json()
                            for breach in breaches[:10]:  # Limit to 10
                                enrichment["data_breaches"].append({
                                    "name": breach.get("Name", ""),
                                    "domain": breach.get("Domain", ""),
                                    "breach_date": breach.get("BreachDate", ""),
                                    "data_classes": breach.get("DataClasses", [])
                                })
                            enrichment["sources"].append("HaveIBeenPwned")
                
                # Clearbit for professional info
                clearbit_key = os.environ.get("CLEARBIT_API_KEY", "")
                if clearbit_key and email:
                    async with session.get(
                        f"https://person.clearbit.com/v2/people/find",
                        params={"email": email},
                        headers={"Authorization": f"Bearer {clearbit_key}"},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data:
                                enrichment["professional_info"].append({
                                    "name": data.get("name", {}).get("fullName", ""),
                                    "title": data.get("employment", {}).get("title", ""),
                                    "company": data.get("employment", {}).get("name", ""),
                                    "location": data.get("location", ""),
                                    "linkedin": data.get("linkedin", {}).get("handle", ""),
                                    "twitter": data.get("twitter", {}).get("handle", ""),
                                    "github": data.get("github", {}).get("handle", ""),
                                    "bio": data.get("bio", "")
                                })
                                enrichment["sources"].append("Clearbit")
                
                # FullContact for contact enrichment
                fullcontact_key = os.environ.get("FULLCONTACT_API_KEY", "")
                if fullcontact_key and email:
                    async with session.post(
                        "https://api.fullcontact.com/v3/person.enrich",
                        json={"email": email},
                        headers={"Authorization": f"Bearer {fullcontact_key}"},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("fullName"):
                                enrichment["profiles"].append({
                                    "name": data.get("fullName", ""),
                                    "age_range": data.get("ageRange", ""),
                                    "gender": data.get("gender", ""),
                                    "location": data.get("location", ""),
                                    "title": data.get("title", ""),
                                    "organization": data.get("organization", "")
                                })
                            
                            for social in data.get("socialProfiles", []):
                                enrichment["social_media"].append({
                                    "network": social.get("type", ""),
                                    "url": social.get("url", ""),
                                    "username": social.get("username", "")
                                })
                            enrichment["sources"].append("FullContact")
                
                # NumVerify for phone validation
                numverify_key = os.environ.get("NUMVERIFY_API_KEY", "")
                if numverify_key and phone:
                    clean_phone = ''.join(c for c in phone if c.isdigit() or c == '+')
                    async with session.get(
                        f"http://apilayer.net/api/validate",
                        params={"access_key": numverify_key, "number": clean_phone},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("valid"):
                                enrichment["phones"].append({
                                    "number": clean_phone,
                                    "valid": data.get("valid", False),
                                    "local_format": data.get("local_format", ""),
                                    "international_format": data.get("international_format", ""),
                                    "country": data.get("country_name", ""),
                                    "carrier": data.get("carrier", ""),
                                    "line_type": data.get("line_type", "")
                                })
                                enrichment["sources"].append("NumVerify")
                
                # GitHub user search (free, no key required)
                if name:
                    search_name = urllib.parse.quote(name)
                    async with session.get(
                        f"https://api.github.com/search/users?q={search_name}",
                        headers={"Accept": "application/vnd.github.v3+json"},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for user in data.get("items", [])[:5]:
                                enrichment["social_media"].append({
                                    "network": "github",
                                    "url": user.get("html_url", ""),
                                    "username": user.get("login", ""),
                                    "avatar": user.get("avatar_url", "")
                                })
                            if data.get("items"):
                                enrichment["sources"].append("GitHub")
                
        except Exception as e:
            enrichment["error"] = str(e)
        
        return {"enrichment": enrichment}
    
    async def _enrich_address(self, params: Dict, variables: Dict) -> Dict:
        """Enrich address information using geolocation and property data sources"""
        import aiohttp
        import urllib.parse
        
        address = params.get("address", "")
        city = params.get("city", "")
        state = params.get("state", "")
        country = params.get("country", "US")
        postal_code = params.get("postal_code", "")
        
        full_address = f"{address}, {city}, {state} {postal_code}, {country}".strip(", ")
        
        enrichment = {
            "query": full_address,
            "normalized_address": {},
            "coordinates": {},
            "property_info": {},
            "nearby_businesses": [],
            "demographics": {},
            "risk_indicators": [],
            "timezone": "",
            "sources": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # OpenStreetMap Nominatim (free, no key required)
                encoded_address = urllib.parse.quote(full_address)
                async with session.get(
                    f"https://nominatim.openstreetmap.org/search",
                    params={
                        "q": full_address,
                        "format": "json",
                        "addressdetails": 1,
                        "limit": 1
                    },
                    headers={"User-Agent": "HydraRecon-SOAR/1.0"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data:
                            result = data[0]
                            enrichment["coordinates"] = {
                                "latitude": float(result.get("lat", 0)),
                                "longitude": float(result.get("lon", 0)),
                                "accuracy": result.get("importance", 0)
                            }
                            
                            addr = result.get("address", {})
                            enrichment["normalized_address"] = {
                                "house_number": addr.get("house_number", ""),
                                "road": addr.get("road", ""),
                                "suburb": addr.get("suburb", ""),
                                "city": addr.get("city") or addr.get("town") or addr.get("village", ""),
                                "county": addr.get("county", ""),
                                "state": addr.get("state", ""),
                                "postcode": addr.get("postcode", ""),
                                "country": addr.get("country", ""),
                                "country_code": addr.get("country_code", "").upper()
                            }
                            enrichment["sources"].append("OpenStreetMap")
                
                # Google Maps Geocoding (if API key available)
                google_key = os.environ.get("GOOGLE_MAPS_API_KEY", "")
                if google_key:
                    async with session.get(
                        "https://maps.googleapis.com/maps/api/geocode/json",
                        params={"address": full_address, "key": google_key},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("results"):
                                result = data["results"][0]
                                geo = result.get("geometry", {}).get("location", {})
                                enrichment["coordinates"] = {
                                    "latitude": geo.get("lat", 0),
                                    "longitude": geo.get("lng", 0),
                                    "location_type": result.get("geometry", {}).get("location_type", "")
                                }
                                
                                # Parse address components
                                for component in result.get("address_components", []):
                                    types = component.get("types", [])
                                    if "street_number" in types:
                                        enrichment["normalized_address"]["house_number"] = component["long_name"]
                                    elif "route" in types:
                                        enrichment["normalized_address"]["road"] = component["long_name"]
                                    elif "locality" in types:
                                        enrichment["normalized_address"]["city"] = component["long_name"]
                                    elif "administrative_area_level_1" in types:
                                        enrichment["normalized_address"]["state"] = component["short_name"]
                                    elif "postal_code" in types:
                                        enrichment["normalized_address"]["postcode"] = component["long_name"]
                                
                                enrichment["sources"].append("Google Maps")
                                
                                # Get nearby places if we have coordinates
                                lat = geo.get("lat")
                                lng = geo.get("lng")
                                if lat and lng:
                                    async with session.get(
                                        "https://maps.googleapis.com/maps/api/place/nearbysearch/json",
                                        params={
                                            "location": f"{lat},{lng}",
                                            "radius": 500,
                                            "key": google_key
                                        },
                                        timeout=aiohttp.ClientTimeout(total=10)
                                    ) as places_resp:
                                        if places_resp.status == 200:
                                            places_data = await places_resp.json()
                                            for place in places_data.get("results", [])[:10]:
                                                enrichment["nearby_businesses"].append({
                                                    "name": place.get("name", ""),
                                                    "type": place.get("types", [None])[0],
                                                    "address": place.get("vicinity", ""),
                                                    "rating": place.get("rating", 0)
                                                })
                
                # IP Geolocation for timezone (using coordinates)
                if enrichment["coordinates"].get("latitude"):
                    lat = enrichment["coordinates"]["latitude"]
                    lng = enrichment["coordinates"]["longitude"]
                    
                    # TimeZoneDB (free tier available)
                    tz_key = os.environ.get("TIMEZONEDB_API_KEY", "")
                    if tz_key:
                        async with session.get(
                            "http://api.timezonedb.com/v2.1/get-time-zone",
                            params={
                                "key": tz_key,
                                "format": "json",
                                "by": "position",
                                "lat": lat,
                                "lng": lng
                            },
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                if data.get("status") == "OK":
                                    enrichment["timezone"] = data.get("zoneName", "")
                                    enrichment["sources"].append("TimeZoneDB")
                
                # Risk assessment based on location
                if enrichment["normalized_address"].get("country_code"):
                    # Check high-risk countries
                    high_risk_countries = {"RU", "CN", "KP", "IR", "SY", "CU", "VE"}
                    medium_risk_countries = {"NG", "PK", "UA", "BY", "IN", "BR", "RO"}
                    
                    cc = enrichment["normalized_address"]["country_code"]
                    if cc in high_risk_countries:
                        enrichment["risk_indicators"].append({
                            "type": "high_risk_country",
                            "severity": "high",
                            "description": f"Address located in high-risk jurisdiction: {cc}"
                        })
                    elif cc in medium_risk_countries:
                        enrichment["risk_indicators"].append({
                            "type": "elevated_risk_country",
                            "severity": "medium",
                            "description": f"Address located in elevated-risk jurisdiction: {cc}"
                        })
                
        except Exception as e:
            enrichment["error"] = str(e)
        
        return {"enrichment": enrichment}
    
    async def _search_person(self, params: Dict, variables: Dict) -> Dict:
        """Comprehensive person search across multiple OSINT sources"""
        import aiohttp
        import urllib.parse
        
        first_name = params.get("first_name", "")
        last_name = params.get("last_name", "")
        full_name = params.get("name", "") or f"{first_name} {last_name}".strip()
        email = params.get("email", "")
        phone = params.get("phone", "")
        city = params.get("city", "")
        state = params.get("state", "")
        age = params.get("age", "")
        
        results = {
            "query": {
                "name": full_name,
                "email": email,
                "phone": phone,
                "location": f"{city}, {state}".strip(", ")
            },
            "matches": [],
            "emails_found": [],
            "phones_found": [],
            "addresses_found": [],
            "social_profiles": [],
            "relatives": [],
            "employment_history": [],
            "education": [],
            "sources": [],
            "confidence_score": 0
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Pipl API (commercial people search)
                pipl_key = os.environ.get("PIPL_API_KEY", "")
                if pipl_key and (full_name or email or phone):
                    search_params = {"key": pipl_key}
                    if full_name:
                        parts = full_name.split()
                        if len(parts) >= 2:
                            search_params["first_name"] = parts[0]
                            search_params["last_name"] = parts[-1]
                    if email:
                        search_params["email"] = email
                    if phone:
                        search_params["phone"] = phone
                    if city:
                        search_params["city"] = city
                    if state:
                        search_params["state"] = state
                    
                    async with session.get(
                        "https://api.pipl.com/search/",
                        params=search_params,
                        timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            
                            for person in data.get("possible_persons", [])[:5]:
                                match = {
                                    "name": "",
                                    "age": "",
                                    "location": "",
                                    "match_score": person.get("@match", 0)
                                }
                                
                                names = person.get("names", [])
                                if names:
                                    match["name"] = names[0].get("display", "")
                                
                                dob = person.get("dob", {})
                                if dob:
                                    match["age"] = dob.get("display", "")
                                
                                addresses = person.get("addresses", [])
                                if addresses:
                                    match["location"] = addresses[0].get("display", "")
                                    for addr in addresses[:3]:
                                        results["addresses_found"].append({
                                            "address": addr.get("display", ""),
                                            "type": addr.get("@type", ""),
                                            "current": addr.get("@current", False)
                                        })
                                
                                for em in person.get("emails", []):
                                    results["emails_found"].append({
                                        "email": em.get("address", ""),
                                        "type": em.get("@type", "")
                                    })
                                
                                for ph in person.get("phones", []):
                                    results["phones_found"].append({
                                        "phone": ph.get("display", ""),
                                        "type": ph.get("@type", "")
                                    })
                                
                                for job in person.get("jobs", []):
                                    results["employment_history"].append({
                                        "title": job.get("title", ""),
                                        "organization": job.get("organization", ""),
                                        "industry": job.get("industry", "")
                                    })
                                
                                for edu in person.get("educations", []):
                                    results["education"].append({
                                        "school": edu.get("school", ""),
                                        "degree": edu.get("degree", "")
                                    })
                                
                                for rel in person.get("relationships", []):
                                    if rel.get("names"):
                                        results["relatives"].append({
                                            "name": rel["names"][0].get("display", ""),
                                            "relationship": rel.get("@type", "")
                                        })
                                
                                for social in person.get("urls", []):
                                    if social.get("@category") == "social":
                                        results["social_profiles"].append({
                                            "url": social.get("url", ""),
                                            "domain": social.get("@domain", "")
                                        })
                                
                                results["matches"].append(match)
                            
                            results["confidence_score"] = data.get("@search_id", 0)
                            results["sources"].append("Pipl")
                
                # BeenVerified style search using public records
                whitepages_key = os.environ.get("WHITEPAGES_API_KEY", "")
                if whitepages_key and full_name:
                    async with session.get(
                        "https://proapi.whitepages.com/3.0/person",
                        params={
                            "api_key": whitepages_key,
                            "name": full_name,
                            "city": city,
                            "state_code": state
                        },
                        timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for person in data.get("results", [])[:5]:
                                results["matches"].append({
                                    "name": person.get("name", ""),
                                    "age": person.get("age_range", ""),
                                    "location": person.get("current_address", {}).get("city", "")
                                })
                            results["sources"].append("Whitepages")
                
                # LinkedIn profile search (using Google Custom Search API)
                google_cse_key = os.environ.get("GOOGLE_CSE_API_KEY", "")
                google_cse_cx = os.environ.get("GOOGLE_CSE_CX", "")
                if google_cse_key and google_cse_cx and full_name:
                    search_query = f"site:linkedin.com/in {full_name}"
                    if city:
                        search_query += f" {city}"
                    
                    async with session.get(
                        "https://www.googleapis.com/customsearch/v1",
                        params={
                            "key": google_cse_key,
                            "cx": google_cse_cx,
                            "q": search_query,
                            "num": 5
                        },
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data.get("items", []):
                                results["social_profiles"].append({
                                    "url": item.get("link", ""),
                                    "title": item.get("title", ""),
                                    "snippet": item.get("snippet", ""),
                                    "domain": "linkedin.com"
                                })
                            results["sources"].append("Google CSE")
                
                # Free email search using DNS MX records
                if email and "@" in email:
                    domain = email.split("@")[1]
                    import subprocess
                    try:
                        result = subprocess.run(
                            ["dig", "+short", "MX", domain],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            results["emails_found"].append({
                                "email": email,
                                "domain_valid": True,
                                "mx_records": result.stdout.strip().split('\n')[:3]
                            })
                    except Exception:
                        pass
                
        except Exception as e:
            results["error"] = str(e)
        
        return {"results": results}
    
    async def _reverse_phone_lookup(self, params: Dict, variables: Dict) -> Dict:
        """Reverse phone number lookup"""
        import aiohttp
        
        phone = params.get("phone", "")
        # Clean phone number
        clean_phone = ''.join(c for c in phone if c.isdigit())
        
        results = {
            "phone": phone,
            "formatted_phone": "",
            "carrier": "",
            "line_type": "",
            "location": {},
            "owner": {},
            "spam_score": 0,
            "sources": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # NumVerify for phone validation
                numverify_key = os.environ.get("NUMVERIFY_API_KEY", "")
                if numverify_key:
                    async with session.get(
                        "http://apilayer.net/api/validate",
                        params={"access_key": numverify_key, "number": clean_phone},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("valid"):
                                results["formatted_phone"] = data.get("international_format", "")
                                results["carrier"] = data.get("carrier", "")
                                results["line_type"] = data.get("line_type", "")
                                results["location"] = {
                                    "country": data.get("country_name", ""),
                                    "country_code": data.get("country_code", ""),
                                    "location": data.get("location", "")
                                }
                                results["sources"].append("NumVerify")
                
                # Twilio Lookup for additional info
                twilio_sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
                twilio_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
                if twilio_sid and twilio_token:
                    import base64
                    auth = base64.b64encode(f"{twilio_sid}:{twilio_token}".encode()).decode()
                    
                    async with session.get(
                        f"https://lookups.twilio.com/v1/PhoneNumbers/{clean_phone}",
                        params={"Type": "carrier,caller-name"},
                        headers={"Authorization": f"Basic {auth}"},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            carrier = data.get("carrier", {})
                            results["carrier"] = carrier.get("name", results["carrier"])
                            results["line_type"] = carrier.get("type", results["line_type"])
                            
                            caller_name = data.get("caller_name", {})
                            if caller_name:
                                results["owner"] = {
                                    "name": caller_name.get("caller_name", ""),
                                    "type": caller_name.get("caller_type", "")
                                }
                            results["sources"].append("Twilio")
                
        except Exception as e:
            results["error"] = str(e)
        
        return {"results": results}
    
    async def _reverse_address_lookup(self, params: Dict, variables: Dict) -> Dict:
        """Reverse address lookup for resident information"""
        import aiohttp
        
        address = params.get("address", "")
        city = params.get("city", "")
        state = params.get("state", "")
        postal_code = params.get("postal_code", "")
        
        full_address = f"{address}, {city}, {state} {postal_code}".strip(", ")
        
        results = {
            "address": full_address,
            "residents": [],
            "property_info": {},
            "neighbors": [],
            "sources": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Whitepages reverse address
                whitepages_key = os.environ.get("WHITEPAGES_API_KEY", "")
                if whitepages_key:
                    async with session.get(
                        "https://proapi.whitepages.com/3.0/location",
                        params={
                            "api_key": whitepages_key,
                            "street_line_1": address,
                            "city": city,
                            "state_code": state,
                            "postal_code": postal_code
                        },
                        timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            
                            # Get residents
                            for person in data.get("current_residents", [])[:10]:
                                results["residents"].append({
                                    "name": person.get("name", ""),
                                    "age_range": person.get("age_range", ""),
                                    "phones": [p.get("phone_number") for p in person.get("phones", [])[:2]]
                                })
                            
                            # Property info
                            prop = data.get("property", {})
                            if prop:
                                results["property_info"] = {
                                    "type": prop.get("property_type", ""),
                                    "year_built": prop.get("year_built", ""),
                                    "bedrooms": prop.get("bedrooms", ""),
                                    "bathrooms": prop.get("bathrooms", ""),
                                    "sqft": prop.get("square_feet", ""),
                                    "lot_size": prop.get("lot_size", ""),
                                    "owner_occupied": prop.get("is_owner_occupied", False)
                                }
                            
                            results["sources"].append("Whitepages")
                
        except Exception as e:
            results["error"] = str(e)
        
        return {"results": results}

    async def _search_address(self, params: Dict, variables: Dict) -> Dict:
        """Search for address information - wrapper for address enrichment"""
        return await self._enrich_address(params, variables)
    
    async def _search_phone(self, params: Dict, variables: Dict) -> Dict:
        """Search for phone information - wrapper for reverse phone lookup"""
        return await self._reverse_phone_lookup(params, variables)
    
    async def _search_social(self, params: Dict, variables: Dict) -> Dict:
        """Search for social media profiles"""
        import aiohttp
        import urllib.parse
        
        username = params.get("username", "")
        name = params.get("name", "")
        email = params.get("email", "")
        
        results = {
            "query": {"username": username, "name": name, "email": email},
            "profiles": [],
            "sources": []
        }
        
        platforms = [
            {"name": "Twitter", "url": f"https://twitter.com/{username}", "check_url": f"https://twitter.com/{username}"},
            {"name": "Instagram", "url": f"https://instagram.com/{username}", "check_url": f"https://instagram.com/{username}"},
            {"name": "LinkedIn", "url": f"https://linkedin.com/in/{username}", "check_url": f"https://linkedin.com/in/{username}"},
            {"name": "GitHub", "url": f"https://github.com/{username}", "check_url": f"https://api.github.com/users/{username}"},
            {"name": "Reddit", "url": f"https://reddit.com/user/{username}", "check_url": f"https://www.reddit.com/user/{username}/about.json"},
            {"name": "TikTok", "url": f"https://tiktok.com/@{username}", "check_url": f"https://tiktok.com/@{username}"},
            {"name": "Facebook", "url": f"https://facebook.com/{username}", "check_url": f"https://facebook.com/{username}"},
            {"name": "Pinterest", "url": f"https://pinterest.com/{username}", "check_url": f"https://pinterest.com/{username}"},
            {"name": "Medium", "url": f"https://medium.com/@{username}", "check_url": f"https://medium.com/@{username}"},
            {"name": "Twitch", "url": f"https://twitch.tv/{username}", "check_url": f"https://twitch.tv/{username}"},
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                if username:
                    # Check GitHub (reliable API)
                    async with session.get(
                        f"https://api.github.com/users/{username}",
                        headers={"Accept": "application/vnd.github.v3+json"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            results["profiles"].append({
                                "platform": "GitHub",
                                "url": data.get("html_url", ""),
                                "username": data.get("login", ""),
                                "name": data.get("name", ""),
                                "bio": data.get("bio", ""),
                                "followers": data.get("followers", 0),
                                "public_repos": data.get("public_repos", 0),
                                "avatar": data.get("avatar_url", ""),
                                "verified": True
                            })
                            results["sources"].append("GitHub API")
                    
                    # Check Reddit
                    async with session.get(
                        f"https://www.reddit.com/user/{username}/about.json",
                        headers={"User-Agent": "HydraRecon/1.0"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            user_data = data.get("data", {})
                            if user_data.get("name"):
                                results["profiles"].append({
                                    "platform": "Reddit",
                                    "url": f"https://reddit.com/user/{username}",
                                    "username": user_data.get("name", ""),
                                    "karma": user_data.get("total_karma", 0),
                                    "created": user_data.get("created_utc", 0),
                                    "verified": True
                                })
                                results["sources"].append("Reddit API")
                    
                    # Add other platforms as potential matches (need manual verification)
                    for platform in ["Twitter", "Instagram", "LinkedIn", "TikTok", "Facebook"]:
                        results["profiles"].append({
                            "platform": platform,
                            "url": next((p["url"] for p in platforms if p["name"] == platform), ""),
                            "username": username,
                            "verified": False,
                            "note": "Needs manual verification"
                        })
                
        except Exception as e:
            results["error"] = str(e)
        
        return {"results": results}
    
    async def _search_breach_data(self, params: Dict, variables: Dict) -> Dict:
        """Search for data breaches associated with an email"""
        import aiohttp
        import urllib.parse
        
        email = params.get("email", "")
        domain = params.get("domain", "")
        
        results = {
            "query": {"email": email, "domain": domain},
            "breaches": [],
            "pastes": [],
            "total_breaches": 0,
            "earliest_breach": "",
            "latest_breach": "",
            "data_classes_exposed": [],
            "sources": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                hibp_key = os.environ.get("HIBP_API_KEY", "")
                
                if hibp_key and email:
                    # Check breached accounts
                    async with session.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
                        headers={
                            "hibp-api-key": hibp_key,
                            "User-Agent": "HydraRecon-SOAR"
                        },
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            breaches = await resp.json()
                            results["total_breaches"] = len(breaches)
                            
                            all_data_classes = set()
                            breach_dates = []
                            
                            for breach in breaches:
                                results["breaches"].append({
                                    "name": breach.get("Name", ""),
                                    "title": breach.get("Title", ""),
                                    "domain": breach.get("Domain", ""),
                                    "breach_date": breach.get("BreachDate", ""),
                                    "added_date": breach.get("AddedDate", ""),
                                    "pwn_count": breach.get("PwnCount", 0),
                                    "description": breach.get("Description", "")[:200],
                                    "data_classes": breach.get("DataClasses", []),
                                    "is_verified": breach.get("IsVerified", False),
                                    "is_sensitive": breach.get("IsSensitive", False)
                                })
                                
                                all_data_classes.update(breach.get("DataClasses", []))
                                if breach.get("BreachDate"):
                                    breach_dates.append(breach["BreachDate"])
                            
                            results["data_classes_exposed"] = list(all_data_classes)
                            if breach_dates:
                                results["earliest_breach"] = min(breach_dates)
                                results["latest_breach"] = max(breach_dates)
                            
                            results["sources"].append("HaveIBeenPwned")
                    
                    # Check paste appearances
                    async with session.get(
                        f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(email)}",
                        headers={
                            "hibp-api-key": hibp_key,
                            "User-Agent": "HydraRecon-SOAR"
                        },
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            pastes = await resp.json()
                            for paste in pastes[:20]:
                                results["pastes"].append({
                                    "source": paste.get("Source", ""),
                                    "id": paste.get("Id", ""),
                                    "title": paste.get("Title", ""),
                                    "date": paste.get("Date", ""),
                                    "email_count": paste.get("EmailCount", 0)
                                })
                
                elif not hibp_key:
                    results["error"] = "HIBP_API_KEY not configured"
                
        except Exception as e:
            results["error"] = str(e)
        
        return {"results": results}
    
    async def _search_email(self, params: Dict, variables: Dict) -> Dict:
        """Search for information about an email address"""
        import aiohttp
        
        email = params.get("email", "")
        
        results = {
            "email": email,
            "valid": False,
            "deliverable": False,
            "disposable": False,
            "free_provider": False,
            "domain_info": {},
            "person_info": {},
            "breaches": [],
            "sources": []
        }
        
        if not email or "@" not in email:
            results["error"] = "Invalid email format"
            return {"results": results}
        
        domain = email.split("@")[1]
        
        try:
            async with aiohttp.ClientSession() as session:
                # Hunter.io email verification
                hunter_key = os.environ.get("HUNTER_API_KEY", "")
                if hunter_key:
                    async with session.get(
                        "https://api.hunter.io/v2/email-verifier",
                        params={"email": email, "api_key": hunter_key},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            result = data.get("data", {})
                            results["valid"] = result.get("status") == "valid"
                            results["deliverable"] = result.get("result") == "deliverable"
                            results["disposable"] = result.get("disposable", False)
                            results["free_provider"] = result.get("webmail", False)
                            results["domain_info"] = {
                                "accept_all": result.get("accept_all", False),
                                "pattern": result.get("pattern", ""),
                                "organization": result.get("organization", "")
                            }
                            results["sources"].append("Hunter.io")
                
                # Check MX records
                import subprocess
                try:
                    mx_result = subprocess.run(
                        ["dig", "+short", "MX", domain],
                        capture_output=True, text=True, timeout=5
                    )
                    if mx_result.returncode == 0 and mx_result.stdout.strip():
                        results["domain_info"]["mx_records"] = mx_result.stdout.strip().split('\n')[:5]
                        results["domain_info"]["has_mx"] = True
                except Exception:
                    pass
                
                # Get person info if Clearbit available
                clearbit_key = os.environ.get("CLEARBIT_API_KEY", "")
                if clearbit_key:
                    async with session.get(
                        "https://person.clearbit.com/v2/people/find",
                        params={"email": email},
                        headers={"Authorization": f"Bearer {clearbit_key}"},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            results["person_info"] = {
                                "name": data.get("name", {}).get("fullName", ""),
                                "title": data.get("employment", {}).get("title", ""),
                                "company": data.get("employment", {}).get("name", ""),
                                "location": data.get("location", ""),
                                "bio": data.get("bio", "")
                            }
                            results["sources"].append("Clearbit")
                
                # Check breaches
                breach_results = await self._search_breach_data({"email": email}, variables)
                if breach_results.get("results", {}).get("breaches"):
                    results["breaches"] = breach_results["results"]["breaches"][:5]
                    results["sources"].append("HaveIBeenPwned")
                
        except Exception as e:
            results["error"] = str(e)
        
        return {"results": results}
    
    async def _search_username(self, params: Dict, variables: Dict) -> Dict:
        """Search for username across platforms"""
        return await self._search_social(params, variables)
    
    async def _osint_deep_search(self, params: Dict, variables: Dict) -> Dict:
        """Comprehensive OSINT search combining all available sources"""
        import asyncio
        
        name = params.get("name", "")
        email = params.get("email", "")
        phone = params.get("phone", "")
        username = params.get("username", "")
        address = params.get("address", "")
        
        results = {
            "query": {
                "name": name,
                "email": email,
                "phone": phone,
                "username": username,
                "address": address
            },
            "person_data": {},
            "email_data": {},
            "phone_data": {},
            "social_data": {},
            "address_data": {},
            "breach_data": {},
            "summary": {
                "total_sources": 0,
                "risk_score": 0,
                "confidence": 0,
                "exposure_level": "unknown"
            }
        }
        
        try:
            # Run all searches in parallel
            tasks = []
            
            if name or email:
                tasks.append(("person", self._enrich_person({
                    "name": name, "email": email, "phone": phone
                }, variables)))
            
            if email:
                tasks.append(("email", self._search_email({"email": email}, variables)))
                tasks.append(("breach", self._search_breach_data({"email": email}, variables)))
            
            if phone:
                tasks.append(("phone", self._search_phone({"phone": phone}, variables)))
            
            if username:
                tasks.append(("social", self._search_social({"username": username}, variables)))
            
            if address:
                tasks.append(("address", self._search_address({"address": address}, variables)))
            
            # Execute all tasks
            if tasks:
                task_results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
                
                sources_found = set()
                for (task_name, _), result in zip(tasks, task_results):
                    if isinstance(result, Exception):
                        continue
                    
                    if task_name == "person":
                        results["person_data"] = result.get("enrichment", {})
                        sources_found.update(result.get("enrichment", {}).get("sources", []))
                    elif task_name == "email":
                        results["email_data"] = result.get("results", {})
                        sources_found.update(result.get("results", {}).get("sources", []))
                    elif task_name == "phone":
                        results["phone_data"] = result.get("results", {})
                        sources_found.update(result.get("results", {}).get("sources", []))
                    elif task_name == "social":
                        results["social_data"] = result.get("results", {})
                        sources_found.update(result.get("results", {}).get("sources", []))
                    elif task_name == "address":
                        results["address_data"] = result.get("enrichment", {})
                        sources_found.update(result.get("enrichment", {}).get("sources", []))
                    elif task_name == "breach":
                        results["breach_data"] = result.get("results", {})
                        sources_found.update(result.get("results", {}).get("sources", []))
                
                results["summary"]["total_sources"] = len(sources_found)
                
                # Calculate risk/exposure score
                breach_count = len(results.get("breach_data", {}).get("breaches", []))
                social_count = len([p for p in results.get("social_data", {}).get("profiles", []) if p.get("verified")])
                
                if breach_count > 5:
                    results["summary"]["exposure_level"] = "critical"
                    results["summary"]["risk_score"] = 90
                elif breach_count > 2:
                    results["summary"]["exposure_level"] = "high"
                    results["summary"]["risk_score"] = 70
                elif breach_count > 0:
                    results["summary"]["exposure_level"] = "moderate"
                    results["summary"]["risk_score"] = 50
                else:
                    results["summary"]["exposure_level"] = "low"
                    results["summary"]["risk_score"] = 20
                
                # Confidence based on data found
                data_points = sum([
                    1 if results["person_data"] else 0,
                    1 if results["email_data"].get("valid") else 0,
                    1 if results["phone_data"].get("formatted_phone") else 0,
                    social_count,
                    1 if results["address_data"].get("coordinates") else 0
                ])
                results["summary"]["confidence"] = min(100, data_points * 15)
                
        except Exception as e:
            results["error"] = str(e)
        
        return {"results": results}

    async def _block_ip(self, params: Dict, variables: Dict) -> Dict:
        """Block IP address on firewall"""
        ip = params.get("ip")
        duration = params.get("duration", "24h")
        
        # Would integrate with firewall API
        return {
            "blocked": True,
            "ip": ip,
            "duration": duration,
            "rule_id": f"BLOCK-{uuid.uuid4().hex[:8]}",
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat()
        }
    
    async def _block_domain(self, params: Dict, variables: Dict) -> Dict:
        """Block domain on DNS/proxy"""
        domain = params.get("domain")
        
        return {
            "blocked": True,
            "domain": domain,
            "rule_id": f"DNS-BLOCK-{uuid.uuid4().hex[:8]}"
        }
    
    async def _quarantine_host(self, params: Dict, variables: Dict) -> Dict:
        """Quarantine host from network"""
        host = params.get("host")
        isolation_type = params.get("isolation_type", "network")
        
        return {
            "quarantined": True,
            "host": host,
            "isolation_type": isolation_type,
            "quarantine_id": f"QRT-{uuid.uuid4().hex[:8]}"
        }
    
    async def _disable_user(self, params: Dict, variables: Dict) -> Dict:
        """Disable user account"""
        username = params.get("username")
        
        return {
            "disabled": True,
            "username": username,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _send_email(self, params: Dict, variables: Dict) -> Dict:
        """Send email notification"""
        to = params.get("to", [])
        subject = params.get("subject", "SOAR Notification")
        body = params.get("body", "")
        
        return {
            "sent": True,
            "to": to,
            "subject": subject,
            "message_id": f"MSG-{uuid.uuid4().hex[:8]}"
        }
    
    async def _send_slack(self, params: Dict, variables: Dict) -> Dict:
        """Send Slack notification"""
        channel = params.get("channel", "#security")
        message = params.get("message", "")
        
        return {
            "sent": True,
            "channel": channel,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _create_ticket(self, params: Dict, variables: Dict) -> Dict:
        """Create ticket in ticketing system"""
        title = params.get("title", "")
        description = params.get("description", "")
        priority = params.get("priority", "medium")
        
        ticket_id = f"TKT-{uuid.uuid4().hex[:8].upper()}"
        
        return {
            "created": True,
            "ticket_id": ticket_id,
            "title": title,
            "priority": priority,
            "url": f"https://tickets.example.com/{ticket_id}"
        }
    
    async def _run_script(self, params: Dict, variables: Dict) -> Dict:
        """Execute custom script"""
        script_path = params.get("script_path", "")
        args = params.get("arguments", [])
        
        return {
            "executed": True,
            "script": script_path,
            "exit_code": 0,
            "stdout": "Script completed successfully",
            "stderr": ""
        }
    
    async def _http_request(self, params: Dict, variables: Dict) -> Dict:
        """Make HTTP request"""
        url = params.get("url", "")
        method = params.get("method", "GET")
        
        return {
            "status_code": 200,
            "url": url,
            "method": method,
            "response": {}
        }
    
    async def _wait(self, params: Dict, variables: Dict) -> Dict:
        """Wait for specified duration"""
        seconds = params.get("seconds", 60)
        await asyncio.sleep(min(seconds, 5))  # Cap for demo
        
        return {
            "waited": True,
            "duration": seconds
        }
    
    async def _evaluate_condition(self, params: Dict, variables: Dict) -> Dict:
        """Evaluate condition"""
        condition = params.get("condition", "true")
        
        # Simple evaluation - would be more sophisticated in production
        result = True
        
        return {
            "condition": condition,
            "result": result
        }
    
    async def _set_variable(self, params: Dict, variables: Dict) -> Dict:
        """Set workflow variable"""
        name = params.get("name", "")
        value = params.get("value", "")
        
        return {
            "variable": name,
            "value": value
        }
    
    async def _create_case(self, params: Dict, variables: Dict) -> Dict:
        """Create investigation case"""
        title = params.get("title", "")
        priority = params.get("priority", "medium")
        
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        
        return {
            "case_id": case_id,
            "title": title,
            "priority": priority,
            "status": "open"
        }
    
    async def _notify_team(self, params: Dict, variables: Dict) -> Dict:
        """Notify security team"""
        team = params.get("team", "soc")
        message = params.get("message", "")
        
        return {
            "notified": True,
            "team": team,
            "channels": ["slack", "email"]
        }


class WorkflowEngine:
    """Execute and manage SOAR workflows"""
    
    def __init__(self):
        self.logger = logging.getLogger("WorkflowEngine")
        self.workflows: Dict[str, Workflow] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.action_executor = ActionExecutor()
        self._load_default_workflows()
    
    def _load_default_workflows(self):
        """Load default SOAR workflows"""
        
        # Phishing Response Workflow
        phishing_wf = Workflow(
            workflow_id="WF-PHISHING-001",
            name="Phishing Response",
            description="Automated phishing incident response workflow",
            version="1.0",
            triggers=[
                WorkflowTrigger(
                    trigger_id="TRG-001",
                    trigger_type=TriggerType.ALERT,
                    name="Phishing Alert",
                    description="Triggered on phishing detection alert",
                    conditions=[{"alert_type": "phishing"}]
                )
            ],
            actions=[
                WorkflowAction(
                    action_id="ACT-001",
                    name="Enrich Sender Domain",
                    action_type=ActionType.ENRICH_DOMAIN,
                    description="Get threat intel on sender domain",
                    parameters={"domain": "{{sender_domain}}"}
                ),
                WorkflowAction(
                    action_id="ACT-002",
                    name="Check URL Reputation",
                    action_type=ActionType.ENRICH_URL,
                    description="Analyze URLs in email",
                    parameters={"url": "{{email_url}}"}
                ),
                WorkflowAction(
                    action_id="ACT-003",
                    name="Quarantine Email",
                    action_type=ActionType.QUARANTINE_EMAIL,
                    description="Remove email from all mailboxes",
                    parameters={"message_id": "{{email_id}}"}
                ),
                WorkflowAction(
                    action_id="ACT-004",
                    name="Block Domain",
                    action_type=ActionType.BLOCK_DOMAIN,
                    description="Block sender domain",
                    parameters={"domain": "{{sender_domain}}"},
                    condition="sender_reputation < 30"
                ),
                WorkflowAction(
                    action_id="ACT-005",
                    name="Create Ticket",
                    action_type=ActionType.CREATE_TICKET,
                    description="Create incident ticket",
                    parameters={
                        "title": "Phishing - {{sender_domain}}",
                        "priority": "high"
                    }
                ),
                WorkflowAction(
                    action_id="ACT-006",
                    name="Notify SOC",
                    action_type=ActionType.NOTIFY_TEAM,
                    description="Alert SOC team",
                    parameters={
                        "team": "soc",
                        "message": "Phishing incident detected from {{sender_domain}}"
                    }
                )
            ],
            tags=["phishing", "email", "automated"],
            category="email_security"
        )
        self.workflows[phishing_wf.workflow_id] = phishing_wf
        
        # Malware Detection Workflow
        malware_wf = Workflow(
            workflow_id="WF-MALWARE-001",
            name="Malware Response",
            description="Automated malware detection response",
            version="1.0",
            triggers=[
                WorkflowTrigger(
                    trigger_id="TRG-001",
                    trigger_type=TriggerType.ALERT,
                    name="Malware Alert",
                    description="Triggered on malware detection",
                    conditions=[{"alert_type": "malware"}]
                )
            ],
            actions=[
                WorkflowAction(
                    action_id="ACT-001",
                    name="Enrich File Hash",
                    action_type=ActionType.ENRICH_HASH,
                    description="Check hash reputation",
                    parameters={"hash": "{{file_hash}}"}
                ),
                WorkflowAction(
                    action_id="ACT-002",
                    name="Quarantine Host",
                    action_type=ActionType.QUARANTINE_HOST,
                    description="Isolate infected host",
                    parameters={
                        "host": "{{affected_host}}",
                        "isolation_type": "network"
                    }
                ),
                WorkflowAction(
                    action_id="ACT-003",
                    name="Quarantine File",
                    action_type=ActionType.QUARANTINE_FILE,
                    description="Quarantine malware sample",
                    parameters={"file_path": "{{file_path}}"}
                ),
                WorkflowAction(
                    action_id="ACT-004",
                    name="Create Case",
                    action_type=ActionType.CREATE_CASE,
                    description="Create investigation case",
                    parameters={
                        "title": "Malware - {{affected_host}}",
                        "priority": "critical"
                    }
                ),
                WorkflowAction(
                    action_id="ACT-005",
                    name="Escalate to IR",
                    action_type=ActionType.ESCALATE,
                    description="Escalate to incident response",
                    parameters={"team": "ir", "severity": "high"}
                )
            ],
            tags=["malware", "endpoint", "automated"],
            category="endpoint_security"
        )
        self.workflows[malware_wf.workflow_id] = malware_wf
        
        # Suspicious Login Workflow
        login_wf = Workflow(
            workflow_id="WF-LOGIN-001",
            name="Suspicious Login Response",
            description="Investigate suspicious login attempts",
            version="1.0",
            triggers=[
                WorkflowTrigger(
                    trigger_id="TRG-001",
                    trigger_type=TriggerType.ALERT,
                    name="Suspicious Login",
                    description="Triggered on suspicious login detection",
                    conditions=[{"alert_type": "suspicious_login"}]
                )
            ],
            actions=[
                WorkflowAction(
                    action_id="ACT-001",
                    name="Enrich Source IP",
                    action_type=ActionType.ENRICH_IP,
                    description="Get IP reputation",
                    parameters={"ip": "{{source_ip}}"}
                ),
                WorkflowAction(
                    action_id="ACT-002",
                    name="Lookup User",
                    action_type=ActionType.LOOKUP_USER,
                    description="Get user information",
                    parameters={"username": "{{username}}"}
                ),
                WorkflowAction(
                    action_id="ACT-003",
                    name="Block IP",
                    action_type=ActionType.BLOCK_IP,
                    description="Block source IP",
                    parameters={"ip": "{{source_ip}}", "duration": "24h"},
                    condition="ip_reputation < 20"
                ),
                WorkflowAction(
                    action_id="ACT-004",
                    name="Notify User",
                    action_type=ActionType.SEND_EMAIL,
                    description="Alert user of suspicious activity",
                    parameters={
                        "to": ["{{user_email}}"],
                        "subject": "Suspicious Login Alert",
                        "body": "Suspicious login detected from {{source_ip}}"
                    }
                )
            ],
            tags=["authentication", "identity", "automated"],
            category="identity_security"
        )
        self.workflows[login_wf.workflow_id] = login_wf
        
        # IOC Hunting Workflow
        ioc_wf = Workflow(
            workflow_id="WF-IOC-001",
            name="IOC Threat Hunt",
            description="Hunt for indicators of compromise",
            version="1.0",
            triggers=[
                WorkflowTrigger(
                    trigger_id="TRG-001",
                    trigger_type=TriggerType.MANUAL,
                    name="Manual Hunt",
                    description="Manually triggered IOC hunt"
                )
            ],
            actions=[
                WorkflowAction(
                    action_id="ACT-001",
                    name="Query SIEM for IOC",
                    action_type=ActionType.QUERY_SIEM,
                    description="Search logs for IOC",
                    parameters={"query": "{{ioc_value}}", "time_range": "7d"}
                ),
                WorkflowAction(
                    action_id="ACT-002",
                    name="Query EDR",
                    action_type=ActionType.HTTP_REQUEST,
                    description="Search EDR for IOC",
                    parameters={
                        "url": "{{edr_api}}/search",
                        "method": "POST",
                        "body": {"ioc": "{{ioc_value}}"}
                    }
                ),
                WorkflowAction(
                    action_id="ACT-003",
                    name="Create Report",
                    action_type=ActionType.CREATE_TICKET,
                    description="Document hunt results",
                    parameters={
                        "title": "IOC Hunt Results - {{ioc_value}}",
                        "priority": "medium"
                    }
                )
            ],
            tags=["threat_hunting", "ioc", "manual"],
            category="threat_hunting"
        )
        self.workflows[ioc_wf.workflow_id] = ioc_wf
    
    async def execute_workflow(self, workflow_id: str, 
                               trigger_data: Dict[str, Any] = None) -> WorkflowExecution:
        """Execute a workflow"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        workflow = self.workflows[workflow_id]
        
        execution = WorkflowExecution(
            execution_id=f"EXEC-{uuid.uuid4().hex[:8].upper()}",
            workflow_id=workflow_id,
            workflow_name=workflow.name,
            status=WorkflowStatus.RUNNING,
            trigger_type=TriggerType.MANUAL,
            trigger_data=trigger_data or {},
            started_at=datetime.now(),
            variables=trigger_data.copy() if trigger_data else {}
        )
        
        self.executions[execution.execution_id] = execution
        
        try:
            for action in workflow.actions:
                if execution.status != WorkflowStatus.RUNNING:
                    break
                
                execution.current_action = action.action_id
                
                # Check condition
                if action.condition:
                    cond_result = await self.action_executor.execute(
                        WorkflowAction(
                            action_id="cond-check",
                            name="Condition Check",
                            action_type=ActionType.CONDITION,
                            description="",
                            parameters={"condition": action.condition}
                        ),
                        execution.variables
                    )
                    if not cond_result.get("outputs", {}).get("result", True):
                        continue
                
                # Execute action
                result = await self.action_executor.execute(action, execution.variables)
                
                action_result = {
                    "action_id": action.action_id,
                    "action_name": action.name,
                    "success": result["success"],
                    "outputs": result.get("outputs", {}),
                    "error": result.get("error"),
                    "timestamp": datetime.now().isoformat()
                }
                
                execution.actions_completed.append(action_result)
                
                # Update variables with outputs
                for output_name, output_value in result.get("outputs", {}).items():
                    execution.variables[output_name] = output_value
                
                if not result["success"] and not action.continue_on_failure:
                    execution.errors.append(result.get("error", "Unknown error"))
                    execution.status = WorkflowStatus.FAILED
                    break
            
            if execution.status == WorkflowStatus.RUNNING:
                execution.status = WorkflowStatus.COMPLETED
            
        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.errors.append(str(e))
        
        execution.completed_at = datetime.now()
        execution.outputs = execution.variables
        
        return execution
    
    def add_workflow(self, workflow: Workflow):
        """Add a workflow"""
        self.workflows[workflow.workflow_id] = workflow
    
    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get workflow by ID"""
        return self.workflows.get(workflow_id)
    
    def list_workflows(self, category: str = None) -> List[Workflow]:
        """List all workflows"""
        workflows = list(self.workflows.values())
        if category:
            workflows = [w for w in workflows if w.category == category]
        return workflows
    
    def get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get execution by ID"""
        return self.executions.get(execution_id)
    
    def list_executions(self, workflow_id: str = None,
                       status: WorkflowStatus = None) -> List[WorkflowExecution]:
        """List workflow executions"""
        executions = list(self.executions.values())
        
        if workflow_id:
            executions = [e for e in executions if e.workflow_id == workflow_id]
        
        if status:
            executions = [e for e in executions if e.status == status]
        
        return sorted(executions, key=lambda e: e.started_at, reverse=True)


class CaseManager:
    """Manage SOAR cases"""
    
    def __init__(self):
        self.logger = logging.getLogger("CaseManager")
        self.cases: Dict[str, Case] = {}
    
    def create_case(self, title: str, description: str,
                   priority: str = "medium", **kwargs) -> Case:
        """Create a new case"""
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        case = Case(
            case_id=case_id,
            title=title,
            description=description,
            status="open",
            priority=priority,
            assignee=kwargs.get("assignee"),
            source=kwargs.get("source", "manual"),
            source_id=kwargs.get("source_id"),
            tags=kwargs.get("tags", [])
        )
        
        # Add creation to timeline
        case.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "created",
            "user": kwargs.get("created_by", "system"),
            "details": f"Case created with priority {priority}"
        })
        
        self.cases[case_id] = case
        return case
    
    def update_case(self, case_id: str, **kwargs) -> Optional[Case]:
        """Update a case"""
        if case_id not in self.cases:
            return None
        
        case = self.cases[case_id]
        
        for key, value in kwargs.items():
            if hasattr(case, key):
                old_value = getattr(case, key)
                setattr(case, key, value)
                
                if old_value != value:
                    case.timeline.append({
                        "timestamp": datetime.now().isoformat(),
                        "action": "updated",
                        "field": key,
                        "old_value": str(old_value),
                        "new_value": str(value)
                    })
        
        case.updated_at = datetime.now()
        return case
    
    def add_artifact(self, case_id: str, artifact_type: str,
                    value: str, description: str = "") -> bool:
        """Add artifact to case"""
        if case_id not in self.cases:
            return False
        
        artifact = {
            "id": f"ART-{uuid.uuid4().hex[:8]}",
            "type": artifact_type,
            "value": value,
            "description": description,
            "added_at": datetime.now().isoformat()
        }
        
        self.cases[case_id].artifacts.append(artifact)
        self.cases[case_id].updated_at = datetime.now()
        
        return True
    
    def add_note(self, case_id: str, content: str, author: str = "system") -> bool:
        """Add note to case"""
        if case_id not in self.cases:
            return False
        
        note = {
            "id": f"NOTE-{uuid.uuid4().hex[:8]}",
            "content": content,
            "author": author,
            "timestamp": datetime.now().isoformat()
        }
        
        self.cases[case_id].notes.append(note)
        self.cases[case_id].updated_at = datetime.now()
        
        return True
    
    def close_case(self, case_id: str, resolution: str = None) -> Optional[Case]:
        """Close a case"""
        if case_id not in self.cases:
            return None
        
        case = self.cases[case_id]
        case.status = "closed"
        case.closed_at = datetime.now()
        case.updated_at = datetime.now()
        
        # Calculate metrics
        case.metrics["time_to_close"] = (case.closed_at - case.created_at).total_seconds() / 3600
        
        case.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "closed",
            "resolution": resolution
        })
        
        return case
    
    def get_case(self, case_id: str) -> Optional[Case]:
        """Get case by ID"""
        return self.cases.get(case_id)
    
    def list_cases(self, status: str = None, priority: str = None) -> List[Case]:
        """List cases with optional filters"""
        cases = list(self.cases.values())
        
        if status:
            cases = [c for c in cases if c.status == status]
        
        if priority:
            cases = [c for c in cases if c.priority == priority]
        
        return sorted(cases, key=lambda c: c.created_at, reverse=True)


class SOAREngine:
    """Main SOAR orchestration engine"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger("SOAREngine")
        self.workflow_engine = WorkflowEngine()
        self.case_manager = CaseManager()
        self.integrations: Dict[str, Integration] = {}
        self._load_default_integrations()
    
    def _load_default_integrations(self):
        """Load default integration configurations"""
        
        default_integrations = [
            Integration(
                integration_id="INT-SIEM-001",
                name="Splunk SIEM",
                integration_type=IntegrationType.SIEM,
                description="Splunk Enterprise Security integration",
                capabilities=["query_logs", "create_alert", "get_events"]
            ),
            Integration(
                integration_id="INT-EDR-001",
                name="CrowdStrike Falcon",
                integration_type=IntegrationType.EDR,
                description="CrowdStrike EDR integration",
                capabilities=["isolate_host", "get_detections", "query_processes"]
            ),
            Integration(
                integration_id="INT-FW-001",
                name="Palo Alto NGFW",
                integration_type=IntegrationType.FIREWALL,
                description="Palo Alto Networks firewall integration",
                capabilities=["block_ip", "block_domain", "create_rule"]
            ),
            Integration(
                integration_id="INT-TI-001",
                name="VirusTotal",
                integration_type=IntegrationType.THREAT_INTEL,
                description="VirusTotal threat intelligence",
                capabilities=["enrich_hash", "enrich_url", "enrich_ip", "enrich_domain"]
            ),
            Integration(
                integration_id="INT-TICKET-001",
                name="ServiceNow",
                integration_type=IntegrationType.TICKETING,
                description="ServiceNow ITSM integration",
                capabilities=["create_ticket", "update_ticket", "close_ticket"]
            )
        ]
        
        for integration in default_integrations:
            self.integrations[integration.integration_id] = integration
    
    async def trigger_workflow(self, workflow_id: str,
                               trigger_data: Dict[str, Any] = None) -> WorkflowExecution:
        """Trigger a workflow execution"""
        return await self.workflow_engine.execute_workflow(workflow_id, trigger_data)
    
    def create_case(self, title: str, description: str, **kwargs) -> Case:
        """Create a new case"""
        return self.case_manager.create_case(title, description, **kwargs)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get SOAR metrics"""
        all_executions = self.workflow_engine.list_executions()
        all_cases = self.case_manager.list_cases()
        
        # Execution metrics
        completed = [e for e in all_executions if e.status == WorkflowStatus.COMPLETED]
        failed = [e for e in all_executions if e.status == WorkflowStatus.FAILED]
        
        avg_duration = 0
        if completed:
            total_duration = sum(
                (e.completed_at - e.started_at).total_seconds()
                for e in completed if e.completed_at
            )
            avg_duration = total_duration / len(completed)
        
        # Case metrics
        open_cases = len([c for c in all_cases if c.status == "open"])
        closed_cases = len([c for c in all_cases if c.status == "closed"])
        
        return {
            "workflows": {
                "total": len(self.workflow_engine.workflows),
                "enabled": len([w for w in self.workflow_engine.workflows.values() if w.is_enabled])
            },
            "executions": {
                "total": len(all_executions),
                "completed": len(completed),
                "failed": len(failed),
                "success_rate": len(completed) / max(len(all_executions), 1) * 100,
                "avg_duration_seconds": round(avg_duration, 2)
            },
            "cases": {
                "total": len(all_cases),
                "open": open_cases,
                "closed": closed_cases
            },
            "integrations": {
                "total": len(self.integrations),
                "enabled": len([i for i in self.integrations.values() if i.is_enabled])
            }
        }
