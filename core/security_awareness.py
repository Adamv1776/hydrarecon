#!/usr/bin/env python3
"""
HydraRecon Security Awareness Training Engine
Enterprise phishing simulation and security training platform.
"""

import asyncio
import json
import hashlib
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from pathlib import Path
import random
import string


class CampaignType(Enum):
    """Types of awareness campaigns"""
    PHISHING = "phishing"
    VISHING = "vishing"
    SMISHING = "smishing"
    USB_DROP = "usb_drop"
    TAILGATING = "tailgating"
    TRAINING = "training"
    QUIZ = "quiz"


class CampaignStatus(Enum):
    """Campaign status"""
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class TargetStatus(Enum):
    """Target interaction status"""
    NOT_SENT = "not_sent"
    SENT = "sent"
    OPENED = "opened"
    CLICKED = "clicked"
    SUBMITTED = "submitted"
    REPORTED = "reported"


class TrainingStatus(Enum):
    """Training completion status"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class DifficultyLevel(Enum):
    """Phishing difficulty levels"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


@dataclass
class PhishingTemplate:
    """Phishing email template"""
    id: str
    name: str
    category: str
    subject: str
    html_content: str
    text_content: str
    sender_name: str
    sender_email: str
    difficulty: DifficultyLevel
    landing_page_id: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    uses: int = 0
    success_rate: float = 0.0


@dataclass
class LandingPage:
    """Phishing landing page"""
    id: str
    name: str
    html_content: str
    capture_fields: List[str]
    redirect_url: str
    awareness_content: str
    logo_url: str = ""
    favicon_url: str = ""


@dataclass
class Target:
    """Campaign target (employee)"""
    id: str
    email: str
    first_name: str
    last_name: str
    department: str
    position: str
    manager: str
    groups: List[str] = field(default_factory=list)
    custom_fields: Dict[str, str] = field(default_factory=dict)
    phishing_history: List[Dict[str, Any]] = field(default_factory=list)
    training_history: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 50.0


@dataclass
class CampaignResult:
    """Individual campaign result for a target"""
    target_id: str
    target_email: str
    status: TargetStatus
    sent_time: Optional[datetime] = None
    opened_time: Optional[datetime] = None
    clicked_time: Optional[datetime] = None
    submitted_time: Optional[datetime] = None
    reported_time: Optional[datetime] = None
    submitted_data: Dict[str, str] = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    location: str = ""


@dataclass
class Campaign:
    """Awareness campaign"""
    id: str
    name: str
    description: str
    campaign_type: CampaignType
    status: CampaignStatus
    created_by: str
    created_date: datetime
    scheduled_date: Optional[datetime] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    template_id: Optional[str] = None
    landing_page_id: Optional[str] = None
    target_groups: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    results: List[CampaignResult] = field(default_factory=list)
    send_rate: int = 100  # emails per hour
    send_order: str = "random"  # random, alphabetical, department
    auto_report_training: bool = True
    redirect_after_click: bool = True
    track_opens: bool = True
    track_clicks: bool = True


@dataclass
class TrainingModule:
    """Security training module"""
    id: str
    name: str
    description: str
    category: str
    content_type: str  # video, interactive, document
    content_url: str
    duration_minutes: int
    passing_score: int
    questions: List[Dict[str, Any]] = field(default_factory=list)
    required: bool = True
    active: bool = True


@dataclass
class TrainingAssignment:
    """Training assignment for a user"""
    id: str
    user_id: str
    module_id: str
    assigned_date: datetime
    due_date: datetime
    status: TrainingStatus
    started_date: Optional[datetime] = None
    completed_date: Optional[datetime] = None
    score: Optional[float] = None
    attempts: int = 0
    time_spent_minutes: int = 0


@dataclass
class DepartmentMetrics:
    """Department-level metrics"""
    department: str
    total_employees: int
    phishing_tests: int
    click_rate: float
    report_rate: float
    training_completion: float
    average_risk_score: float


class SecurityAwarenessEngine:
    """Enterprise security awareness and training platform"""
    
    def __init__(self, db_path: str = "awareness.db"):
        self.db_path = db_path
        self.templates: Dict[str, PhishingTemplate] = {}
        self.landing_pages: Dict[str, LandingPage] = {}
        self.targets: Dict[str, Target] = {}
        self.campaigns: Dict[str, Campaign] = {}
        self.training_modules: Dict[str, TrainingModule] = {}
        self.assignments: Dict[str, TrainingAssignment] = {}
        self.callbacks: Dict[str, List[Callable]] = {}
        self._init_database()
        self._init_default_templates()
        self._init_default_training()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_templates (
                id TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                subject TEXT,
                html_content TEXT,
                text_content TEXT,
                sender_name TEXT,
                sender_email TEXT,
                difficulty TEXT,
                landing_page_id TEXT,
                indicators TEXT,
                tags TEXT,
                uses INTEGER,
                success_rate REAL,
                created_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                first_name TEXT,
                last_name TEXT,
                department TEXT,
                position TEXT,
                manager TEXT,
                groups TEXT,
                custom_fields TEXT,
                phishing_history TEXT,
                training_history TEXT,
                risk_score REAL,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                campaign_type TEXT,
                status TEXT,
                created_by TEXT,
                created_date TEXT,
                scheduled_date TEXT,
                start_date TEXT,
                end_date TEXT,
                template_id TEXT,
                landing_page_id TEXT,
                target_groups TEXT,
                targets TEXT,
                results TEXT,
                config TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS training_modules (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                category TEXT,
                content_type TEXT,
                content_url TEXT,
                duration_minutes INTEGER,
                passing_score INTEGER,
                questions TEXT,
                required INTEGER,
                active INTEGER,
                created_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS training_assignments (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                module_id TEXT,
                assigned_date TEXT,
                due_date TEXT,
                status TEXT,
                started_date TEXT,
                completed_date TEXT,
                score REAL,
                attempts INTEGER,
                time_spent_minutes INTEGER,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT,
                target_id TEXT,
                event_type TEXT,
                event_time TEXT,
                ip_address TEXT,
                user_agent TEXT,
                data TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _init_default_templates(self):
        """Initialize default phishing templates"""
        templates = [
            PhishingTemplate(
                id="t001",
                name="IT Password Reset",
                category="IT Support",
                subject="Action Required: Password Expiration Notice",
                html_content="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <img src="{{company_logo}}" alt="Company Logo" style="height: 50px;">
                    <h2>Password Expiration Notice</h2>
                    <p>Dear {{first_name}},</p>
                    <p>Your password will expire in 24 hours. To avoid any disruption to your work, please reset your password immediately.</p>
                    <p><a href="{{phishing_url}}" style="background-color: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password Now</a></p>
                    <p>If you did not request this change, please contact IT Support.</p>
                    <p>Best regards,<br>IT Support Team</p>
                </div>
                </body>
                </html>
                """,
                text_content="Your password will expire in 24 hours. Reset it at: {{phishing_url}}",
                sender_name="IT Support",
                sender_email="it-support@{{company_domain}}",
                difficulty=DifficultyLevel.EASY,
                indicators=["Urgency", "Generic greeting", "External link"]
            ),
            PhishingTemplate(
                id="t002",
                name="Shared Document",
                category="Cloud Services",
                subject="{{sender_name}} shared a document with you",
                html_content="""
                <html>
                <body style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
                <div style="max-width: 500px; margin: 20px auto; background: white; padding: 30px; border-radius: 8px;">
                    <img src="{{cloud_logo}}" alt="Cloud" style="height: 40px;">
                    <h3>{{sender_name}} shared a document with you</h3>
                    <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                        <p style="margin: 0;"><strong>Q3 Financial Report.xlsx</strong></p>
                        <p style="margin: 5px 0 0 0; color: #666;">Shared on {{date}}</p>
                    </div>
                    <a href="{{phishing_url}}" style="display: block; background: #1a73e8; color: white; text-align: center; padding: 12px; text-decoration: none; border-radius: 4px;">Open Document</a>
                </div>
                </body>
                </html>
                """,
                text_content="{{sender_name}} shared Q3 Financial Report.xlsx with you: {{phishing_url}}",
                sender_name="Google Drive",
                sender_email="drive-shares-noreply@google.com",
                difficulty=DifficultyLevel.MEDIUM,
                indicators=["Impersonating trusted service", "Curiosity trigger"]
            ),
            PhishingTemplate(
                id="t003",
                name="HR Benefits Update",
                category="HR",
                subject="Important: Benefits Enrollment Deadline Tomorrow",
                html_content="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c3e50;">Benefits Enrollment Reminder</h2>
                    <p>Dear {{first_name}},</p>
                    <p>This is a reminder that the annual benefits enrollment period ends <strong>tomorrow</strong>.</p>
                    <p>If you haven't reviewed and confirmed your benefits selections, please do so immediately to ensure your coverage continues without interruption.</p>
                    <p><a href="{{phishing_url}}" style="background-color: #27ae60; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Review Benefits Now</a></p>
                    <p>Please note: Failure to complete enrollment may result in default coverage options being applied.</p>
                    <p>Human Resources Team</p>
                </div>
                </body>
                </html>
                """,
                text_content="Benefits enrollment ends tomorrow. Review your selections: {{phishing_url}}",
                sender_name="Human Resources",
                sender_email="benefits@{{company_domain}}",
                difficulty=DifficultyLevel.HARD,
                indicators=["Urgency", "Fear of loss", "Legitimate-looking sender"]
            ),
            PhishingTemplate(
                id="t004",
                name="Package Delivery",
                category="Delivery",
                subject="Your package could not be delivered",
                html_content="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
                    <img src="{{carrier_logo}}" alt="Delivery" style="height: 40px;">
                    <h3>Delivery Attempt Failed</h3>
                    <p>We attempted to deliver your package today but were unable to complete the delivery.</p>
                    <p><strong>Tracking Number:</strong> {{tracking_number}}</p>
                    <p>To reschedule your delivery or update your delivery preferences, please click below:</p>
                    <p><a href="{{phishing_url}}" style="background: #ff6b00; color: white; padding: 10px 20px; text-decoration: none;">Reschedule Delivery</a></p>
                    <p style="color: #666; font-size: 12px;">If you do not reschedule within 48 hours, your package will be returned to sender.</p>
                </div>
                </body>
                </html>
                """,
                text_content="Package delivery failed. Reschedule at: {{phishing_url}}",
                sender_name="Delivery Notification",
                sender_email="delivery@carrier-notify.com",
                difficulty=DifficultyLevel.EASY,
                indicators=["External sender", "Urgency", "Unknown package"]
            ),
            PhishingTemplate(
                id="t005",
                name="CEO Wire Transfer",
                category="Executive Impersonation",
                subject="Urgent: Wire Transfer Needed",
                html_content="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                <p>Hi,</p>
                <p>I need you to process an urgent wire transfer for a confidential acquisition we're working on. This needs to happen today.</p>
                <p>Please review the details and complete the transfer: <a href="{{phishing_url}}">Transfer Details</a></p>
                <p>Don't discuss this with anyone else as the deal is highly confidential.</p>
                <p>Thanks,<br>{{ceo_name}}<br>Sent from my iPhone</p>
                </body>
                </html>
                """,
                text_content="Urgent wire transfer needed. Details: {{phishing_url}} - {{ceo_name}}",
                sender_name="{{ceo_name}}",
                sender_email="{{ceo_name_lower}}@{{lookalike_domain}}",
                difficulty=DifficultyLevel.EXPERT,
                indicators=["Executive impersonation", "Urgency", "Secrecy request", "External domain"]
            )
        ]
        
        for template in templates:
            self.templates[template.id] = template
    
    def _init_default_training(self):
        """Initialize default training modules"""
        modules = [
            TrainingModule(
                id="m001",
                name="Phishing Awareness 101",
                description="Learn to identify and report phishing attempts",
                category="Phishing",
                content_type="interactive",
                content_url="/training/phishing-101",
                duration_minutes=15,
                passing_score=80,
                questions=[
                    {
                        "id": "q1",
                        "question": "Which of these is a common phishing indicator?",
                        "options": ["Urgent language", "Company logo", "Correct grammar", "Short email"],
                        "correct": 0
                    },
                    {
                        "id": "q2",
                        "question": "What should you do if you receive a suspicious email?",
                        "options": ["Click links to verify", "Report to IT", "Reply to sender", "Forward to colleagues"],
                        "correct": 1
                    }
                ]
            ),
            TrainingModule(
                id="m002",
                name="Password Security",
                description="Best practices for creating and managing passwords",
                category="Authentication",
                content_type="video",
                content_url="/training/password-security",
                duration_minutes=10,
                passing_score=85
            ),
            TrainingModule(
                id="m003",
                name="Social Engineering Defense",
                description="Recognize and prevent social engineering attacks",
                category="Social Engineering",
                content_type="interactive",
                content_url="/training/social-engineering",
                duration_minutes=20,
                passing_score=80
            ),
            TrainingModule(
                id="m004",
                name="Data Protection Basics",
                description="How to handle sensitive data securely",
                category="Data Protection",
                content_type="video",
                content_url="/training/data-protection",
                duration_minutes=12,
                passing_score=80
            ),
            TrainingModule(
                id="m005",
                name="Mobile Security",
                description="Secure your mobile devices and data",
                category="Mobile",
                content_type="interactive",
                content_url="/training/mobile-security",
                duration_minutes=15,
                passing_score=75
            )
        ]
        
        for module in modules:
            self.training_modules[module.id] = module
    
    async def import_targets(
        self,
        targets_data: List[Dict[str, str]]
    ) -> List[Target]:
        """Import targets from list"""
        imported = []
        
        for data in targets_data:
            target_id = hashlib.sha256(
                data["email"].lower().encode()
            ).hexdigest()[:16]
            
            target = Target(
                id=target_id,
                email=data["email"].lower(),
                first_name=data.get("first_name", ""),
                last_name=data.get("last_name", ""),
                department=data.get("department", ""),
                position=data.get("position", ""),
                manager=data.get("manager", ""),
                groups=data.get("groups", "").split(",") if data.get("groups") else []
            )
            
            self.targets[target_id] = target
            await self._save_target(target)
            imported.append(target)
        
        return imported
    
    async def create_campaign(
        self,
        name: str,
        campaign_type: CampaignType,
        template_id: str,
        target_ids: Optional[List[str]] = None,
        target_groups: Optional[List[str]] = None,
        scheduled_date: Optional[datetime] = None,
        created_by: str = "admin",
        **kwargs
    ) -> Campaign:
        """Create a new awareness campaign"""
        campaign_id = hashlib.sha256(
            f"{name}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Resolve targets from groups if needed
        all_targets = list(target_ids or [])
        if target_groups:
            for group in target_groups:
                group_targets = [
                    t.id for t in self.targets.values()
                    if group in t.groups
                ]
                all_targets.extend(group_targets)
        
        all_targets = list(set(all_targets))  # Remove duplicates
        
        campaign = Campaign(
            id=campaign_id,
            name=name,
            description=kwargs.get("description", ""),
            campaign_type=campaign_type,
            status=CampaignStatus.SCHEDULED if scheduled_date else CampaignStatus.DRAFT,
            created_by=created_by,
            created_date=datetime.now(),
            scheduled_date=scheduled_date,
            template_id=template_id,
            landing_page_id=kwargs.get("landing_page_id"),
            target_groups=target_groups or [],
            targets=all_targets,
            send_rate=kwargs.get("send_rate", 100),
            send_order=kwargs.get("send_order", "random"),
            auto_report_training=kwargs.get("auto_report_training", True)
        )
        
        # Initialize results for each target
        for target_id in all_targets:
            target = self.targets.get(target_id)
            if target:
                campaign.results.append(CampaignResult(
                    target_id=target_id,
                    target_email=target.email,
                    status=TargetStatus.NOT_SENT
                ))
        
        self.campaigns[campaign_id] = campaign
        await self._save_campaign(campaign)
        await self._trigger_callback("campaign_created", campaign)
        
        return campaign
    
    async def start_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Start a campaign"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign or campaign.status not in [CampaignStatus.DRAFT, CampaignStatus.SCHEDULED]:
            return None
        
        campaign.status = CampaignStatus.RUNNING
        campaign.start_date = datetime.now()
        
        await self._save_campaign(campaign)
        await self._trigger_callback("campaign_started", campaign)
        
        # Start sending emails (in production, this would be async/queued)
        asyncio.create_task(self._send_campaign_emails(campaign))
        
        return campaign
    
    async def _send_campaign_emails(self, campaign: Campaign):
        """Send campaign emails to targets"""
        template = self.templates.get(campaign.template_id)
        if not template:
            return
        
        # Shuffle if random order
        results = campaign.results.copy()
        if campaign.send_order == "random":
            random.shuffle(results)
        
        for result in results:
            if campaign.status != CampaignStatus.RUNNING:
                break
            
            target = self.targets.get(result.target_id)
            if not target:
                continue
            
            # Generate unique tracking link
            tracking_id = self._generate_tracking_id(campaign.id, target.id)
            
            # Personalize template
            # In production, this would send actual emails
            result.status = TargetStatus.SENT
            result.sent_time = datetime.now()
            
            await self._log_event(campaign.id, target.id, "sent", {})
            
            # Rate limiting
            await asyncio.sleep(3600 / campaign.send_rate)
        
        # Check if all sent
        if all(r.status != TargetStatus.NOT_SENT for r in campaign.results):
            await self._trigger_callback("campaign_emails_sent", campaign)
    
    def _generate_tracking_id(self, campaign_id: str, target_id: str) -> str:
        """Generate unique tracking ID"""
        return hashlib.sha256(
            f"{campaign_id}:{target_id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:32]
    
    async def record_event(
        self,
        campaign_id: str,
        target_id: str,
        event_type: str,
        ip_address: str = "",
        user_agent: str = "",
        data: Optional[Dict] = None
    ):
        """Record tracking event"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return
        
        result = next((r for r in campaign.results if r.target_id == target_id), None)
        if not result:
            return
        
        now = datetime.now()
        
        if event_type == "opened" and result.status == TargetStatus.SENT:
            result.status = TargetStatus.OPENED
            result.opened_time = now
            result.ip_address = ip_address
            result.user_agent = user_agent
        
        elif event_type == "clicked" and result.status in [TargetStatus.SENT, TargetStatus.OPENED]:
            result.status = TargetStatus.CLICKED
            result.clicked_time = now
            result.ip_address = ip_address
            result.user_agent = user_agent
            
            # Update target risk score
            await self._update_target_risk(target_id, "clicked")
        
        elif event_type == "submitted":
            result.status = TargetStatus.SUBMITTED
            result.submitted_time = now
            result.submitted_data = data or {}
            
            # Higher risk for credential submission
            await self._update_target_risk(target_id, "submitted")
            
            # Auto-assign training if enabled
            if campaign.auto_report_training:
                await self._assign_remediation_training(target_id)
        
        elif event_type == "reported":
            result.status = TargetStatus.REPORTED
            result.reported_time = now
            
            # Reward for reporting
            await self._update_target_risk(target_id, "reported")
        
        await self._log_event(campaign_id, target_id, event_type, data or {})
        await self._save_campaign(campaign)
        await self._trigger_callback(f"target_{event_type}", {"campaign": campaign, "result": result})
    
    async def _update_target_risk(self, target_id: str, event_type: str):
        """Update target risk score based on event"""
        target = self.targets.get(target_id)
        if not target:
            return
        
        # Adjust risk score
        adjustments = {
            "clicked": 10,
            "submitted": 25,
            "reported": -15
        }
        
        adjustment = adjustments.get(event_type, 0)
        target.risk_score = max(0, min(100, target.risk_score + adjustment))
        
        # Add to history
        target.phishing_history.append({
            "date": datetime.now().isoformat(),
            "event": event_type,
            "risk_score": target.risk_score
        })
        
        await self._save_target(target)
    
    async def _assign_remediation_training(self, target_id: str):
        """Assign remediation training to target who clicked/submitted"""
        module = self.training_modules.get("m001")  # Phishing 101
        if not module:
            return
        
        assignment_id = hashlib.sha256(
            f"{target_id}:{module.id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        assignment = TrainingAssignment(
            id=assignment_id,
            user_id=target_id,
            module_id=module.id,
            assigned_date=datetime.now(),
            due_date=datetime.now() + timedelta(days=7),
            status=TrainingStatus.NOT_STARTED
        )
        
        self.assignments[assignment_id] = assignment
        await self._save_assignment(assignment)
    
    async def assign_training(
        self,
        user_ids: List[str],
        module_ids: List[str],
        due_days: int = 14
    ) -> List[TrainingAssignment]:
        """Assign training modules to users"""
        assigned = []
        
        for user_id in user_ids:
            for module_id in module_ids:
                assignment_id = hashlib.sha256(
                    f"{user_id}:{module_id}:{datetime.now().isoformat()}".encode()
                ).hexdigest()[:16]
                
                assignment = TrainingAssignment(
                    id=assignment_id,
                    user_id=user_id,
                    module_id=module_id,
                    assigned_date=datetime.now(),
                    due_date=datetime.now() + timedelta(days=due_days),
                    status=TrainingStatus.NOT_STARTED
                )
                
                self.assignments[assignment_id] = assignment
                await self._save_assignment(assignment)
                assigned.append(assignment)
        
        return assigned
    
    async def complete_training(
        self,
        assignment_id: str,
        score: float,
        time_spent: int
    ) -> Optional[TrainingAssignment]:
        """Record training completion"""
        assignment = self.assignments.get(assignment_id)
        if not assignment:
            return None
        
        module = self.training_modules.get(assignment.module_id)
        
        assignment.score = score
        assignment.time_spent_minutes = time_spent
        assignment.attempts += 1
        assignment.completed_date = datetime.now()
        
        if module and score >= module.passing_score:
            assignment.status = TrainingStatus.COMPLETED
            
            # Update target training history
            target = self.targets.get(assignment.user_id)
            if target:
                target.training_history.append({
                    "date": datetime.now().isoformat(),
                    "module": module.name,
                    "score": score,
                    "passed": True
                })
                # Reduce risk score for completing training
                target.risk_score = max(0, target.risk_score - 5)
                await self._save_target(target)
        else:
            assignment.status = TrainingStatus.FAILED
        
        await self._save_assignment(assignment)
        return assignment
    
    async def get_campaign_stats(self, campaign_id: str) -> Dict[str, Any]:
        """Get campaign statistics"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return {}
        
        total = len(campaign.results)
        sent = len([r for r in campaign.results if r.status != TargetStatus.NOT_SENT])
        opened = len([r for r in campaign.results if r.status in [
            TargetStatus.OPENED, TargetStatus.CLICKED, TargetStatus.SUBMITTED, TargetStatus.REPORTED
        ]])
        clicked = len([r for r in campaign.results if r.status in [
            TargetStatus.CLICKED, TargetStatus.SUBMITTED
        ]])
        submitted = len([r for r in campaign.results if r.status == TargetStatus.SUBMITTED])
        reported = len([r for r in campaign.results if r.status == TargetStatus.REPORTED])
        
        return {
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "status": campaign.status.value,
            "total_targets": total,
            "emails_sent": sent,
            "opened": opened,
            "clicked": clicked,
            "submitted": submitted,
            "reported": reported,
            "open_rate": round(opened / sent * 100, 2) if sent > 0 else 0,
            "click_rate": round(clicked / sent * 100, 2) if sent > 0 else 0,
            "submit_rate": round(submitted / sent * 100, 2) if sent > 0 else 0,
            "report_rate": round(reported / sent * 100, 2) if sent > 0 else 0
        }
    
    async def get_department_metrics(self) -> List[DepartmentMetrics]:
        """Get metrics by department"""
        departments = {}
        
        for target in self.targets.values():
            dept = target.department or "Unknown"
            if dept not in departments:
                departments[dept] = {
                    "total": 0,
                    "tests": 0,
                    "clicks": 0,
                    "reports": 0,
                    "training_complete": 0,
                    "risk_scores": []
                }
            
            departments[dept]["total"] += 1
            departments[dept]["risk_scores"].append(target.risk_score)
            
            # Count from phishing history
            for event in target.phishing_history:
                departments[dept]["tests"] += 1
                if event.get("event") == "clicked":
                    departments[dept]["clicks"] += 1
                elif event.get("event") == "reported":
                    departments[dept]["reports"] += 1
            
            # Count training completion
            user_assignments = [
                a for a in self.assignments.values()
                if a.user_id == target.id and a.status == TrainingStatus.COMPLETED
            ]
            if user_assignments:
                departments[dept]["training_complete"] += 1
        
        metrics = []
        for dept, data in departments.items():
            total = data["total"]
            tests = data["tests"]
            
            metrics.append(DepartmentMetrics(
                department=dept,
                total_employees=total,
                phishing_tests=tests,
                click_rate=round(data["clicks"] / tests * 100, 2) if tests > 0 else 0,
                report_rate=round(data["reports"] / tests * 100, 2) if tests > 0 else 0,
                training_completion=round(data["training_complete"] / total * 100, 2) if total > 0 else 0,
                average_risk_score=round(
                    sum(data["risk_scores"]) / len(data["risk_scores"]), 2
                ) if data["risk_scores"] else 50
            ))
        
        return sorted(metrics, key=lambda m: m.click_rate, reverse=True)
    
    async def get_high_risk_users(self, threshold: float = 70) -> List[Target]:
        """Get users with high risk scores"""
        return [
            t for t in self.targets.values()
            if t.risk_score >= threshold
        ]
    
    async def get_training_overdue(self) -> List[TrainingAssignment]:
        """Get overdue training assignments"""
        now = datetime.now()
        return [
            a for a in self.assignments.values()
            if a.status in [TrainingStatus.NOT_STARTED, TrainingStatus.IN_PROGRESS]
            and a.due_date < now
        ]
    
    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get overall dashboard statistics"""
        # Calculate overall stats
        total_campaigns = len(self.campaigns)
        active_campaigns = len([
            c for c in self.campaigns.values()
            if c.status == CampaignStatus.RUNNING
        ])
        
        # Aggregate all campaign results
        total_sent = 0
        total_clicked = 0
        total_reported = 0
        
        for campaign in self.campaigns.values():
            for result in campaign.results:
                if result.status != TargetStatus.NOT_SENT:
                    total_sent += 1
                if result.status in [TargetStatus.CLICKED, TargetStatus.SUBMITTED]:
                    total_clicked += 1
                if result.status == TargetStatus.REPORTED:
                    total_reported += 1
        
        # Training stats
        total_assignments = len(self.assignments)
        completed_training = len([
            a for a in self.assignments.values()
            if a.status == TrainingStatus.COMPLETED
        ])
        overdue_training = len(await self.get_training_overdue())
        
        # Risk stats
        high_risk = len(await self.get_high_risk_users())
        avg_risk = sum(t.risk_score for t in self.targets.values()) / len(self.targets) if self.targets else 50
        
        return {
            "total_employees": len(self.targets),
            "total_campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "emails_sent": total_sent,
            "overall_click_rate": round(total_clicked / total_sent * 100, 2) if total_sent > 0 else 0,
            "overall_report_rate": round(total_reported / total_sent * 100, 2) if total_sent > 0 else 0,
            "training_assignments": total_assignments,
            "training_completed": completed_training,
            "training_overdue": overdue_training,
            "training_completion_rate": round(completed_training / total_assignments * 100, 2) if total_assignments > 0 else 0,
            "high_risk_employees": high_risk,
            "average_risk_score": round(avg_risk, 2)
        }
    
    def register_callback(self, event: str, callback: Callable):
        """Register callback for events"""
        if event not in self.callbacks:
            self.callbacks[event] = []
        self.callbacks[event].append(callback)
    
    async def _trigger_callback(self, event: str, data: Any):
        """Trigger callbacks for event"""
        for callback in self.callbacks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as e:
                print(f"Callback error: {e}")
    
    async def _log_event(
        self,
        campaign_id: str,
        target_id: str,
        event_type: str,
        data: Dict
    ):
        """Log campaign event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO campaign_events (campaign_id, target_id, event_type, event_time, data)
            VALUES (?, ?, ?, ?, ?)
        """, (campaign_id, target_id, event_type, datetime.now().isoformat(), json.dumps(data)))
        
        conn.commit()
        conn.close()
    
    async def _save_target(self, target: Target):
        """Save target to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO targets VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            target.id, target.email, target.first_name, target.last_name,
            target.department, target.position, target.manager,
            json.dumps(target.groups), json.dumps(target.custom_fields),
            json.dumps(target.phishing_history), json.dumps(target.training_history),
            target.risk_score,
            datetime.now().isoformat(), datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_campaign(self, campaign: Campaign):
        """Save campaign to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO campaigns VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            campaign.id, campaign.name, campaign.description,
            campaign.campaign_type.value, campaign.status.value,
            campaign.created_by,
            campaign.created_date.isoformat(),
            campaign.scheduled_date.isoformat() if campaign.scheduled_date else None,
            campaign.start_date.isoformat() if campaign.start_date else None,
            campaign.end_date.isoformat() if campaign.end_date else None,
            campaign.template_id, campaign.landing_page_id,
            json.dumps(campaign.target_groups), json.dumps(campaign.targets),
            json.dumps([{
                "target_id": r.target_id,
                "status": r.status.value,
                "sent_time": r.sent_time.isoformat() if r.sent_time else None,
                "opened_time": r.opened_time.isoformat() if r.opened_time else None,
                "clicked_time": r.clicked_time.isoformat() if r.clicked_time else None
            } for r in campaign.results]),
            json.dumps({
                "send_rate": campaign.send_rate,
                "send_order": campaign.send_order,
                "auto_report_training": campaign.auto_report_training
            }),
            datetime.now().isoformat(), datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_assignment(self, assignment: TrainingAssignment):
        """Save training assignment to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO training_assignments VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            assignment.id, assignment.user_id, assignment.module_id,
            assignment.assigned_date.isoformat(),
            assignment.due_date.isoformat(),
            assignment.status.value,
            assignment.started_date.isoformat() if assignment.started_date else None,
            assignment.completed_date.isoformat() if assignment.completed_date else None,
            assignment.score, assignment.attempts, assignment.time_spent_minutes,
            datetime.now().isoformat(), datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
