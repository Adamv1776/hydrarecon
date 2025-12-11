"""
HydraRecon Advanced Social Engineering Defense Module
Social engineering attack simulation and defense analysis
"""

import asyncio
import hashlib
import json
import os
import re
import random
import string
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging

try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

logger = logging.getLogger(__name__)


class AttackVector(Enum):
    """Social engineering attack vectors"""
    PHISHING_EMAIL = "phishing_email"
    SPEAR_PHISHING = "spear_phishing"
    WHALING = "whaling"
    VISHING = "vishing"
    SMISHING = "smishing"
    PRETEXTING = "pretexting"
    BAITING = "baiting"
    QUID_PRO_QUO = "quid_pro_quo"
    TAILGATING = "tailgating"
    IMPERSONATION = "impersonation"
    WATERING_HOLE = "watering_hole"
    BUSINESS_EMAIL_COMPROMISE = "bec"
    USB_DROP = "usb_drop"
    SOCIAL_MEDIA = "social_media"


class PhishingCategory(Enum):
    """Phishing email categories"""
    CREDENTIAL_HARVEST = "credential_harvest"
    MALWARE_DELIVERY = "malware_delivery"
    DATA_THEFT = "data_theft"
    WIRE_FRAUD = "wire_fraud"
    GIFT_CARD_SCAM = "gift_card_scam"
    TECH_SUPPORT = "tech_support"
    TAX_SCAM = "tax_scam"
    COVID_THEMED = "covid_themed"
    INVOICE_FRAUD = "invoice_fraud"
    PACKAGE_DELIVERY = "package_delivery"


class DifficultyLevel(Enum):
    """Attack difficulty level"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class RiskLevel(Enum):
    """Risk assessment level"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PhishingTemplate:
    """Phishing email template"""
    template_id: str
    name: str
    category: PhishingCategory
    difficulty: DifficultyLevel
    subject: str
    body: str
    sender_name: str
    sender_domain: str
    landing_page: Optional[str] = None
    attachments: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    training_tips: List[str] = field(default_factory=list)


@dataclass
class PhishingCampaign:
    """Phishing simulation campaign"""
    campaign_id: str
    name: str
    template: PhishingTemplate
    targets: List[str]
    start_time: datetime
    end_time: Optional[datetime] = None
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_submitted: int = 0
    reports_received: int = 0
    status: str = "draft"


@dataclass
class PhishingResult:
    """Phishing simulation result"""
    campaign_id: str
    target_email: str
    email_sent_at: Optional[datetime] = None
    email_opened_at: Optional[datetime] = None
    link_clicked_at: Optional[datetime] = None
    credentials_submitted_at: Optional[datetime] = None
    reported_at: Optional[datetime] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass
class EmailAnalysis:
    """Email security analysis result"""
    email_id: str
    sender: str
    subject: str
    is_phishing: bool
    confidence: float
    risk_level: RiskLevel
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.now)


@dataclass
class VulnerableUser:
    """User vulnerability profile"""
    user_id: str
    email: str
    name: Optional[str] = None
    department: Optional[str] = None
    click_rate: float = 0.0
    report_rate: float = 0.0
    training_completed: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    simulation_history: List[Dict[str, Any]] = field(default_factory=list)


class PhishingTemplateGenerator:
    """Generate phishing email templates"""
    
    def __init__(self):
        self.templates = self._load_default_templates()
        
    def _load_default_templates(self) -> Dict[str, PhishingTemplate]:
        """Load default phishing templates"""
        templates = {}
        
        # Password Reset Template
        templates['password_reset'] = PhishingTemplate(
            template_id='password_reset',
            name='IT Password Reset',
            category=PhishingCategory.CREDENTIAL_HARVEST,
            difficulty=DifficultyLevel.EASY,
            subject='Urgent: Your password will expire in 24 hours',
            body='''Dear {{first_name}},

Your corporate password will expire in 24 hours. To avoid losing access to your account, please reset your password immediately by clicking the link below:

[Reset Password Now]

If you do not reset your password, your account will be locked and you will need to contact IT support.

Best regards,
IT Security Team
{{company_name}}

This is an automated message. Please do not reply.''',
            sender_name='IT Security Team',
            sender_domain='it-security-{{company_domain}}',
            indicators=[
                'Urgency/pressure tactics',
                'Generic greeting possible',
                'Suspicious sender domain',
                'Link to external site'
            ],
            training_tips=[
                'Verify password reset requests through official IT channels',
                'Check the sender email address carefully',
                'Look for urgency language designed to pressure you',
                'Hover over links before clicking'
            ]
        )
        
        # Microsoft 365 Template
        templates['m365_login'] = PhishingTemplate(
            template_id='m365_login',
            name='Microsoft 365 Login Alert',
            category=PhishingCategory.CREDENTIAL_HARVEST,
            difficulty=DifficultyLevel.MEDIUM,
            subject='[Microsoft 365] Unusual sign-in activity detected',
            body='''Microsoft
━━━━━━━━━━━━━━━━━━━━

Unusual sign-in activity

We detected something unusual about a recent sign-in to your Microsoft account.

Sign-in details:
• Country/region: Russia
• IP address: 185.xxx.xxx.xxx
• Date: {{current_date}}
• Platform: Windows
• Browser: Chrome

If this was you, you can ignore this message. If you didn't sign in recently, your account may be compromised.

[Review recent activity]

Thanks,
The Microsoft account team

━━━━━━━━━━━━━━━━━━━━
Microsoft Privacy Statement''',
            sender_name='Microsoft Account Team',
            sender_domain='account-security-microsoft.com',
            indicators=[
                'Suspicious domain (not microsoft.com)',
                'Fear-inducing content',
                'Urgency to click immediately',
                'IP address from "suspicious" location'
            ],
            training_tips=[
                'Microsoft emails come from microsoft.com domains',
                'Go directly to microsoft.com to check account activity',
                'Real security alerts provide more context',
                'Verify through official Microsoft Security portal'
            ]
        )
        
        # Invoice/Payment Template
        templates['invoice_due'] = PhishingTemplate(
            template_id='invoice_due',
            name='Urgent Invoice Payment',
            category=PhishingCategory.INVOICE_FRAUD,
            difficulty=DifficultyLevel.HARD,
            subject='RE: Invoice #{{invoice_number}} - Payment Required',
            body='''Hi {{first_name}},

I hope this email finds you well. I'm following up on invoice #{{invoice_number}} which was due on {{due_date}}.

Our records show this invoice remains unpaid. To avoid any late fees and service interruption, please process this payment at your earliest convenience.

Payment Details:
Amount Due: ${{amount}}
Due Date: {{due_date}}
Invoice: See attached

For your convenience, you can pay directly through our secure payment portal:
[Pay Now]

If you have already made this payment, please disregard this notice and accept our apologies.

Best regards,
{{fake_name}}
Accounts Receivable
{{fake_company}}
Tel: {{fake_phone}}''',
            sender_name='Accounts Receivable',
            sender_domain='billing-{{similar_company}}.com',
            attachments=['Invoice_{{invoice_number}}.pdf.exe'],
            indicators=[
                'Attachment with hidden extension',
                'Urgency about payment',
                'External payment portal link',
                'Slight domain variation'
            ],
            training_tips=[
                'Verify invoice requests through known contacts',
                'Check file extensions carefully',
                'Be wary of payment portal links in emails',
                'Confirm banking details through phone call'
            ]
        )
        
        # CEO Fraud/BEC Template
        templates['ceo_request'] = PhishingTemplate(
            template_id='ceo_request',
            name='CEO Urgent Request',
            category=PhishingCategory.WIRE_FRAUD,
            difficulty=DifficultyLevel.EXPERT,
            subject='Urgent - Need your help',
            body='''{{first_name}},

Are you at your desk? I need you to handle something for me urgently and confidentially.

I'm in back-to-back meetings all day and can't make calls. I need you to process a wire transfer for a time-sensitive acquisition we're closing today. This needs to stay confidential until the deal is announced.

Can you handle this for me? Let me know and I'll send the details.

Thanks,
{{ceo_name}}

Sent from my iPhone''',
            sender_name='{{ceo_name}}',
            sender_domain='{{ceo_name_lower}}-personal.com',
            indicators=[
                'Unusual request channel',
                'Extreme urgency',
                'Request for confidentiality',
                'Inability to call/meet in person',
                'Sent from mobile (excuse for informal tone)'
            ],
            training_tips=[
                'Always verify unusual financial requests by phone',
                'Executives won\'t bypass normal approval processes',
                'Confidentiality requests are red flags',
                'Check email headers for actual sender domain'
            ]
        )
        
        # Package Delivery Template
        templates['package_delivery'] = PhishingTemplate(
            template_id='package_delivery',
            name='Package Delivery Notification',
            category=PhishingCategory.MALWARE_DELIVERY,
            difficulty=DifficultyLevel.EASY,
            subject='Your package could not be delivered - Action Required',
            body='''UPS Delivery Notification

Hello,

We attempted to deliver your package today but were unable to complete the delivery.

Tracking Number: 1Z999AA10123456784
Scheduled Delivery: {{current_date}}
Status: DELIVERY EXCEPTION

To reschedule your delivery or pick up at a UPS location, please verify your address:

[Verify Delivery Address]

If we don't hear from you within 48 hours, your package will be returned to the sender.

UPS Customer Service
1-800-742-5877''',
            sender_name='UPS Delivery',
            sender_domain='ups-delivery-notification.com',
            indicators=[
                'Fake delivery company domain',
                'No specific package information',
                'Urgency with 48-hour deadline',
                'Link to verify/reschedule'
            ],
            training_tips=[
                'Check tracking directly on ups.com',
                'Real UPS emails come from ups.com',
                'Be suspicious of delivery issues for unknown packages',
                'Call UPS directly if unsure'
            ]
        )
        
        # DocuSign Template
        templates['docusign'] = PhishingTemplate(
            template_id='docusign',
            name='DocuSign Document Request',
            category=PhishingCategory.CREDENTIAL_HARVEST,
            difficulty=DifficultyLevel.MEDIUM,
            subject='{{sender_name}} sent you a document to review and sign',
            body='''DocuSign

{{sender_name}} ({{sender_email}}) sent you a document to review and sign.

REVIEW DOCUMENT

Document: {{document_name}}
Security Code: {{security_code}}

This message was sent to you by {{sender_name}} who is using the DocuSign Electronic Signature Service.

If you'd rather not receive email from this sender, you may report it to DocuSign''',
            sender_name='DocuSign',
            sender_domain='docus1gn.com',
            indicators=[
                'Typosquatted domain',
                'Generic document request',
                'Security code in email',
                'Review document button'
            ],
            training_tips=[
                'Verify DocuSign emails come from docusign.com',
                'Check if you\'re expecting a document',
                'Log into DocuSign directly to view documents',
                'Look for subtle domain misspellings'
            ]
        )
        
        return templates
        
    def generate_template(self, category: PhishingCategory, 
                         difficulty: DifficultyLevel,
                         context: Dict[str, str]) -> PhishingTemplate:
        """Generate customized phishing template"""
        # Find matching template
        for template in self.templates.values():
            if template.category == category and template.difficulty == difficulty:
                return self._customize_template(template, context)
                
        # Generate new template if no match
        return self._create_custom_template(category, difficulty, context)
        
    def _customize_template(self, template: PhishingTemplate, 
                           context: Dict[str, str]) -> PhishingTemplate:
        """Customize template with context"""
        if not JINJA_AVAILABLE:
            return template
            
        # Render subject
        subject_template = Template(template.subject)
        subject = subject_template.render(**context)
        
        # Render body
        body_template = Template(template.body)
        body = body_template.render(**context)
        
        return PhishingTemplate(
            template_id=f"{template.template_id}_{hashlib.md5(str(context).encode()).hexdigest()[:8]}",
            name=template.name,
            category=template.category,
            difficulty=template.difficulty,
            subject=subject,
            body=body,
            sender_name=template.sender_name,
            sender_domain=template.sender_domain,
            landing_page=template.landing_page,
            attachments=template.attachments,
            indicators=template.indicators,
            training_tips=template.training_tips
        )
        
    def _create_custom_template(self, category: PhishingCategory,
                               difficulty: DifficultyLevel,
                               context: Dict[str, str]) -> PhishingTemplate:
        """Create custom template based on parameters"""
        return PhishingTemplate(
            template_id=f"custom_{hashlib.md5(str(context).encode()).hexdigest()[:8]}",
            name="Custom Template",
            category=category,
            difficulty=difficulty,
            subject="Action Required",
            body="Custom phishing content",
            sender_name="Unknown",
            sender_domain="suspicious.com",
            indicators=["Custom template"],
            training_tips=["Review email carefully"]
        )


class EmailSecurityAnalyzer:
    """Analyze emails for phishing indicators"""
    
    def __init__(self):
        self.indicators = self._load_indicators()
        self.safe_domains = self._load_safe_domains()
        
    def _load_indicators(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load phishing indicators"""
        return {
            'urgent_language': [
                {'pattern': r'\burgent\b', 'weight': 0.3, 'description': 'Contains "urgent"'},
                {'pattern': r'\bimmediately\b', 'weight': 0.3, 'description': 'Contains "immediately"'},
                {'pattern': r'\basap\b', 'weight': 0.2, 'description': 'Contains "ASAP"'},
                {'pattern': r'\bexpir(e|ed|ing|es)\b', 'weight': 0.3, 'description': 'Mentions expiration'},
                {'pattern': r'\b(suspend|lock|disable)\b', 'weight': 0.4, 'description': 'Account threat'},
                {'pattern': r'\b24\s*(hours?|hrs?)\b', 'weight': 0.3, 'description': 'Time pressure'},
            ],
            'credential_requests': [
                {'pattern': r'\b(password|passwd|pwd)\b', 'weight': 0.3, 'description': 'Mentions password'},
                {'pattern': r'\b(login|log\s*in|signin|sign\s*in)\b', 'weight': 0.2, 'description': 'Login reference'},
                {'pattern': r'\b(verify|confirm|validate)\s+your\b', 'weight': 0.4, 'description': 'Verification request'},
                {'pattern': r'\b(username|user\s*name|email)\s*(and|&)\s*(password|passwd)\b', 'weight': 0.5, 'description': 'Credential request'},
                {'pattern': r'\bsecurity\s*(code|question|answer)\b', 'weight': 0.3, 'description': 'Security info request'},
            ],
            'financial_indicators': [
                {'pattern': r'\bwire\s*transfer\b', 'weight': 0.5, 'description': 'Wire transfer mention'},
                {'pattern': r'\binvoice\b', 'weight': 0.2, 'description': 'Invoice mention'},
                {'pattern': r'\b(payment|pay)\b', 'weight': 0.2, 'description': 'Payment reference'},
                {'pattern': r'\bgift\s*card\b', 'weight': 0.5, 'description': 'Gift card mention'},
                {'pattern': r'\$\d+', 'weight': 0.1, 'description': 'Money amount'},
            ],
            'suspicious_links': [
                {'pattern': r'https?://bit\.ly/', 'weight': 0.4, 'description': 'Shortened URL'},
                {'pattern': r'https?://tinyurl\.com/', 'weight': 0.4, 'description': 'Shortened URL'},
                {'pattern': r'https?://[^/]*\d+\.[^/]*/', 'weight': 0.3, 'description': 'IP-based URL'},
                {'pattern': r'https?://[^/]*@', 'weight': 0.5, 'description': 'URL with credentials'},
                {'pattern': r'https?://[^/]*-[^/]*-[^/]*\.', 'weight': 0.3, 'description': 'Hyphenated domain'},
            ],
            'impersonation': [
                {'pattern': r'\b(microsoft|google|apple|amazon|paypal|netflix)\b', 'weight': 0.2, 'description': 'Brand mention'},
                {'pattern': r'\b(account\s*team|security\s*team|support\s*team)\b', 'weight': 0.2, 'description': 'Team impersonation'},
                {'pattern': r'\bsent\s*from\s*my\s*(iphone|ipad|android)\b', 'weight': 0.2, 'description': 'Mobile signature'},
            ],
            'attachment_threats': [
                {'pattern': r'\.exe(\b|$)', 'weight': 0.5, 'description': 'Executable attachment'},
                {'pattern': r'\.scr(\b|$)', 'weight': 0.5, 'description': 'Screensaver attachment'},
                {'pattern': r'\.zip(\b|$)', 'weight': 0.2, 'description': 'Archive attachment'},
                {'pattern': r'\.doc[xm]?(\b|$)', 'weight': 0.2, 'description': 'Office document'},
                {'pattern': r'\.js(\b|$)', 'weight': 0.5, 'description': 'JavaScript attachment'},
                {'pattern': r'password\s*(protected|required)', 'weight': 0.3, 'description': 'Password protected file'},
            ],
        }
        
    def _load_safe_domains(self) -> Set[str]:
        """Load known safe domains"""
        return {
            'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
            'paypal.com', 'netflix.com', 'docusign.com', 'adobe.com',
            'dropbox.com', 'salesforce.com', 'slack.com', 'zoom.us',
            'office.com', 'live.com', 'outlook.com', 'onedrive.com',
            'github.com', 'linkedin.com', 'twitter.com', 'facebook.com',
        }
        
    def analyze_email(self, sender: str, subject: str, body: str,
                     headers: Optional[Dict[str, str]] = None,
                     attachments: Optional[List[str]] = None) -> EmailAnalysis:
        """Analyze email for phishing indicators"""
        found_indicators = []
        total_score = 0.0
        
        # Combine subject and body for analysis
        content = f"{subject}\n{body}".lower()
        
        # Check all indicator categories
        for category, patterns in self.indicators.items():
            for indicator in patterns:
                if re.search(indicator['pattern'], content, re.IGNORECASE):
                    found_indicators.append({
                        'category': category,
                        'description': indicator['description'],
                        'weight': indicator['weight']
                    })
                    total_score += indicator['weight']
                    
        # Check sender domain
        sender_domain = self._extract_domain(sender)
        if sender_domain:
            # Check for typosquatting
            typosquat_score = self._check_typosquatting(sender_domain)
            if typosquat_score > 0:
                found_indicators.append({
                    'category': 'domain',
                    'description': f'Possible typosquatting: {sender_domain}',
                    'weight': typosquat_score
                })
                total_score += typosquat_score
                
            # Check if domain is in safe list
            if sender_domain in self.safe_domains:
                total_score -= 0.5  # Reduce score for known safe domains
                
        # Check attachments
        if attachments:
            for attachment in attachments:
                for indicator in self.indicators['attachment_threats']:
                    if re.search(indicator['pattern'], attachment, re.IGNORECASE):
                        found_indicators.append({
                            'category': 'attachment',
                            'description': f'Suspicious attachment: {attachment}',
                            'weight': indicator['weight']
                        })
                        total_score += indicator['weight']
                        
        # Check headers
        if headers:
            header_issues = self._analyze_headers(headers)
            found_indicators.extend(header_issues)
            for issue in header_issues:
                total_score += issue.get('weight', 0.1)
                
        # Normalize score
        confidence = min(total_score / 3.0, 1.0)  # 3.0 is ~100% confidence threshold
        
        # Determine risk level
        if confidence >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif confidence >= 0.6:
            risk_level = RiskLevel.HIGH
        elif confidence >= 0.4:
            risk_level = RiskLevel.MEDIUM
        elif confidence >= 0.2:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO
            
        # Generate recommendations
        recommendations = self._generate_recommendations(found_indicators)
        
        return EmailAnalysis(
            email_id=hashlib.md5(f"{sender}{subject}".encode()).hexdigest()[:12],
            sender=sender,
            subject=subject,
            is_phishing=confidence >= 0.5,
            confidence=confidence,
            risk_level=risk_level,
            indicators=found_indicators,
            recommendations=recommendations
        )
        
    def _extract_domain(self, email: str) -> Optional[str]:
        """Extract domain from email address"""
        match = re.search(r'@([a-zA-Z0-9.-]+)', email)
        return match.group(1).lower() if match else None
        
    def _check_typosquatting(self, domain: str) -> float:
        """Check for domain typosquatting"""
        typosquat_patterns = {
            'microsft.com': 0.8,
            'microsooft.com': 0.8,
            'micros0ft.com': 0.8,
            'googIe.com': 0.8,
            'g00gle.com': 0.8,
            'amaz0n.com': 0.8,
            'amazonn.com': 0.8,
            'paypa1.com': 0.8,
            'paypall.com': 0.8,
            'app1e.com': 0.8,
            'dropb0x.com': 0.8,
            'netf1ix.com': 0.8,
        }
        
        # Check exact matches
        if domain in typosquat_patterns:
            return typosquat_patterns[domain]
            
        # Check for suspicious patterns
        for safe_domain in self.safe_domains:
            base = safe_domain.split('.')[0]
            if base in domain and domain != safe_domain:
                # Levenshtein-like check
                if self._similarity(base, domain.split('.')[0]) > 0.7:
                    return 0.6
                    
        return 0.0
        
    def _similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity"""
        if s1 == s2:
            return 1.0
        len1, len2 = len(s1), len(s2)
        if not len1 or not len2:
            return 0.0
        common = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        return common / max(len1, len2)
        
    def _analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze email headers for issues"""
        issues = []
        
        # Check SPF
        spf = headers.get('Received-SPF', '').lower()
        if 'fail' in spf or 'softfail' in spf:
            issues.append({
                'category': 'authentication',
                'description': 'SPF check failed',
                'weight': 0.4
            })
            
        # Check DKIM
        dkim = headers.get('DKIM-Signature', '')
        if not dkim:
            issues.append({
                'category': 'authentication',
                'description': 'No DKIM signature',
                'weight': 0.2
            })
            
        # Check for header inconsistencies
        from_header = headers.get('From', '')
        reply_to = headers.get('Reply-To', '')
        if reply_to and from_header:
            from_domain = self._extract_domain(from_header)
            reply_domain = self._extract_domain(reply_to)
            if from_domain != reply_domain:
                issues.append({
                    'category': 'header',
                    'description': 'Reply-To domain differs from From domain',
                    'weight': 0.4
                })
                
        return issues
        
    def _generate_recommendations(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        categories = set(i['category'] for i in indicators)
        
        if 'urgent_language' in categories:
            recommendations.append("Don't be pressured by urgent language - verify through official channels")
        if 'credential_requests' in categories:
            recommendations.append("Never enter credentials from email links - go directly to the website")
        if 'financial_indicators' in categories:
            recommendations.append("Verify financial requests by phone using known contact numbers")
        if 'suspicious_links' in categories:
            recommendations.append("Don't click shortened or suspicious links - verify the actual destination")
        if 'attachment' in categories:
            recommendations.append("Don't open unexpected attachments, especially executables")
        if 'domain' in categories:
            recommendations.append("Check sender email addresses carefully for slight misspellings")
        if 'authentication' in categories:
            recommendations.append("This email failed authentication checks - treat with caution")
            
        if not recommendations:
            recommendations.append("Email appears legitimate but always verify unexpected requests")
            
        return recommendations


class SecurityAwarenessTraining:
    """Security awareness training management"""
    
    def __init__(self):
        self.training_modules = self._load_training_modules()
        self.user_progress: Dict[str, Dict[str, Any]] = {}
        
    def _load_training_modules(self) -> Dict[str, Dict[str, Any]]:
        """Load training modules"""
        return {
            'phishing_basics': {
                'id': 'phishing_basics',
                'title': 'Phishing Fundamentals',
                'description': 'Learn to identify common phishing attacks',
                'duration_minutes': 15,
                'topics': [
                    'What is phishing?',
                    'Common phishing techniques',
                    'How to spot phishing emails',
                    'Safe email practices'
                ],
                'quiz_questions': [
                    {
                        'question': 'What should you do if you receive an urgent email asking for your password?',
                        'options': [
                            'Reply with your password immediately',
                            'Click the link and enter your password',
                            'Contact IT through official channels to verify',
                            'Forward it to your colleagues'
                        ],
                        'correct': 2
                    },
                    {
                        'question': 'Which is a sign of a phishing email?',
                        'options': [
                            'Email from your known colleague',
                            'Slight misspelling in sender domain',
                            'Email with company logo',
                            'Email sent during business hours'
                        ],
                        'correct': 1
                    }
                ]
            },
            'bec_awareness': {
                'id': 'bec_awareness',
                'title': 'Business Email Compromise',
                'description': 'Understand and prevent CEO fraud and BEC attacks',
                'duration_minutes': 20,
                'topics': [
                    'What is BEC?',
                    'Common BEC scenarios',
                    'Wire fraud prevention',
                    'Verification procedures'
                ],
                'quiz_questions': [
                    {
                        'question': 'Your CEO emails asking for an urgent wire transfer. What should you do?',
                        'options': [
                            'Process it immediately since it\'s from the CEO',
                            'Ask a colleague to process it',
                            'Call the CEO using a known phone number to verify',
                            'Reply asking for more details'
                        ],
                        'correct': 2
                    }
                ]
            },
            'password_security': {
                'id': 'password_security',
                'title': 'Password Security Best Practices',
                'description': 'Learn to create and manage secure passwords',
                'duration_minutes': 10,
                'topics': [
                    'Creating strong passwords',
                    'Password managers',
                    'Multi-factor authentication',
                    'Avoiding password reuse'
                ],
                'quiz_questions': []
            },
            'social_engineering': {
                'id': 'social_engineering',
                'title': 'Social Engineering Defense',
                'description': 'Recognize and resist social engineering attacks',
                'duration_minutes': 25,
                'topics': [
                    'Types of social engineering',
                    'Psychological manipulation tactics',
                    'Pretexting and impersonation',
                    'Physical security awareness'
                ],
                'quiz_questions': []
            }
        }
        
    def assign_training(self, user_email: str, module_id: str):
        """Assign training module to user"""
        if user_email not in self.user_progress:
            self.user_progress[user_email] = {
                'assigned_modules': [],
                'completed_modules': [],
                'quiz_scores': {}
            }
            
        if module_id not in self.user_progress[user_email]['assigned_modules']:
            self.user_progress[user_email]['assigned_modules'].append(module_id)
            
    def complete_training(self, user_email: str, module_id: str, quiz_score: float = 1.0):
        """Mark training as completed"""
        if user_email in self.user_progress:
            if module_id not in self.user_progress[user_email]['completed_modules']:
                self.user_progress[user_email]['completed_modules'].append(module_id)
            self.user_progress[user_email]['quiz_scores'][module_id] = quiz_score
            
    def get_user_status(self, user_email: str) -> Dict[str, Any]:
        """Get user's training status"""
        if user_email not in self.user_progress:
            return {
                'assigned': 0,
                'completed': 0,
                'pending': 0,
                'average_score': 0.0
            }
            
        progress = self.user_progress[user_email]
        completed = len(progress['completed_modules'])
        assigned = len(progress['assigned_modules'])
        
        avg_score = 0.0
        if progress['quiz_scores']:
            avg_score = sum(progress['quiz_scores'].values()) / len(progress['quiz_scores'])
            
        return {
            'assigned': assigned,
            'completed': completed,
            'pending': assigned - completed,
            'average_score': avg_score,
            'completed_modules': progress['completed_modules']
        }


class SocialEngineeringDefense:
    """Main social engineering defense integration"""
    
    def __init__(self):
        self.template_generator = PhishingTemplateGenerator()
        self.email_analyzer = EmailSecurityAnalyzer()
        self.training = SecurityAwarenessTraining()
        self.campaigns: Dict[str, PhishingCampaign] = {}
        self.user_profiles: Dict[str, VulnerableUser] = {}
        
    def analyze_email(self, sender: str, subject: str, body: str,
                     headers: Optional[Dict[str, str]] = None,
                     attachments: Optional[List[str]] = None) -> EmailAnalysis:
        """Analyze email for phishing"""
        return self.email_analyzer.analyze_email(
            sender, subject, body, headers, attachments
        )
        
    def create_campaign(self, name: str, template_id: str,
                       targets: List[str]) -> PhishingCampaign:
        """Create phishing simulation campaign"""
        template = self.template_generator.templates.get(template_id)
        if not template:
            raise ValueError(f"Template not found: {template_id}")
            
        campaign = PhishingCampaign(
            campaign_id=hashlib.md5(f"{name}{datetime.now()}".encode()).hexdigest()[:12],
            name=name,
            template=template,
            targets=targets,
            start_time=datetime.now(),
            status='draft'
        )
        
        self.campaigns[campaign.campaign_id] = campaign
        return campaign
        
    def get_user_risk_score(self, email: str) -> float:
        """Calculate user risk score"""
        if email not in self.user_profiles:
            return 0.5  # Default moderate risk
            
        user = self.user_profiles[email]
        
        # Calculate based on click rate and training
        click_factor = user.click_rate * 0.5
        report_factor = (1 - user.report_rate) * 0.2
        training_factor = 0.3 if not user.training_completed else 0.0
        
        return min(click_factor + report_factor + training_factor, 1.0)
        
    def generate_report(self, campaign_id: str) -> str:
        """Generate campaign report"""
        if campaign_id not in self.campaigns:
            return "Campaign not found"
            
        campaign = self.campaigns[campaign_id]
        
        report = []
        report.append("=" * 60)
        report.append("PHISHING SIMULATION REPORT")
        report.append("=" * 60)
        
        report.append(f"\nCampaign: {campaign.name}")
        report.append(f"Status: {campaign.status}")
        report.append(f"Start: {campaign.start_time}")
        
        report.append(f"\n{'=' * 40}")
        report.append("METRICS")
        report.append("=" * 40)
        
        report.append(f"Emails Sent: {campaign.emails_sent}")
        report.append(f"Emails Opened: {campaign.emails_opened}")
        report.append(f"Links Clicked: {campaign.links_clicked}")
        report.append(f"Credentials Submitted: {campaign.credentials_submitted}")
        report.append(f"Reports Received: {campaign.reports_received}")
        
        if campaign.emails_sent > 0:
            report.append(f"\nOpen Rate: {(campaign.emails_opened / campaign.emails_sent) * 100:.1f}%")
            report.append(f"Click Rate: {(campaign.links_clicked / campaign.emails_sent) * 100:.1f}%")
            report.append(f"Submit Rate: {(campaign.credentials_submitted / campaign.emails_sent) * 100:.1f}%")
            report.append(f"Report Rate: {(campaign.reports_received / campaign.emails_sent) * 100:.1f}%")
            
        report.append(f"\n{'=' * 40}")
        report.append("TEMPLATE INFO")
        report.append("=" * 40)
        
        template = campaign.template
        report.append(f"Template: {template.name}")
        report.append(f"Category: {template.category.value}")
        report.append(f"Difficulty: {template.difficulty.value}")
        
        report.append(f"\nIndicators to Look For:")
        for indicator in template.indicators:
            report.append(f"  • {indicator}")
            
        report.append(f"\nTraining Tips:")
        for tip in template.training_tips:
            report.append(f"  • {tip}")
            
        return "\n".join(report)
