"""
HydraRecon AI Threat Narrator
Voice-powered AI that explains security findings in real-time with natural language
"""

import asyncio
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import re


class NarrationStyle(Enum):
    """Narration personality styles"""
    PROFESSIONAL = "professional"  # Formal, technical
    CASUAL = "casual"  # Friendly, conversational
    DRAMATIC = "dramatic"  # Urgent, action-movie style
    EDUCATIONAL = "educational"  # Teaching, explanatory
    EXECUTIVE = "executive"  # High-level summary for C-suite
    TACTICAL = "tactical"  # Military/SOC style
    HACKER = "hacker"  # Underground, technical slang


class NarrationPriority(Enum):
    """Priority levels for narration queue"""
    BACKGROUND = 1
    LOW = 2
    NORMAL = 3
    HIGH = 4
    URGENT = 5
    CRITICAL = 6


class NarrationCategory(Enum):
    """Categories of narration content"""
    FINDING = "finding"
    ALERT = "alert"
    STATUS = "status"
    SUMMARY = "summary"
    TUTORIAL = "tutorial"
    WARNING = "warning"
    ACHIEVEMENT = "achievement"
    RECOMMENDATION = "recommendation"


@dataclass
class NarrationSegment:
    """A single narration segment"""
    segment_id: str
    text: str
    ssml: str  # Speech Synthesis Markup Language
    priority: NarrationPriority
    category: NarrationCategory
    style: NarrationStyle
    duration_estimate: float  # seconds
    timestamp: datetime
    context: Dict[str, Any] = field(default_factory=dict)
    audio_file: Optional[str] = None
    spoken: bool = False


@dataclass
class ThreatContext:
    """Context for threat narration"""
    threat_type: str
    severity: str
    target: str
    source: str
    technique: str
    impact: str
    recommendation: str
    related_cves: List[str] = field(default_factory=list)
    related_mitre: List[str] = field(default_factory=list)
    confidence: float = 0.0
    urgency: str = "normal"


class ThreatNarratorEngine:
    """
    AI-powered threat narration engine
    
    Features:
    - Real-time voice narration of security findings
    - Multiple personality styles
    - Context-aware explanations
    - SSML support for natural speech
    - Prioritized narration queue
    - Educational mode for learning
    """
    
    def __init__(self, db_path: str = "narrator.db"):
        self.db_path = db_path
        self.current_style = NarrationStyle.PROFESSIONAL
        self.narration_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.is_speaking = False
        self.is_enabled = True
        self.volume = 1.0
        self.speech_rate = 1.0
        self.voice = "default"
        self.callbacks: List[Callable] = []
        self._initialize_database()
        self._load_templates()
    
    def _initialize_database(self):
        """Initialize narration database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS narration_history (
                segment_id TEXT PRIMARY KEY,
                text TEXT,
                ssml TEXT,
                priority TEXT,
                category TEXT,
                style TEXT,
                duration_estimate REAL,
                timestamp TIMESTAMP,
                context TEXT,
                spoken INTEGER
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_explanations (
                threat_type TEXT PRIMARY KEY,
                short_explanation TEXT,
                detailed_explanation TEXT,
                impact_description TEXT,
                remediation_steps TEXT,
                examples TEXT,
                related_threats TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS narration_stats (
                date TEXT PRIMARY KEY,
                total_narrations INTEGER,
                findings_narrated INTEGER,
                alerts_narrated INTEGER,
                total_duration REAL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _load_templates(self):
        """Load narration templates for different styles"""
        self.templates = {
            NarrationStyle.PROFESSIONAL: {
                "finding_intro": [
                    "Security finding detected: {title}.",
                    "Analysis reveals: {title}.",
                    "Identified vulnerability: {title}.",
                    "Assessment indicates: {title}."
                ],
                "severity_critical": [
                    "This is a critical severity issue requiring immediate attention.",
                    "Critical severity detected. Immediate action recommended.",
                    "This vulnerability is rated critical and poses significant risk."
                ],
                "severity_high": [
                    "This is a high severity finding that should be addressed promptly.",
                    "High severity issue identified. Prioritize remediation.",
                    "This poses a high risk to the system."
                ],
                "severity_medium": [
                    "Medium severity finding. Schedule remediation accordingly.",
                    "This presents a moderate risk level.",
                    "Medium priority issue detected."
                ],
                "severity_low": [
                    "Low severity finding for your awareness.",
                    "Minor issue detected.",
                    "Low risk finding noted."
                ],
                "recommendation": [
                    "Recommended action: {action}.",
                    "To remediate, {action}.",
                    "Suggested mitigation: {action}."
                ],
                "scan_complete": [
                    "Scan complete. {count} findings identified across {targets} targets.",
                    "Assessment finished. Discovered {count} security issues.",
                    "Analysis complete with {count} findings requiring attention."
                ]
            },
            NarrationStyle.DRAMATIC: {
                "finding_intro": [
                    "Alert! We've got a breach indicator: {title}!",
                    "Red alert! Security threat detected: {title}!",
                    "Warning! Hostile activity identified: {title}!",
                    "Incoming! Threat signature matched: {title}!"
                ],
                "severity_critical": [
                    "This is DEFCON 1, people! Critical threat in the system!",
                    "All hands on deck! We have a critical vulnerability!",
                    "Maximum alert level! This could take down the entire network!"
                ],
                "severity_high": [
                    "This is serious. High-level threat detected!",
                    "We've got a significant breach attempt here!",
                    "Elevated threat level! Take action immediately!"
                ],
                "severity_medium": [
                    "Moderate threat detected. Stay vigilant.",
                    "We've got activity. Medium priority threat.",
                    "Something's brewing. Keep your eyes on this one."
                ],
                "severity_low": [
                    "Minor blip on the radar.",
                    "Small fish, but don't ignore it.",
                    "Low-level activity detected."
                ],
                "recommendation": [
                    "Counter-measure: {action}. Execute immediately!",
                    "Defensive protocol: {action}. Move now!",
                    "Neutralize with: {action}!"
                ],
                "scan_complete": [
                    "Mission complete! {count} hostiles identified across {targets} sectors!",
                    "Reconnaissance finished! {count} threats mapped!",
                    "Intel gathered! {count} vulnerabilities in our crosshairs!"
                ]
            },
            NarrationStyle.CASUAL: {
                "finding_intro": [
                    "Hey, found something interesting: {title}.",
                    "Heads up! Spotted: {title}.",
                    "Check this out: {title}.",
                    "Got one for you: {title}."
                ],
                "severity_critical": [
                    "Okay, this one's really bad. You'll want to fix this ASAP.",
                    "Yikes! This is critical. Drop everything.",
                    "Major problem here. Needs immediate attention."
                ],
                "severity_high": [
                    "This is pretty serious. Should deal with it soon.",
                    "Not great news. High severity issue.",
                    "This one's important. Bump it up the priority list."
                ],
                "severity_medium": [
                    "Something to keep an eye on. Medium severity.",
                    "Not urgent, but don't forget about it.",
                    "Moderate issue. Put it on the to-do list."
                ],
                "severity_low": [
                    "Small thing, just FYI.",
                    "Minor finding. No rush.",
                    "Little issue to note."
                ],
                "recommendation": [
                    "Quick fix: {action}.",
                    "Here's what you can do: {action}.",
                    "Try this: {action}."
                ],
                "scan_complete": [
                    "All done! Found {count} things across {targets} targets.",
                    "Finished up. {count} findings to review.",
                    "Scan's done. {count} issues on the list."
                ]
            },
            NarrationStyle.EDUCATIONAL: {
                "finding_intro": [
                    "Let me explain this finding: {title}.",
                    "Here's an educational note about: {title}.",
                    "This is a good learning opportunity: {title}.",
                    "Let's understand: {title}."
                ],
                "severity_critical": [
                    "Critical severity means this vulnerability could allow complete system compromise. In real-world terms, an attacker could take full control.",
                    "A critical rating indicates the highest risk level. These are the vulnerabilities that make headlines.",
                    "When we say critical, we mean this could lead to data breaches, ransomware, or complete system takeover."
                ],
                "severity_high": [
                    "High severity vulnerabilities are serious but may require additional factors to exploit fully.",
                    "A high rating means significant risk. Think of it as one step away from complete compromise.",
                    "High severity issues often lead to significant data exposure or system access."
                ],
                "severity_medium": [
                    "Medium severity means there's a vulnerability, but exploitation is limited or requires specific conditions.",
                    "These findings represent moderate risk. They're important but not immediately catastrophic.",
                    "Medium issues often need to be chained with other vulnerabilities for maximum impact."
                ],
                "severity_low": [
                    "Low severity findings are informational or have minimal direct impact.",
                    "These are good security hygiene items but pose limited immediate risk.",
                    "Low severity doesn't mean ignore it—it means prioritize other things first."
                ],
                "recommendation": [
                    "The recommended fix is: {action}. Let me explain why this works...",
                    "To remediate this: {action}. This addresses the root cause by...",
                    "Best practice here is: {action}. This follows industry standards because..."
                ],
                "scan_complete": [
                    "Scan complete. We found {count} findings across {targets} targets. Let's review what this means for your security posture.",
                    "Analysis finished with {count} discoveries. Each finding represents a potential learning opportunity.",
                    "Assessment complete: {count} items found. Let me help you understand the overall picture."
                ]
            },
            NarrationStyle.EXECUTIVE: {
                "finding_intro": [
                    "Executive summary: {title}.",
                    "Key finding: {title}.",
                    "Business risk identified: {title}.",
                    "Strategic concern: {title}."
                ],
                "severity_critical": [
                    "Business-critical risk. Potential for significant financial and reputational impact.",
                    "This poses immediate risk to business operations and requires executive attention.",
                    "Critical exposure that could result in regulatory penalties and customer impact."
                ],
                "severity_high": [
                    "Significant business risk requiring prompt resource allocation.",
                    "High-priority item for the risk committee.",
                    "Material risk to operations. Budget consideration required."
                ],
                "severity_medium": [
                    "Moderate business impact. Include in quarterly remediation planning.",
                    "Standard risk item for ongoing security program.",
                    "Manageable risk within current security budget."
                ],
                "severity_low": [
                    "Low business impact. Address in regular maintenance cycles.",
                    "Minor item for security hygiene.",
                    "Minimal risk exposure."
                ],
                "recommendation": [
                    "Recommended investment: {action}. Expected ROI in risk reduction.",
                    "Strategic action: {action}. Aligns with compliance requirements.",
                    "Business recommendation: {action}."
                ],
                "scan_complete": [
                    "Assessment complete. {count} risk items identified across {targets} assets. Risk score updated.",
                    "Security posture reviewed: {count} findings affecting business operations.",
                    "Audit finished. {count} items for board-level risk discussion."
                ]
            },
            NarrationStyle.TACTICAL: {
                "finding_intro": [
                    "SITREP: Hostile indicator {title}.",
                    "Intel report: {title}.",
                    "Threat identified: {title}. Assessing.",
                    "Contact: {title}. Analyzing threat vector."
                ],
                "severity_critical": [
                    "Priority Alpha. Immediate response required. All units.",
                    "Code Red. Critical threat. Initiate containment protocols.",
                    "Flash priority. Active compromise indicators. Execute IR playbook."
                ],
                "severity_high": [
                    "Priority Bravo. Elevated threat level. Prepare response teams.",
                    "High alert status. Monitor and prepare countermeasures.",
                    "Significant threat. Allocate resources for remediation."
                ],
                "severity_medium": [
                    "Priority Charlie. Standard threat level. Continue monitoring.",
                    "Moderate contact. Document and track.",
                    "Yellow status. Add to threat register."
                ],
                "severity_low": [
                    "Priority Delta. Low threat. Note for records.",
                    "Minimal contact. Standard logging.",
                    "Green status. Informational only."
                ],
                "recommendation": [
                    "Tactical recommendation: {action}. Execute on authorization.",
                    "Counter-operation: {action}. Await green light.",
                    "Remediation protocol: {action}. Standard operating procedure."
                ],
                "scan_complete": [
                    "Mission complete. {count} contacts across {targets} sectors. Preparing debrief.",
                    "Recon finished. {count} threat indicators mapped. Intel ready for analysis.",
                    "Operation concluded. {count} items for threat assessment."
                ]
            },
            NarrationStyle.HACKER: {
                "finding_intro": [
                    "Yo, check this pwnable: {title}.",
                    "Found a juicy one: {title}.",
                    "Nice! Got: {title}.",
                    "Interesting attack surface: {title}."
                ],
                "severity_critical": [
                    "This is game over territory. Full pwnage potential.",
                    "Root shell waiting to happen. Critical vuln.",
                    "Remote code exec vibes. Ship it to prod, I dare you."
                ],
                "severity_high": [
                    "Solid finding. Could chain this to something nasty.",
                    "Good exploitation potential here.",
                    "High value target. Worth the effort."
                ],
                "severity_medium": [
                    "Decent bug. Might need some creativity.",
                    "Medium difficulty pwn. Needs more recon.",
                    "There's something here. Keep digging."
                ],
                "severity_low": [
                    "Low hanging fruit. Easy points.",
                    "Minor info leak. Better than nothing.",
                    "Small win. Stack 'em up."
                ],
                "recommendation": [
                    "Patch it: {action}. Or don't, I'll find it again.",
                    "Fix: {action}. Basic hygiene, folks.",
                    "Remediate: {action}. Unless you want visitors."
                ],
                "scan_complete": [
                    "Scan done. {count} bugs across {targets} boxes. Time to write reports.",
                    "Recon complete. {count} vulns in the bag.",
                    "Finished the sweep. {count} findings. Not bad."
                ]
            }
        }
        
        # Threat explanations database
        self.threat_explanations = {
            "sql_injection": {
                "short": "SQL injection allows attackers to manipulate database queries",
                "detailed": "SQL injection occurs when user input is not properly sanitized before being included in SQL queries. Attackers can inject malicious SQL code to read, modify, or delete data, and sometimes execute system commands.",
                "impact": "Complete database compromise, data theft, authentication bypass, and potential server takeover",
                "remediation": "Use parameterized queries, prepared statements, and input validation"
            },
            "xss": {
                "short": "Cross-site scripting allows injection of malicious scripts into web pages",
                "detailed": "XSS vulnerabilities occur when applications include untrusted data in web pages without proper validation. Attackers can inject scripts that execute in victims' browsers, stealing cookies, credentials, or performing actions as the victim.",
                "impact": "Session hijacking, credential theft, defacement, malware distribution",
                "remediation": "Encode output, use Content Security Policy, validate and sanitize input"
            },
            "rce": {
                "short": "Remote code execution allows attackers to run arbitrary code on target systems",
                "detailed": "RCE vulnerabilities let attackers execute commands or code on the target system remotely. This is often the most severe class of vulnerability, leading to complete system compromise.",
                "impact": "Full system compromise, data theft, ransomware deployment, lateral movement",
                "remediation": "Patch vulnerable software, implement least privilege, use application firewalls"
            },
            "ssrf": {
                "short": "Server-side request forgery allows attackers to make requests from the server",
                "detailed": "SSRF occurs when attackers can make the server perform HTTP requests to arbitrary destinations. This can be used to scan internal networks, access cloud metadata services, or attack internal services.",
                "impact": "Internal network reconnaissance, cloud credential theft, access to internal services",
                "remediation": "Validate and whitelist allowed URLs, block internal IP ranges, use network segmentation"
            },
            "idor": {
                "short": "Insecure direct object reference allows access to unauthorized resources",
                "detailed": "IDOR occurs when applications expose internal implementation objects like database IDs without proper authorization checks. Attackers can modify identifiers to access other users' data.",
                "impact": "Unauthorized data access, privacy violations, data modification",
                "remediation": "Implement proper authorization checks, use indirect references, validate user permissions"
            }
        }
    
    def set_style(self, style: NarrationStyle):
        """Set the narration style"""
        self.current_style = style
    
    def set_volume(self, volume: float):
        """Set narration volume (0.0 to 1.0)"""
        self.volume = max(0.0, min(1.0, volume))
    
    def set_speech_rate(self, rate: float):
        """Set speech rate (0.5 to 2.0)"""
        self.speech_rate = max(0.5, min(2.0, rate))
    
    def add_callback(self, callback: Callable):
        """Add a callback for narration events"""
        self.callbacks.append(callback)
    
    async def narrate_finding(self, finding: Dict[str, Any], 
                             priority: NarrationPriority = NarrationPriority.NORMAL) -> NarrationSegment:
        """Generate narration for a security finding"""
        import uuid
        
        style_templates = self.templates[self.current_style]
        
        # Build narration text
        title = finding.get("title", "Unknown finding")
        severity = finding.get("severity", "medium").lower()
        description = finding.get("description", "")
        recommendation = finding.get("recommendation", "Review and remediate")
        
        # Select templates
        import random
        intro = random.choice(style_templates["finding_intro"]).format(title=title)
        
        severity_key = f"severity_{severity}"
        severity_text = random.choice(style_templates.get(severity_key, style_templates["severity_medium"]))
        
        rec_text = random.choice(style_templates["recommendation"]).format(action=recommendation)
        
        # Combine into full narration
        full_text = f"{intro} {severity_text} {rec_text}"
        
        # Generate SSML for better speech synthesis
        ssml = self._generate_ssml(full_text, severity)
        
        # Estimate duration (rough: ~150 words per minute)
        word_count = len(full_text.split())
        duration = (word_count / 150) * 60 / self.speech_rate
        
        segment = NarrationSegment(
            segment_id=str(uuid.uuid4()),
            text=full_text,
            ssml=ssml,
            priority=priority,
            category=NarrationCategory.FINDING,
            style=self.current_style,
            duration_estimate=duration,
            timestamp=datetime.now(),
            context=finding
        )
        
        await self._queue_narration(segment)
        return segment
    
    async def narrate_alert(self, alert: Dict[str, Any]) -> NarrationSegment:
        """Generate narration for an alert"""
        import uuid
        
        alert_type = alert.get("type", "security")
        message = alert.get("message", "Alert triggered")
        severity = alert.get("severity", "medium")
        
        if severity in ["critical", "catastrophic"]:
            text = f"ALERT! {message}"
            priority = NarrationPriority.CRITICAL
        elif severity == "high":
            text = f"Warning: {message}"
            priority = NarrationPriority.HIGH
        else:
            text = f"Notice: {message}"
            priority = NarrationPriority.NORMAL
        
        ssml = self._generate_ssml(text, severity)
        
        segment = NarrationSegment(
            segment_id=str(uuid.uuid4()),
            text=text,
            ssml=ssml,
            priority=priority,
            category=NarrationCategory.ALERT,
            style=self.current_style,
            duration_estimate=len(text.split()) / 150 * 60,
            timestamp=datetime.now(),
            context=alert
        )
        
        await self._queue_narration(segment)
        return segment
    
    async def narrate_scan_complete(self, scan_result: Dict[str, Any]) -> NarrationSegment:
        """Generate narration for scan completion"""
        import uuid
        
        style_templates = self.templates[self.current_style]
        
        finding_count = scan_result.get("finding_count", 0)
        target_count = scan_result.get("target_count", 1)
        critical_count = scan_result.get("critical_count", 0)
        
        import random
        base_text = random.choice(style_templates["scan_complete"]).format(
            count=finding_count,
            targets=target_count
        )
        
        if critical_count > 0:
            base_text += f" {critical_count} critical issues require immediate attention."
        
        segment = NarrationSegment(
            segment_id=str(uuid.uuid4()),
            text=base_text,
            ssml=self._generate_ssml(base_text, "info"),
            priority=NarrationPriority.HIGH,
            category=NarrationCategory.STATUS,
            style=self.current_style,
            duration_estimate=len(base_text.split()) / 150 * 60,
            timestamp=datetime.now(),
            context=scan_result
        )
        
        await self._queue_narration(segment)
        return segment
    
    async def narrate_summary(self, summary: Dict[str, Any]) -> NarrationSegment:
        """Generate a summary narration"""
        import uuid
        
        period = summary.get("period", "today")
        total_findings = summary.get("total_findings", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        assets = summary.get("assets_scanned", 0)
        
        text = f"Security summary for {period}. "
        text += f"Scanned {assets} assets and identified {total_findings} findings. "
        
        if critical > 0:
            text += f"{critical} critical and {high} high severity issues need attention. "
        elif high > 0:
            text += f"{high} high severity issues should be prioritized. "
        else:
            text += "No critical or high severity issues at this time. "
        
        segment = NarrationSegment(
            segment_id=str(uuid.uuid4()),
            text=text,
            ssml=self._generate_ssml(text, "info"),
            priority=NarrationPriority.NORMAL,
            category=NarrationCategory.SUMMARY,
            style=self.current_style,
            duration_estimate=len(text.split()) / 150 * 60,
            timestamp=datetime.now(),
            context=summary
        )
        
        await self._queue_narration(segment)
        return segment
    
    async def explain_threat(self, threat_type: str) -> NarrationSegment:
        """Provide educational explanation of a threat type"""
        import uuid
        
        explanation = self.threat_explanations.get(threat_type.lower(), {
            "short": f"A {threat_type} vulnerability",
            "detailed": f"This is a {threat_type} type vulnerability that could impact system security.",
            "impact": "Potential security compromise",
            "remediation": "Follow security best practices"
        })
        
        if self.current_style == NarrationStyle.EDUCATIONAL:
            text = f"Let me explain {threat_type}. {explanation['detailed']} "
            text += f"The impact includes: {explanation['impact']}. "
            text += f"To fix this: {explanation['remediation']}."
        else:
            text = f"{explanation['short']}. {explanation['remediation']}."
        
        segment = NarrationSegment(
            segment_id=str(uuid.uuid4()),
            text=text,
            ssml=self._generate_ssml(text, "info"),
            priority=NarrationPriority.LOW,
            category=NarrationCategory.TUTORIAL,
            style=self.current_style,
            duration_estimate=len(text.split()) / 150 * 60,
            timestamp=datetime.now(),
            context={"threat_type": threat_type, "explanation": explanation}
        )
        
        await self._queue_narration(segment)
        return segment
    
    async def narrate_achievement(self, achievement: Dict[str, Any]) -> NarrationSegment:
        """Narrate a gamification achievement"""
        import uuid
        
        name = achievement.get("name", "Achievement Unlocked")
        description = achievement.get("description", "")
        xp = achievement.get("xp", 0)
        
        text = f"Achievement unlocked: {name}! {description}"
        if xp > 0:
            text += f" You earned {xp} experience points!"
        
        segment = NarrationSegment(
            segment_id=str(uuid.uuid4()),
            text=text,
            ssml=self._generate_ssml(text, "success"),
            priority=NarrationPriority.NORMAL,
            category=NarrationCategory.ACHIEVEMENT,
            style=self.current_style,
            duration_estimate=len(text.split()) / 150 * 60,
            timestamp=datetime.now(),
            context=achievement
        )
        
        await self._queue_narration(segment)
        return segment
    
    def _generate_ssml(self, text: str, tone: str) -> str:
        """Generate SSML markup for better speech synthesis"""
        rate = f"{int(self.speech_rate * 100)}%"
        volume_level = "loud" if self.volume > 0.7 else "medium" if self.volume > 0.3 else "soft"
        
        # Adjust prosody based on tone
        if tone in ["critical", "catastrophic"]:
            pitch = "+10%"
            rate = "fast"
            emphasis = "strong"
        elif tone == "high":
            pitch = "+5%"
            emphasis = "moderate"
        elif tone in ["success", "achievement"]:
            pitch = "+5%"
            emphasis = "moderate"
        else:
            pitch = "0%"
            emphasis = "none"
        
        ssml = f"""<speak>
    <prosody rate="{rate}" pitch="{pitch}" volume="{volume_level}">
        <emphasis level="{emphasis}">{text}</emphasis>
    </prosody>
</speak>"""
        
        return ssml
    
    async def _queue_narration(self, segment: NarrationSegment):
        """Add narration to the queue"""
        # Priority queue uses (priority, timestamp, segment) for ordering
        await self.narration_queue.put((
            -segment.priority.value,  # Negative for max-priority behavior
            segment.timestamp.timestamp(),
            segment
        ))
        
        # Persist to database
        await self._persist_segment(segment)
        
        # Notify callbacks
        for callback in self.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(segment)
                else:
                    callback(segment)
            except Exception as e:
                print(f"Callback error: {e}")
    
    async def _persist_segment(self, segment: NarrationSegment):
        """Persist narration segment to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO narration_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            segment.segment_id,
            segment.text,
            segment.ssml,
            segment.priority.value,
            segment.category.value,
            segment.style.value,
            segment.duration_estimate,
            segment.timestamp.isoformat(),
            json.dumps(segment.context),
            1 if segment.spoken else 0
        ))
        
        conn.commit()
        conn.close()
    
    async def get_next_narration(self) -> Optional[NarrationSegment]:
        """Get the next narration from the queue"""
        if self.narration_queue.empty():
            return None
        
        try:
            _, _, segment = await asyncio.wait_for(
                self.narration_queue.get(),
                timeout=0.1
            )
            return segment
        except asyncio.TimeoutError:
            return None
    
    async def process_queue(self, speech_callback: Callable = None):
        """Process the narration queue continuously"""
        while self.is_enabled:
            try:
                segment = await self.get_next_narration()
                if segment:
                    self.is_speaking = True
                    
                    if speech_callback:
                        if asyncio.iscoroutinefunction(speech_callback):
                            await speech_callback(segment)
                        else:
                            speech_callback(segment)
                    
                    # Wait for estimated duration
                    await asyncio.sleep(segment.duration_estimate)
                    
                    segment.spoken = True
                    await self._persist_segment(segment)
                    
                    self.is_speaking = False
                else:
                    await asyncio.sleep(0.5)
                    
            except Exception as e:
                print(f"Queue processing error: {e}")
                self.is_speaking = False
                await asyncio.sleep(1.0)
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status"""
        return {
            "queue_size": self.narration_queue.qsize(),
            "is_speaking": self.is_speaking,
            "is_enabled": self.is_enabled,
            "current_style": self.current_style.value,
            "volume": self.volume,
            "speech_rate": self.speech_rate
        }
    
    async def get_history(self, limit: int = 50) -> List[NarrationSegment]:
        """Get recent narration history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM narration_history
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        segments = []
        for row in rows:
            segments.append(NarrationSegment(
                segment_id=row[0],
                text=row[1],
                ssml=row[2],
                priority=NarrationPriority(row[3]),
                category=NarrationCategory(row[4]),
                style=NarrationStyle(row[5]),
                duration_estimate=row[6],
                timestamp=datetime.fromisoformat(row[7]),
                context=json.loads(row[8]) if row[8] else {},
                spoken=bool(row[9])
            ))
        
        return segments
    
    def clear_queue(self):
        """Clear the narration queue"""
        while not self.narration_queue.empty():
            try:
                self.narration_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
    
    def enable(self):
        """Enable narration"""
        self.is_enabled = True
    
    def disable(self):
        """Disable narration"""
        self.is_enabled = False
        self.clear_queue()
