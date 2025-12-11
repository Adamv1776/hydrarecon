"""
HydraRecon Gamification Engine
XP, achievements, leaderboards, and challenges for team motivation
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import hashlib


class AchievementCategory(Enum):
    """Categories of achievements"""
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    PERSISTENCE = "persistence"
    EVASION = "evasion"
    REPORTING = "reporting"
    COLLABORATION = "collaboration"
    LEARNING = "learning"
    SPEED = "speed"
    ACCURACY = "accuracy"
    DEDICATION = "dedication"
    MASTERY = "mastery"
    SPECIAL = "special"


class AchievementRarity(Enum):
    """Rarity levels for achievements"""
    COMMON = "common"
    UNCOMMON = "uncommon"
    RARE = "rare"
    EPIC = "epic"
    LEGENDARY = "legendary"
    MYTHIC = "mythic"


class RankTier(Enum):
    """Rank tiers for users"""
    SCRIPT_KIDDIE = "Script Kiddie"
    JUNIOR_ANALYST = "Junior Analyst"
    SECURITY_ANALYST = "Security Analyst"
    PENETRATION_TESTER = "Penetration Tester"
    SENIOR_PENTESTER = "Senior Pentester"
    RED_TEAM_OPERATOR = "Red Team Operator"
    SECURITY_RESEARCHER = "Security Researcher"
    EXPLOIT_DEVELOPER = "Exploit Developer"
    APT_HUNTER = "APT Hunter"
    CYBER_LEGEND = "Cyber Legend"


class ChallengeType(Enum):
    """Types of challenges"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    SEASONAL = "seasonal"
    SPECIAL_EVENT = "special_event"
    COMMUNITY = "community"


class ChallengeStatus(Enum):
    """Status of a challenge"""
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class Achievement:
    """An unlockable achievement"""
    achievement_id: str
    name: str
    description: str
    category: AchievementCategory
    rarity: AchievementRarity
    xp_reward: int
    icon: str
    secret: bool = False
    repeatable: bool = False
    max_progress: int = 1
    conditions: Dict[str, Any] = field(default_factory=dict)
    rewards: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class UserAchievement:
    """A user's progress on an achievement"""
    user_id: str
    achievement_id: str
    progress: int = 0
    completed: bool = False
    completed_at: Optional[datetime] = None
    times_completed: int = 0


@dataclass
class Challenge:
    """A time-limited challenge"""
    challenge_id: str
    name: str
    description: str
    challenge_type: ChallengeType
    start_time: datetime
    end_time: datetime
    objectives: List[Dict[str, Any]]
    xp_reward: int
    bonus_rewards: List[Dict[str, Any]] = field(default_factory=list)
    participants: List[str] = field(default_factory=list)
    leaderboard: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class UserChallenge:
    """A user's progress on a challenge"""
    user_id: str
    challenge_id: str
    status: ChallengeStatus
    progress: Dict[str, int] = field(default_factory=dict)
    score: int = 0
    completed_at: Optional[datetime] = None


@dataclass
class UserProfile:
    """User's gamification profile"""
    user_id: str
    username: str
    avatar: str
    xp: int = 0
    level: int = 1
    rank: RankTier = RankTier.SCRIPT_KIDDIE
    achievements_unlocked: List[str] = field(default_factory=list)
    badges: List[str] = field(default_factory=list)
    titles: List[str] = field(default_factory=list)
    active_title: str = ""
    stats: Dict[str, int] = field(default_factory=dict)
    streak_days: int = 0
    last_active: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class LeaderboardEntry:
    """Entry in a leaderboard"""
    user_id: str
    username: str
    score: int
    rank: int
    change: int = 0  # Position change from last period
    avatar: str = ""
    title: str = ""


class GamificationEngine:
    """
    Gamification engine for security operations
    
    Features:
    - XP and leveling system
    - Achievements and badges
    - Daily/weekly challenges
    - Leaderboards
    - Streaks and bonuses
    - Team competitions
    """
    
    def __init__(self, db_path: str = "gamification.db"):
        self.db_path = db_path
        self.achievements: Dict[str, Achievement] = {}
        self.challenges: Dict[str, Challenge] = {}
        self.users: Dict[str, UserProfile] = {}
        self.event_handlers: List[Callable] = []
        self._initialize_database()
        self._load_achievements()
        self._generate_challenges()
    
    def _initialize_database(self):
        """Initialize the gamification database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                avatar TEXT,
                xp INTEGER DEFAULT 0,
                level INTEGER DEFAULT 1,
                rank TEXT,
                achievements_unlocked TEXT,
                badges TEXT,
                titles TEXT,
                active_title TEXT,
                stats TEXT,
                streak_days INTEGER DEFAULT 0,
                last_active TIMESTAMP,
                created_at TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_achievements (
                user_id TEXT,
                achievement_id TEXT,
                progress INTEGER DEFAULT 0,
                completed INTEGER DEFAULT 0,
                completed_at TIMESTAMP,
                times_completed INTEGER DEFAULT 0,
                PRIMARY KEY (user_id, achievement_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_challenges (
                user_id TEXT,
                challenge_id TEXT,
                status TEXT,
                progress TEXT,
                score INTEGER DEFAULT 0,
                completed_at TIMESTAMP,
                PRIMARY KEY (user_id, challenge_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS xp_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                xp_amount INTEGER,
                source TEXT,
                description TEXT,
                timestamp TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS leaderboards (
                leaderboard_id TEXT,
                period TEXT,
                user_id TEXT,
                score INTEGER,
                rank INTEGER,
                updated_at TIMESTAMP,
                PRIMARY KEY (leaderboard_id, period, user_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _load_achievements(self):
        """Load all achievements"""
        self.achievements = {
            # Reconnaissance Achievements
            "first_scan": Achievement(
                achievement_id="first_scan",
                name="First Blood",
                description="Complete your first security scan",
                category=AchievementCategory.RECONNAISSANCE,
                rarity=AchievementRarity.COMMON,
                xp_reward=50,
                icon="🎯"
            ),
            "scan_master": Achievement(
                achievement_id="scan_master",
                name="Scan Master",
                description="Complete 100 security scans",
                category=AchievementCategory.RECONNAISSANCE,
                rarity=AchievementRarity.RARE,
                xp_reward=500,
                icon="🔍",
                max_progress=100
            ),
            "port_explorer": Achievement(
                achievement_id="port_explorer",
                name="Port Explorer",
                description="Discover 1000 open ports",
                category=AchievementCategory.RECONNAISSANCE,
                rarity=AchievementRarity.UNCOMMON,
                xp_reward=200,
                icon="🚪",
                max_progress=1000
            ),
            "subdomain_hunter": Achievement(
                achievement_id="subdomain_hunter",
                name="Subdomain Hunter",
                description="Discover 500 subdomains",
                category=AchievementCategory.RECONNAISSANCE,
                rarity=AchievementRarity.RARE,
                xp_reward=400,
                icon="🌐",
                max_progress=500
            ),
            "osint_investigator": Achievement(
                achievement_id="osint_investigator",
                name="OSINT Investigator",
                description="Complete 50 OSINT investigations",
                category=AchievementCategory.RECONNAISSANCE,
                rarity=AchievementRarity.UNCOMMON,
                xp_reward=300,
                icon="🕵️",
                max_progress=50
            ),
            
            # Exploitation Achievements
            "first_vuln": Achievement(
                achievement_id="first_vuln",
                name="Vulnerability Hunter",
                description="Discover your first vulnerability",
                category=AchievementCategory.EXPLOITATION,
                rarity=AchievementRarity.COMMON,
                xp_reward=100,
                icon="🐛"
            ),
            "critical_finder": Achievement(
                achievement_id="critical_finder",
                name="Critical Finder",
                description="Discover a critical vulnerability",
                category=AchievementCategory.EXPLOITATION,
                rarity=AchievementRarity.UNCOMMON,
                xp_reward=250,
                icon="💀"
            ),
            "zero_day_hunter": Achievement(
                achievement_id="zero_day_hunter",
                name="Zero-Day Hunter",
                description="Discover a zero-day vulnerability",
                category=AchievementCategory.EXPLOITATION,
                rarity=AchievementRarity.LEGENDARY,
                xp_reward=5000,
                icon="🏆",
                secret=True
            ),
            "exploit_chain_master": Achievement(
                achievement_id="exploit_chain_master",
                name="Chain Reaction",
                description="Create and execute a 5+ node exploit chain",
                category=AchievementCategory.EXPLOITATION,
                rarity=AchievementRarity.EPIC,
                xp_reward=1000,
                icon="⛓️"
            ),
            "sql_slayer": Achievement(
                achievement_id="sql_slayer",
                name="SQL Slayer",
                description="Discover 25 SQL injection vulnerabilities",
                category=AchievementCategory.EXPLOITATION,
                rarity=AchievementRarity.RARE,
                xp_reward=500,
                icon="💉",
                max_progress=25
            ),
            
            # Speed Achievements
            "speed_demon": Achievement(
                achievement_id="speed_demon",
                name="Speed Demon",
                description="Complete a full assessment in under 10 minutes",
                category=AchievementCategory.SPEED,
                rarity=AchievementRarity.RARE,
                xp_reward=300,
                icon="⚡"
            ),
            "quick_draw": Achievement(
                achievement_id="quick_draw",
                name="Quick Draw",
                description="Find a critical vuln within 5 minutes of starting",
                category=AchievementCategory.SPEED,
                rarity=AchievementRarity.EPIC,
                xp_reward=750,
                icon="🤠"
            ),
            "marathon_runner": Achievement(
                achievement_id="marathon_runner",
                name="Marathon Runner",
                description="Conduct a 24-hour continuous assessment",
                category=AchievementCategory.DEDICATION,
                rarity=AchievementRarity.EPIC,
                xp_reward=1500,
                icon="🏃"
            ),
            
            # Reporting Achievements
            "first_report": Achievement(
                achievement_id="first_report",
                name="Documented",
                description="Generate your first report",
                category=AchievementCategory.REPORTING,
                rarity=AchievementRarity.COMMON,
                xp_reward=50,
                icon="📝"
            ),
            "report_master": Achievement(
                achievement_id="report_master",
                name="Report Master",
                description="Generate 50 comprehensive reports",
                category=AchievementCategory.REPORTING,
                rarity=AchievementRarity.RARE,
                xp_reward=500,
                icon="📊",
                max_progress=50
            ),
            "executive_whisperer": Achievement(
                achievement_id="executive_whisperer",
                name="Executive Whisperer",
                description="Generate 10 executive summary reports",
                category=AchievementCategory.REPORTING,
                rarity=AchievementRarity.UNCOMMON,
                xp_reward=200,
                icon="👔",
                max_progress=10
            ),
            
            # Dedication Achievements
            "daily_grind": Achievement(
                achievement_id="daily_grind",
                name="Daily Grind",
                description="Log in 7 days in a row",
                category=AchievementCategory.DEDICATION,
                rarity=AchievementRarity.UNCOMMON,
                xp_reward=200,
                icon="📅",
                max_progress=7
            ),
            "monthly_warrior": Achievement(
                achievement_id="monthly_warrior",
                name="Monthly Warrior",
                description="Log in 30 days in a row",
                category=AchievementCategory.DEDICATION,
                rarity=AchievementRarity.RARE,
                xp_reward=1000,
                icon="🗓️",
                max_progress=30
            ),
            "yearly_legend": Achievement(
                achievement_id="yearly_legend",
                name="Yearly Legend",
                description="Log in 365 days in a row",
                category=AchievementCategory.DEDICATION,
                rarity=AchievementRarity.MYTHIC,
                xp_reward=10000,
                icon="👑",
                max_progress=365
            ),
            "night_owl": Achievement(
                achievement_id="night_owl",
                name="Night Owl",
                description="Complete 10 scans between midnight and 6 AM",
                category=AchievementCategory.DEDICATION,
                rarity=AchievementRarity.UNCOMMON,
                xp_reward=150,
                icon="🦉",
                max_progress=10
            ),
            
            # Learning Achievements
            "tutorial_complete": Achievement(
                achievement_id="tutorial_complete",
                name="Graduate",
                description="Complete the getting started tutorial",
                category=AchievementCategory.LEARNING,
                rarity=AchievementRarity.COMMON,
                xp_reward=100,
                icon="🎓"
            ),
            "technique_explorer": Achievement(
                achievement_id="technique_explorer",
                name="Technique Explorer",
                description="Use 20 different attack techniques",
                category=AchievementCategory.LEARNING,
                rarity=AchievementRarity.RARE,
                xp_reward=500,
                icon="📚",
                max_progress=20
            ),
            "mitre_master": Achievement(
                achievement_id="mitre_master",
                name="MITRE Master",
                description="Execute techniques from all MITRE ATT&CK tactics",
                category=AchievementCategory.MASTERY,
                rarity=AchievementRarity.LEGENDARY,
                xp_reward=3000,
                icon="🏛️"
            ),
            
            # Special Achievements
            "early_adopter": Achievement(
                achievement_id="early_adopter",
                name="Early Adopter",
                description="Join during the beta period",
                category=AchievementCategory.SPECIAL,
                rarity=AchievementRarity.RARE,
                xp_reward=500,
                icon="🌟",
                secret=True
            ),
            "bug_bounty_hunter": Achievement(
                achievement_id="bug_bounty_hunter",
                name="Bug Bounty Hunter",
                description="Successfully report a bug in HydraRecon",
                category=AchievementCategory.SPECIAL,
                rarity=AchievementRarity.EPIC,
                xp_reward=2000,
                icon="💎",
                secret=True
            ),
            "community_hero": Achievement(
                achievement_id="community_hero",
                name="Community Hero",
                description="Help 10 other users with their questions",
                category=AchievementCategory.COLLABORATION,
                rarity=AchievementRarity.RARE,
                xp_reward=750,
                icon="🦸",
                max_progress=10
            ),
            
            # Mastery Achievements
            "jack_of_all_trades": Achievement(
                achievement_id="jack_of_all_trades",
                name="Jack of All Trades",
                description="Use every tool in HydraRecon at least once",
                category=AchievementCategory.MASTERY,
                rarity=AchievementRarity.EPIC,
                xp_reward=2000,
                icon="🃏"
            ),
            "perfectionist": Achievement(
                achievement_id="perfectionist",
                name="Perfectionist",
                description="Complete an assessment with 100% accuracy",
                category=AchievementCategory.ACCURACY,
                rarity=AchievementRarity.RARE,
                xp_reward=500,
                icon="💯"
            ),
        }
    
    def _generate_challenges(self):
        """Generate daily and weekly challenges"""
        now = datetime.now()
        
        # Daily challenges
        daily_end = now.replace(hour=23, minute=59, second=59)
        
        self.challenges = {
            "daily_scan": Challenge(
                challenge_id="daily_scan",
                name="Daily Scan",
                description="Complete 5 security scans today",
                challenge_type=ChallengeType.DAILY,
                start_time=now.replace(hour=0, minute=0, second=0),
                end_time=daily_end,
                objectives=[{"type": "scans", "target": 5}],
                xp_reward=100
            ),
            "daily_vulns": Challenge(
                challenge_id="daily_vulns",
                name="Vulnerability Spree",
                description="Discover 10 vulnerabilities today",
                challenge_type=ChallengeType.DAILY,
                start_time=now.replace(hour=0, minute=0, second=0),
                end_time=daily_end,
                objectives=[{"type": "vulnerabilities", "target": 10}],
                xp_reward=150
            ),
            "daily_reports": Challenge(
                challenge_id="daily_reports",
                name="Documentation Day",
                description="Generate 3 reports today",
                challenge_type=ChallengeType.DAILY,
                start_time=now.replace(hour=0, minute=0, second=0),
                end_time=daily_end,
                objectives=[{"type": "reports", "target": 3}],
                xp_reward=75
            ),
            
            # Weekly challenges
            "weekly_deep_dive": Challenge(
                challenge_id="weekly_deep_dive",
                name="Deep Dive",
                description="Complete a comprehensive assessment on 5 targets",
                challenge_type=ChallengeType.WEEKLY,
                start_time=now - timedelta(days=now.weekday()),
                end_time=now + timedelta(days=6-now.weekday()),
                objectives=[{"type": "comprehensive_scans", "target": 5}],
                xp_reward=500
            ),
            "weekly_critical": Challenge(
                challenge_id="weekly_critical",
                name="Critical Hunter",
                description="Find 5 critical vulnerabilities this week",
                challenge_type=ChallengeType.WEEKLY,
                start_time=now - timedelta(days=now.weekday()),
                end_time=now + timedelta(days=6-now.weekday()),
                objectives=[{"type": "critical_vulns", "target": 5}],
                xp_reward=750
            ),
            "weekly_variety": Challenge(
                challenge_id="weekly_variety",
                name="Variety Show",
                description="Use 10 different scanning modules this week",
                challenge_type=ChallengeType.WEEKLY,
                start_time=now - timedelta(days=now.weekday()),
                end_time=now + timedelta(days=6-now.weekday()),
                objectives=[{"type": "unique_modules", "target": 10}],
                xp_reward=400
            ),
        }
    
    def get_or_create_profile(self, user_id: str, username: str = None) -> UserProfile:
        """Get or create a user profile"""
        if user_id in self.users:
            return self.users[user_id]
        
        # Check database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        
        if row:
            profile = UserProfile(
                user_id=row[0],
                username=row[1],
                avatar=row[2] or "",
                xp=row[3],
                level=row[4],
                rank=RankTier(row[5]) if row[5] else RankTier.SCRIPT_KIDDIE,
                achievements_unlocked=json.loads(row[6]) if row[6] else [],
                badges=json.loads(row[7]) if row[7] else [],
                titles=json.loads(row[8]) if row[8] else [],
                active_title=row[9] or "",
                stats=json.loads(row[10]) if row[10] else {},
                streak_days=row[11],
                last_active=datetime.fromisoformat(row[12]) if row[12] else None,
                created_at=datetime.fromisoformat(row[13]) if row[13] else datetime.now()
            )
        else:
            # Create new profile
            profile = UserProfile(
                user_id=user_id,
                username=username or f"User_{user_id[:8]}",
                avatar="👤",
                created_at=datetime.now()
            )
            self._save_profile(profile)
        
        conn.close()
        self.users[user_id] = profile
        return profile
    
    def _save_profile(self, profile: UserProfile):
        """Save user profile to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO user_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile.user_id,
            profile.username,
            profile.avatar,
            profile.xp,
            profile.level,
            profile.rank.value,
            json.dumps(profile.achievements_unlocked),
            json.dumps(profile.badges),
            json.dumps(profile.titles),
            profile.active_title,
            json.dumps(profile.stats),
            profile.streak_days,
            profile.last_active.isoformat() if profile.last_active else None,
            profile.created_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def add_xp(self, user_id: str, amount: int, source: str, 
                    description: str = "") -> Dict[str, Any]:
        """Add XP to a user and check for level ups"""
        profile = self.get_or_create_profile(user_id)
        
        old_level = profile.level
        old_rank = profile.rank
        
        profile.xp += amount
        
        # Calculate new level (100 XP per level, increasing)
        new_level = self._calculate_level(profile.xp)
        profile.level = new_level
        
        # Calculate new rank
        new_rank = self._calculate_rank(new_level)
        profile.rank = new_rank
        
        # Record XP gain
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO xp_history (user_id, xp_amount, source, description, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, amount, source, description, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        # Save profile
        self._save_profile(profile)
        
        result = {
            "xp_gained": amount,
            "total_xp": profile.xp,
            "level": new_level,
            "rank": new_rank.value,
            "leveled_up": new_level > old_level,
            "ranked_up": new_rank != old_rank
        }
        
        # Trigger events
        if new_level > old_level:
            await self._trigger_event("level_up", {
                "user_id": user_id,
                "old_level": old_level,
                "new_level": new_level
            })
        
        if new_rank != old_rank:
            await self._trigger_event("rank_up", {
                "user_id": user_id,
                "old_rank": old_rank.value,
                "new_rank": new_rank.value
            })
        
        return result
    
    def _calculate_level(self, xp: int) -> int:
        """Calculate level from XP"""
        # Level formula: XP needed = 100 * level * (level + 1) / 2
        level = 1
        xp_for_next = 100
        remaining_xp = xp
        
        while remaining_xp >= xp_for_next:
            remaining_xp -= xp_for_next
            level += 1
            xp_for_next = 100 * level
        
        return level
    
    def _calculate_rank(self, level: int) -> RankTier:
        """Calculate rank from level"""
        if level >= 100:
            return RankTier.CYBER_LEGEND
        elif level >= 75:
            return RankTier.APT_HUNTER
        elif level >= 60:
            return RankTier.EXPLOIT_DEVELOPER
        elif level >= 50:
            return RankTier.SECURITY_RESEARCHER
        elif level >= 40:
            return RankTier.RED_TEAM_OPERATOR
        elif level >= 30:
            return RankTier.SENIOR_PENTESTER
        elif level >= 20:
            return RankTier.PENETRATION_TESTER
        elif level >= 10:
            return RankTier.SECURITY_ANALYST
        elif level >= 5:
            return RankTier.JUNIOR_ANALYST
        else:
            return RankTier.SCRIPT_KIDDIE
    
    async def update_achievement_progress(self, user_id: str, achievement_id: str,
                                          progress: int = 1) -> Optional[Dict[str, Any]]:
        """Update progress on an achievement"""
        if achievement_id not in self.achievements:
            return None
        
        achievement = self.achievements[achievement_id]
        profile = self.get_or_create_profile(user_id)
        
        # Get current progress
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT progress, completed, times_completed FROM user_achievements
            WHERE user_id = ? AND achievement_id = ?
        """, (user_id, achievement_id))
        
        row = cursor.fetchone()
        
        if row:
            current_progress = row[0]
            already_completed = bool(row[1])
            times_completed = row[2]
        else:
            current_progress = 0
            already_completed = False
            times_completed = 0
        
        # Skip if already completed and not repeatable
        if already_completed and not achievement.repeatable:
            conn.close()
            return None
        
        # Update progress
        new_progress = current_progress + progress
        completed = new_progress >= achievement.max_progress
        
        cursor.execute("""
            INSERT OR REPLACE INTO user_achievements VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            achievement_id,
            new_progress,
            1 if completed else 0,
            datetime.now().isoformat() if completed else None,
            times_completed + 1 if completed else times_completed
        ))
        
        conn.commit()
        conn.close()
        
        result = {
            "achievement_id": achievement_id,
            "name": achievement.name,
            "progress": new_progress,
            "max_progress": achievement.max_progress,
            "completed": completed,
            "newly_completed": completed and not already_completed
        }
        
        # Award XP and update profile if newly completed
        if completed and not already_completed:
            await self.add_xp(user_id, achievement.xp_reward, "achievement",
                            f"Unlocked: {achievement.name}")
            
            if achievement_id not in profile.achievements_unlocked:
                profile.achievements_unlocked.append(achievement_id)
                self._save_profile(profile)
            
            await self._trigger_event("achievement_unlocked", {
                "user_id": user_id,
                "achievement": achievement
            })
        
        return result
    
    async def check_streak(self, user_id: str) -> Dict[str, Any]:
        """Check and update user's login streak"""
        profile = self.get_or_create_profile(user_id)
        
        now = datetime.now()
        today = now.date()
        
        if profile.last_active:
            last_date = profile.last_active.date()
            days_diff = (today - last_date).days
            
            if days_diff == 1:
                # Consecutive day
                profile.streak_days += 1
            elif days_diff > 1:
                # Streak broken
                profile.streak_days = 1
            # Same day - no change
        else:
            profile.streak_days = 1
        
        profile.last_active = now
        self._save_profile(profile)
        
        # Check streak achievements
        if profile.streak_days >= 7:
            await self.update_achievement_progress(user_id, "daily_grind", profile.streak_days)
        if profile.streak_days >= 30:
            await self.update_achievement_progress(user_id, "monthly_warrior", profile.streak_days)
        if profile.streak_days >= 365:
            await self.update_achievement_progress(user_id, "yearly_legend", profile.streak_days)
        
        # Streak XP bonus
        streak_bonus = min(profile.streak_days * 5, 50)  # Max 50 XP bonus
        if profile.streak_days > 1:
            await self.add_xp(user_id, streak_bonus, "streak_bonus",
                            f"Day {profile.streak_days} streak bonus")
        
        return {
            "streak_days": profile.streak_days,
            "streak_bonus": streak_bonus
        }
    
    async def update_challenge_progress(self, user_id: str, challenge_id: str,
                                       objective_type: str, amount: int = 1) -> Optional[Dict[str, Any]]:
        """Update progress on a challenge"""
        if challenge_id not in self.challenges:
            return None
        
        challenge = self.challenges[challenge_id]
        now = datetime.now()
        
        # Check if challenge is active
        if now < challenge.start_time or now > challenge.end_time:
            return {"status": "expired"}
        
        # Get current progress
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT status, progress, score FROM user_challenges
            WHERE user_id = ? AND challenge_id = ?
        """, (user_id, challenge_id))
        
        row = cursor.fetchone()
        
        if row:
            status = ChallengeStatus(row[0])
            progress = json.loads(row[1]) if row[1] else {}
            score = row[2]
        else:
            status = ChallengeStatus.ACTIVE
            progress = {}
            score = 0
        
        # Skip if already completed
        if status == ChallengeStatus.COMPLETED:
            conn.close()
            return {"status": "already_completed"}
        
        # Update progress
        progress[objective_type] = progress.get(objective_type, 0) + amount
        
        # Check if all objectives met
        all_complete = True
        for obj in challenge.objectives:
            obj_type = obj["type"]
            target = obj["target"]
            if progress.get(obj_type, 0) < target:
                all_complete = False
                break
        
        if all_complete:
            status = ChallengeStatus.COMPLETED
            await self.add_xp(user_id, challenge.xp_reward, "challenge",
                            f"Completed: {challenge.name}")
        
        cursor.execute("""
            INSERT OR REPLACE INTO user_challenges VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            challenge_id,
            status.value,
            json.dumps(progress),
            score,
            datetime.now().isoformat() if all_complete else None
        ))
        
        conn.commit()
        conn.close()
        
        return {
            "challenge_id": challenge_id,
            "name": challenge.name,
            "progress": progress,
            "status": status.value,
            "completed": all_complete
        }
    
    async def record_action(self, user_id: str, action_type: str, 
                           metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Record a user action and trigger relevant achievements/challenges"""
        results = {
            "xp_gained": 0,
            "achievements": [],
            "challenges": [],
            "streak": None
        }
        
        # Check streak
        results["streak"] = await self.check_streak(user_id)
        
        # Action-specific logic
        if action_type == "scan_complete":
            # XP for scans
            xp = 10
            await self.add_xp(user_id, xp, action_type)
            results["xp_gained"] += xp
            
            # Achievement progress
            result = await self.update_achievement_progress(user_id, "first_scan")
            if result:
                results["achievements"].append(result)
            
            result = await self.update_achievement_progress(user_id, "scan_master")
            if result:
                results["achievements"].append(result)
            
            # Challenge progress
            for challenge_id in ["daily_scan", "weekly_deep_dive"]:
                result = await self.update_challenge_progress(
                    user_id, challenge_id, "scans"
                )
                if result:
                    results["challenges"].append(result)
        
        elif action_type == "vulnerability_found":
            severity = metadata.get("severity", "medium") if metadata else "medium"
            
            # XP based on severity
            xp_map = {"low": 5, "medium": 15, "high": 30, "critical": 50}
            xp = xp_map.get(severity, 10)
            await self.add_xp(user_id, xp, action_type, f"{severity} vulnerability")
            results["xp_gained"] += xp
            
            # Achievements
            result = await self.update_achievement_progress(user_id, "first_vuln")
            if result:
                results["achievements"].append(result)
            
            if severity == "critical":
                result = await self.update_achievement_progress(user_id, "critical_finder")
                if result:
                    results["achievements"].append(result)
            
            # Challenges
            result = await self.update_challenge_progress(
                user_id, "daily_vulns", "vulnerabilities"
            )
            if result:
                results["challenges"].append(result)
            
            if severity == "critical":
                result = await self.update_challenge_progress(
                    user_id, "weekly_critical", "critical_vulns"
                )
                if result:
                    results["challenges"].append(result)
        
        elif action_type == "report_generated":
            xp = 25
            await self.add_xp(user_id, xp, action_type)
            results["xp_gained"] += xp
            
            result = await self.update_achievement_progress(user_id, "first_report")
            if result:
                results["achievements"].append(result)
            
            result = await self.update_achievement_progress(user_id, "report_master")
            if result:
                results["achievements"].append(result)
            
            result = await self.update_challenge_progress(
                user_id, "daily_reports", "reports"
            )
            if result:
                results["challenges"].append(result)
        
        # Update stats
        profile = self.get_or_create_profile(user_id)
        profile.stats[action_type] = profile.stats.get(action_type, 0) + 1
        self._save_profile(profile)
        
        return results
    
    async def get_leaderboard(self, leaderboard_type: str = "xp",
                             period: str = "all_time",
                             limit: int = 10) -> List[LeaderboardEntry]:
        """Get leaderboard entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if leaderboard_type == "xp":
            cursor.execute("""
                SELECT user_id, username, xp, avatar, active_title
                FROM user_profiles
                ORDER BY xp DESC
                LIMIT ?
            """, (limit,))
        else:
            # Other leaderboard types (e.g., vulnerabilities found)
            cursor.execute("""
                SELECT user_id, username, xp, avatar, active_title
                FROM user_profiles
                ORDER BY xp DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        entries = []
        for i, row in enumerate(rows, 1):
            entries.append(LeaderboardEntry(
                user_id=row[0],
                username=row[1],
                score=row[2],
                rank=i,
                avatar=row[3] or "👤",
                title=row[4] or ""
            ))
        
        return entries
    
    def get_achievements(self, user_id: str = None) -> Dict[str, Any]:
        """Get all achievements with user progress"""
        achievements = {}
        
        user_progress = {}
        if user_id:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT achievement_id, progress, completed FROM user_achievements
                WHERE user_id = ?
            """, (user_id,))
            
            for row in cursor.fetchall():
                user_progress[row[0]] = {
                    "progress": row[1],
                    "completed": bool(row[2])
                }
            conn.close()
        
        for ach_id, ach in self.achievements.items():
            progress_data = user_progress.get(ach_id, {"progress": 0, "completed": False})
            
            achievements[ach_id] = {
                "name": ach.name,
                "description": ach.description if not ach.secret or progress_data["completed"] else "???",
                "category": ach.category.value,
                "rarity": ach.rarity.value,
                "xp_reward": ach.xp_reward,
                "icon": ach.icon,
                "secret": ach.secret,
                "progress": progress_data["progress"],
                "max_progress": ach.max_progress,
                "completed": progress_data["completed"]
            }
        
        return achievements
    
    def get_active_challenges(self) -> List[Dict[str, Any]]:
        """Get currently active challenges"""
        now = datetime.now()
        active = []
        
        for challenge_id, challenge in self.challenges.items():
            if challenge.start_time <= now <= challenge.end_time:
                time_remaining = (challenge.end_time - now).total_seconds()
                active.append({
                    "challenge_id": challenge_id,
                    "name": challenge.name,
                    "description": challenge.description,
                    "type": challenge.challenge_type.value,
                    "objectives": challenge.objectives,
                    "xp_reward": challenge.xp_reward,
                    "time_remaining": time_remaining,
                    "time_remaining_formatted": self._format_duration(time_remaining)
                })
        
        return active
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        
        if hours > 24:
            days = hours // 24
            return f"{days}d {hours % 24}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def add_event_handler(self, handler: Callable):
        """Add an event handler"""
        self.event_handlers.append(handler)
    
    async def _trigger_event(self, event_type: str, data: Dict[str, Any]):
        """Trigger an event to all handlers"""
        for handler in self.event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event_type, data)
                else:
                    handler(event_type, data)
            except Exception as e:
                print(f"Event handler error: {e}")
