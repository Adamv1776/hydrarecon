"""
HydraRecon Gamification Engine Page
XP, achievements, leaderboards, and skill progression
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QProgressBar, QScrollArea, QGridLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QStackedWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont

from typing import Dict, List
from datetime import datetime


class AchievementBadge(QFrame):
    """Widget for displaying an achievement badge"""
    
    def __init__(self, achievement: Dict, parent=None):
        super().__init__(parent)
        self.achievement = achievement
        self.setup_ui()
    
    def setup_ui(self):
        unlocked = self.achievement.get('unlocked', False)
        rarity = self.achievement.get('rarity', 'common')
        
        rarity_colors = {
            'common': '#888888',
            'uncommon': '#00ff00',
            'rare': '#0088ff',
            'epic': '#ff00ff',
            'legendary': '#ff8800'
        }
        
        color = rarity_colors.get(rarity, '#888')
        
        if unlocked:
            bg_style = f"background: {color}22; border: 2px solid {color};"
        else:
            bg_style = "background: #1a1a1a; border: 2px solid #333;"
        
        self.setStyleSheet(f"""
            QFrame {{
                {bg_style}
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Icon
        icon = self.achievement.get('icon', '🏆')
        icon_label = QLabel(icon)
        icon_label.setStyleSheet(f"font-size: 36px; {'opacity: 1;' if unlocked else 'opacity: 0.3;'}")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        # Name
        name = self.achievement.get('name', 'Achievement')
        name_label = QLabel(name)
        name_label.setStyleSheet(f"color: {color if unlocked else '#555'}; font-weight: bold; font-size: 11px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label.setWordWrap(True)
        layout.addWidget(name_label)
        
        # Description
        desc = self.achievement.get('description', '')
        desc_label = QLabel(desc)
        desc_label.setStyleSheet(f"color: {'#888' if unlocked else '#444'}; font-size: 9px;")
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        # XP reward
        xp = self.achievement.get('xp', 0)
        xp_label = QLabel(f"+{xp} XP")
        xp_label.setStyleSheet(f"color: {color if unlocked else '#333'}; font-size: 10px; font-weight: bold;")
        xp_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(xp_label)
        
        self.setFixedSize(130, 160)


class SkillTreeNode(QFrame):
    """Widget for a skill tree node"""
    
    clicked = pyqtSignal(str)
    
    def __init__(self, skill: Dict, parent=None):
        super().__init__(parent)
        self.skill = skill
        self.setup_ui()
    
    def setup_ui(self):
        unlocked = self.skill.get('unlocked', False)
        max_level = self.skill.get('max_level', 5)
        current_level = self.skill.get('level', 0)
        
        if unlocked:
            color = '#00ff00'
            bg = '#00ff0022'
        elif current_level > 0:
            color = '#ffff00'
            bg = '#ffff0022'
        else:
            color = '#555'
            bg = '#1a1a1a'
        
        self.setStyleSheet(f"""
            QFrame {{
                background: {bg};
                border: 2px solid {color};
                border-radius: 50%;
            }}
            QFrame:hover {{
                background: {color}44;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Icon
        icon = self.skill.get('icon', '⚡')
        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 20px;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        # Level
        level_label = QLabel(f"{current_level}/{max_level}")
        level_label.setStyleSheet(f"color: {color}; font-size: 9px;")
        level_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(level_label)
        
        self.setFixedSize(60, 60)
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.skill.get('id', ''))
        super().mousePressEvent(event)


class GamificationPage(QWidget):
    """Gamification page with XP, achievements, and leaderboards"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_xp = 12500
        self.current_level = 15
        self.rank = "Cyber Warrior"
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Profile header
        profile = QFrame()
        profile.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #001100, stop:0.5 #002200, stop:1 #001100);
                border-bottom: 2px solid #00ff00;
            }
        """)
        profile_layout = QHBoxLayout(profile)
        
        # Avatar
        avatar = QLabel("👤")
        avatar.setStyleSheet("""
            font-size: 48px;
            background: #00ff0022;
            border: 2px solid #00ff00;
            border-radius: 35px;
            padding: 10px;
        """)
        profile_layout.addWidget(avatar)
        
        # User info
        info_layout = QVBoxLayout()
        
        username = QLabel("CyberOperator_Alpha")
        username.setStyleSheet("color: #00ff00; font-size: 20px; font-weight: bold;")
        info_layout.addWidget(username)
        
        rank_label = QLabel(f"🎖️ {self.rank}")
        rank_label.setStyleSheet("color: #ff8800; font-size: 14px;")
        info_layout.addWidget(rank_label)
        
        profile_layout.addLayout(info_layout)
        
        profile_layout.addStretch()
        
        # Level and XP
        level_frame = QFrame()
        level_layout = QVBoxLayout(level_frame)
        
        level_label = QLabel(f"Level {self.current_level}")
        level_label.setStyleSheet("color: #00ff00; font-size: 24px; font-weight: bold;")
        level_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        level_layout.addWidget(level_label)
        
        xp_bar = QProgressBar()
        xp_bar.setRange(0, 10000)
        xp_bar.setValue(self.current_xp % 10000)
        xp_bar.setFormat(f"{self.current_xp:,} / {(self.current_level + 1) * 10000:,} XP")
        xp_bar.setStyleSheet("""
            QProgressBar {
                background: #1a1a1a;
                border: 1px solid #333;
                border-radius: 5px;
                height: 20px;
                text-align: center;
                color: #00ff00;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #003300, stop:1 #00ff00);
                border-radius: 4px;
            }
        """)
        level_layout.addWidget(xp_bar)
        
        profile_layout.addWidget(level_frame)
        
        # Stats
        stats_layout = QGridLayout()
        
        stats = [
            ("🎯", "Scans", "1,247"),
            ("💥", "Exploits", "89"),
            ("🏆", "Achievements", "23/50"),
            ("🔥", "Streak", "7 days")
        ]
        
        for i, (icon, label, value) in enumerate(stats):
            stat_frame = QFrame()
            stat_frame.setStyleSheet("""
                QFrame {
                    background: #00ff0011;
                    border: 1px solid #00ff0044;
                    border-radius: 4px;
                    padding: 5px;
                }
            """)
            stat_layout = QVBoxLayout(stat_frame)
            stat_layout.setContentsMargins(10, 5, 10, 5)
            
            icon_label = QLabel(f"{icon} {label}")
            icon_label.setStyleSheet("color: #888; font-size: 11px;")
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_layout.addWidget(icon_label)
            
            value_label = QLabel(value)
            value_label.setStyleSheet("color: #00ff00; font-size: 14px; font-weight: bold;")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_layout.addWidget(value_label)
            
            stats_layout.addWidget(stat_frame, 0, i)
        
        profile_layout.addLayout(stats_layout)
        
        layout.addWidget(profile)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: #0a0a0a;
            }
            QTabBar::tab {
                background: #1a1a1a;
                color: #888;
                padding: 10px 20px;
                border: 1px solid #333;
            }
            QTabBar::tab:selected {
                background: #002200;
                color: #00ff00;
                border-bottom: 2px solid #00ff00;
            }
        """)
        
        # Achievements tab
        achievements_tab = QWidget()
        ach_layout = QVBoxLayout(achievements_tab)
        
        ach_scroll = QScrollArea()
        ach_scroll.setWidgetResizable(True)
        ach_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        ach_container = QWidget()
        ach_grid = QGridLayout(ach_container)
        
        achievements = [
            {'icon': '🔍', 'name': 'First Scan', 'description': 'Complete your first scan', 'xp': 100, 'unlocked': True, 'rarity': 'common'},
            {'icon': '💥', 'name': 'Exploit Master', 'description': 'Successfully run 10 exploits', 'xp': 500, 'unlocked': True, 'rarity': 'uncommon'},
            {'icon': '🕵️', 'name': 'Shadow Walker', 'description': 'Complete 5 stealth scans', 'xp': 250, 'unlocked': True, 'rarity': 'uncommon'},
            {'icon': '⚡', 'name': 'Speed Demon', 'description': 'Complete a scan in under 10s', 'xp': 200, 'unlocked': True, 'rarity': 'rare'},
            {'icon': '🔐', 'name': 'Password Hunter', 'description': 'Crack 50 passwords', 'xp': 1000, 'unlocked': True, 'rarity': 'rare'},
            {'icon': '🌐', 'name': 'Network Ninja', 'description': 'Map 100 networks', 'xp': 750, 'unlocked': False, 'rarity': 'rare'},
            {'icon': '🎭', 'name': 'Master of Disguise', 'description': 'Evade 25 detection systems', 'xp': 1500, 'unlocked': False, 'rarity': 'epic'},
            {'icon': '👑', 'name': 'Domain Admin', 'description': 'Compromise a domain controller', 'xp': 2500, 'unlocked': False, 'rarity': 'legendary'},
            {'icon': '🌟', 'name': 'Zero Day Hunter', 'description': 'Discover a zero-day vulnerability', 'xp': 5000, 'unlocked': False, 'rarity': 'legendary'},
            {'icon': '🏴‍☠️', 'name': 'APT Simulator', 'description': 'Complete an APT simulation', 'xp': 3000, 'unlocked': False, 'rarity': 'epic'},
            {'icon': '🔥', 'name': 'On Fire', 'description': '30 day login streak', 'xp': 1000, 'unlocked': False, 'rarity': 'epic'},
            {'icon': '🤖', 'name': 'AI Master', 'description': 'Use all AI features', 'xp': 800, 'unlocked': True, 'rarity': 'uncommon'}
        ]
        
        for i, ach in enumerate(achievements):
            badge = AchievementBadge(ach)
            ach_grid.addWidget(badge, i // 6, i % 6)
        
        ach_scroll.setWidget(ach_container)
        ach_layout.addWidget(ach_scroll)
        
        tabs.addTab(achievements_tab, "🏆 Achievements")
        
        # Leaderboard tab
        leaderboard_tab = QWidget()
        lb_layout = QVBoxLayout(leaderboard_tab)
        
        lb_table = QTableWidget(10, 5)
        lb_table.setHorizontalHeaderLabels(['Rank', 'Player', 'Level', 'XP', 'Achievements'])
        lb_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        lb_table.setStyleSheet("""
            QTableWidget {
                background: #1a1a1a;
                color: #00ff00;
                border: 1px solid #333;
                gridline-color: #333;
            }
            QHeaderView::section {
                background: #111;
                color: #00ff00;
                border: 1px solid #333;
                padding: 5px;
            }
        """)
        
        players = [
            ('🥇', 'ShadowH4cker', 42, '425,000', '48/50'),
            ('🥈', 'CyberNinja_X', 38, '380,500', '45/50'),
            ('🥉', 'R00tK1ng', 35, '352,000', '42/50'),
            ('4', 'Ph4nt0m', 32, '320,000', '38/50'),
            ('5', 'ByteBreaker', 30, '300,100', '35/50'),
            ('6', 'DarkVec0r', 28, '285,000', '32/50'),
            ('7', 'N3tW4rr10r', 25, '250,500', '30/50'),
            ('→', 'CyberOperator_Alpha (You)', 15, '125,000', '23/50'),
            ('9', 'H4x0r_Elite', 22, '220,000', '28/50'),
            ('10', 'C0d3Br3ak3r', 20, '200,000', '25/50')
        ]
        
        for i, (rank, name, level, xp, achievements) in enumerate(players):
            lb_table.setItem(i, 0, QTableWidgetItem(str(rank)))
            lb_table.setItem(i, 1, QTableWidgetItem(name))
            lb_table.setItem(i, 2, QTableWidgetItem(str(level)))
            lb_table.setItem(i, 3, QTableWidgetItem(xp))
            lb_table.setItem(i, 4, QTableWidgetItem(achievements))
            
            # Highlight current user
            if 'You' in name:
                for j in range(5):
                    item = lb_table.item(i, j)
                    if item:
                        item.setBackground(QColor('#003300'))
        
        lb_layout.addWidget(lb_table)
        
        tabs.addTab(leaderboard_tab, "🏅 Leaderboard")
        
        # Skill Tree tab
        skills_tab = QWidget()
        skills_layout = QVBoxLayout(skills_tab)
        
        skill_categories = QHBoxLayout()
        
        categories = ['🔍 Recon', '💥 Exploitation', '🔐 Crypto', '🌐 Network', '🛡️ Defense']
        for cat in categories:
            btn = QPushButton(cat)
            btn.setStyleSheet("""
                QPushButton {
                    background: #1a1a1a;
                    color: #888;
                    border: 1px solid #333;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #252525; color: #00ff00; }
                QPushButton:checked { background: #003300; color: #00ff00; border-color: #00ff00; }
            """)
            btn.setCheckable(True)
            if cat == '🔍 Recon':
                btn.setChecked(True)
            skill_categories.addWidget(btn)
        
        skills_layout.addLayout(skill_categories)
        
        # Skill tree visualization
        skill_tree = QFrame()
        skill_tree.setStyleSheet("background: #0a0a0a; border: 1px solid #333; border-radius: 8px;")
        tree_layout = QGridLayout(skill_tree)
        tree_layout.setSpacing(20)
        
        skills = [
            {'id': 's1', 'icon': '🔍', 'level': 5, 'max_level': 5, 'unlocked': True},
            {'id': 's2', 'icon': '🌐', 'level': 4, 'max_level': 5, 'unlocked': True},
            {'id': 's3', 'icon': '📡', 'level': 3, 'max_level': 5, 'unlocked': True},
            {'id': 's4', 'icon': '🔎', 'level': 2, 'max_level': 5, 'unlocked': False},
            {'id': 's5', 'icon': '🕵️', 'level': 1, 'max_level': 5, 'unlocked': False},
            {'id': 's6', 'icon': '👁️', 'level': 0, 'max_level': 5, 'unlocked': False},
        ]
        
        positions = [(0, 2), (1, 1), (1, 3), (2, 0), (2, 2), (2, 4)]
        for skill, (row, col) in zip(skills, positions):
            node = SkillTreeNode(skill)
            tree_layout.addWidget(node, row, col, Qt.AlignmentFlag.AlignCenter)
        
        skills_layout.addWidget(skill_tree, 1)
        
        # Skill points
        sp_frame = QFrame()
        sp_frame.setStyleSheet("background: #111; border: 1px solid #333; border-radius: 4px; padding: 10px;")
        sp_layout = QHBoxLayout(sp_frame)
        
        sp_label = QLabel("⭐ Skill Points Available: 3")
        sp_label.setStyleSheet("color: #ffff00; font-size: 14px; font-weight: bold;")
        sp_layout.addWidget(sp_label)
        
        sp_layout.addStretch()
        
        reset_btn = QPushButton("🔄 Reset Tree")
        reset_btn.setStyleSheet("""
            QPushButton {
                background: #1a1a1a;
                color: #888;
                border: 1px solid #333;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #252525; }
        """)
        sp_layout.addWidget(reset_btn)
        
        skills_layout.addWidget(sp_frame)
        
        tabs.addTab(skills_tab, "🌳 Skill Tree")
        
        # Challenges tab
        challenges_tab = QWidget()
        ch_layout = QVBoxLayout(challenges_tab)
        
        ch_header = QHBoxLayout()
        ch_title = QLabel("🎯 Daily Challenges")
        ch_title.setStyleSheet("color: #00ff00; font-size: 16px; font-weight: bold;")
        ch_header.addWidget(ch_title)
        
        ch_header.addStretch()
        
        refresh_label = QLabel("Refreshes in: 4h 23m")
        refresh_label.setStyleSheet("color: #888;")
        ch_header.addWidget(refresh_label)
        
        ch_layout.addLayout(ch_header)
        
        challenges = [
            {'name': 'Quick Scanner', 'desc': 'Complete 5 port scans', 'progress': 3, 'total': 5, 'xp': 200, 'done': False},
            {'name': 'Vulnerability Hunter', 'desc': 'Find 10 vulnerabilities', 'progress': 10, 'total': 10, 'xp': 500, 'done': True},
            {'name': 'Password Pro', 'desc': 'Crack 3 passwords', 'progress': 1, 'total': 3, 'xp': 300, 'done': False},
            {'name': 'Network Explorer', 'desc': 'Map 2 network segments', 'progress': 0, 'total': 2, 'xp': 400, 'done': False}
        ]
        
        for ch in challenges:
            ch_frame = QFrame()
            ch_frame.setStyleSheet(f"""
                QFrame {{
                    background: {'#00330022' if ch['done'] else '#1a1a1a'};
                    border: 1px solid {'#00ff00' if ch['done'] else '#333'};
                    border-radius: 6px;
                    padding: 10px;
                }}
            """)
            frame_layout = QHBoxLayout(ch_frame)
            
            # Challenge info
            info = QVBoxLayout()
            
            name_label = QLabel(f"{'✅' if ch['done'] else '🎯'} {ch['name']}")
            name_label.setStyleSheet(f"color: {'#00ff00' if ch['done'] else '#fff'}; font-weight: bold;")
            info.addWidget(name_label)
            
            desc_label = QLabel(ch['desc'])
            desc_label.setStyleSheet("color: #888; font-size: 11px;")
            info.addWidget(desc_label)
            
            frame_layout.addLayout(info, 1)
            
            # Progress
            prog = QVBoxLayout()
            
            prog_bar = QProgressBar()
            prog_bar.setRange(0, ch['total'])
            prog_bar.setValue(ch['progress'])
            prog_bar.setFormat(f"{ch['progress']}/{ch['total']}")
            prog_bar.setStyleSheet("""
                QProgressBar {
                    background: #111;
                    border: 1px solid #333;
                    border-radius: 3px;
                    height: 16px;
                    text-align: center;
                    color: #00ff00;
                }
                QProgressBar::chunk {
                    background: #00ff00;
                    border-radius: 2px;
                }
            """)
            prog.addWidget(prog_bar)
            
            xp_label = QLabel(f"+{ch['xp']} XP")
            xp_label.setStyleSheet("color: #ffff00; font-size: 11px;")
            xp_label.setAlignment(Qt.AlignmentFlag.AlignRight)
            prog.addWidget(xp_label)
            
            frame_layout.addLayout(prog)
            
            ch_layout.addWidget(ch_frame)
        
        ch_layout.addStretch()
        
        tabs.addTab(challenges_tab, "🎯 Challenges")
        
        layout.addWidget(tabs, 1)
