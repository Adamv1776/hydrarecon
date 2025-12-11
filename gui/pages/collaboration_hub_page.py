"""
HydraRecon Collaboration Hub Page
Real-time multi-user pentesting and team coordination
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QListWidget, QListWidgetItem, QSplitter, QTextEdit,
    QGroupBox, QLineEdit, QScrollArea, QComboBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont

from datetime import datetime
from typing import Dict, List, Optional


class TeamMemberWidget(QFrame):
    """Widget for displaying a team member"""
    
    def __init__(self, member: Dict, parent=None):
        super().__init__(parent)
        self.member = member
        self.setup_ui()
    
    def setup_ui(self):
        status = self.member.get('status', 'offline')
        
        status_colors = {
            'online': '#00ff00',
            'busy': '#ff8800',
            'away': '#ffff00',
            'offline': '#555'
        }
        
        color = status_colors.get(status, '#555')
        
        self.setStyleSheet(f"""
            QFrame {{
                background: #1a1a1a;
                border: 1px solid {color};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        
        # Avatar
        avatar = QLabel(self.member.get('avatar', '👤'))
        avatar.setStyleSheet("font-size: 24px;")
        layout.addWidget(avatar)
        
        # Info
        info = QVBoxLayout()
        
        name = QLabel(self.member.get('name', 'Unknown'))
        name.setStyleSheet(f"color: {color}; font-weight: bold;")
        info.addWidget(name)
        
        role = self.member.get('role', 'Member')
        activity = self.member.get('activity', 'Idle')
        detail = QLabel(f"{role} • {activity}")
        detail.setStyleSheet("color: #888; font-size: 10px;")
        info.addWidget(detail)
        
        layout.addLayout(info, 1)
        
        # Status indicator
        indicator = QLabel("●")
        indicator.setStyleSheet(f"color: {color}; font-size: 16px;")
        layout.addWidget(indicator)


class ChatMessageWidget(QFrame):
    """Widget for a chat message"""
    
    def __init__(self, message: Dict, parent=None):
        super().__init__(parent)
        self.message = message
        self.setup_ui()
    
    def setup_ui(self):
        is_own = self.message.get('is_own', False)
        msg_type = self.message.get('type', 'text')
        
        bg_color = '#002200' if is_own else '#1a1a1a'
        align = Qt.AlignmentFlag.AlignRight if is_own else Qt.AlignmentFlag.AlignLeft
        
        self.setStyleSheet(f"""
            QFrame {{
                background: {bg_color};
                border: 1px solid #333;
                border-radius: 8px;
                padding: 8px;
                margin: {'0 0 0 50px' if is_own else '0 50px 0 0'};
            }}
        """)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QHBoxLayout()
        
        if not is_own:
            sender = QLabel(self.message.get('sender', 'Unknown'))
            sender.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 11px;")
            header.addWidget(sender)
        
        header.addStretch()
        
        time = self.message.get('time', '')
        time_label = QLabel(time)
        time_label.setStyleSheet("color: #666; font-size: 9px;")
        header.addWidget(time_label)
        
        layout.addLayout(header)
        
        # Content
        if msg_type == 'text':
            content = QLabel(self.message.get('content', ''))
            content.setWordWrap(True)
            content.setStyleSheet("color: #ccc;")
            layout.addWidget(content)
        elif msg_type == 'command':
            cmd = QLabel(f"$ {self.message.get('content', '')}")
            cmd.setStyleSheet("color: #00ff00; font-family: Consolas; background: #0a0a0a; padding: 4px; border-radius: 3px;")
            layout.addWidget(cmd)
        elif msg_type == 'finding':
            finding = QFrame()
            finding.setStyleSheet("background: #330000; border: 1px solid #ff0000; border-radius: 4px; padding: 4px;")
            finding_layout = QVBoxLayout(finding)
            
            finding_title = QLabel(f"🚨 {self.message.get('content', '')}")
            finding_title.setStyleSheet("color: #ff0000; font-weight: bold;")
            finding_layout.addWidget(finding_title)
            
            layout.addWidget(finding)


class SharedResourceWidget(QFrame):
    """Widget for a shared resource"""
    
    def __init__(self, resource: Dict, parent=None):
        super().__init__(parent)
        self.resource = resource
        self.setup_ui()
    
    def setup_ui(self):
        res_type = self.resource.get('type', 'file')
        
        type_icons = {
            'file': '📄',
            'target': '🎯',
            'credential': '🔐',
            'finding': '🚨',
            'tool_output': '🖥️'
        }
        
        self.setStyleSheet("""
            QFrame {
                background: #1a1a1a;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 8px;
            }
            QFrame:hover { border-color: #00ff00; }
        """)
        
        layout = QHBoxLayout(self)
        
        icon = QLabel(type_icons.get(res_type, '📁'))
        icon.setStyleSheet("font-size: 18px;")
        layout.addWidget(icon)
        
        info = QVBoxLayout()
        
        name = QLabel(self.resource.get('name', 'Resource'))
        name.setStyleSheet("color: #00ff00; font-weight: bold;")
        info.addWidget(name)
        
        meta = QLabel(f"Shared by {self.resource.get('shared_by', 'Unknown')}")
        meta.setStyleSheet("color: #666; font-size: 10px;")
        info.addWidget(meta)
        
        layout.addLayout(info, 1)
        
        use_btn = QPushButton("Use")
        use_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 4px 12px;
                border-radius: 3px;
            }
            QPushButton:hover { background: #004400; }
        """)
        layout.addWidget(use_btn)


class CollaborationHubPage(QWidget):
    """Collaboration Hub page for team pentesting"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.session_active = False
        self.setup_ui()
        self.load_demo_data()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header = QFrame()
        header.setStyleSheet("background: #111; border-bottom: 1px solid #00ff00;")
        header_layout = QHBoxLayout(header)
        
        title = QLabel("👥 Collaboration Hub")
        title.setStyleSheet("color: #00ff00; font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Session info
        self.session_label = QLabel("Session: webapp_pentest_team")
        self.session_label.setStyleSheet("color: #888;")
        header_layout.addWidget(self.session_label)
        
        # Online indicator
        self.online_count = QLabel("👥 4 Online")
        self.online_count.setStyleSheet("""
            color: #00ff00;
            background: #00330033;
            padding: 4px 12px;
            border-radius: 4px;
        """)
        header_layout.addWidget(self.online_count)
        
        # Actions
        self.session_btn = QPushButton("🚀 Start Session")
        self.session_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #004400; }
        """)
        self.session_btn.clicked.connect(self.toggle_session)
        header_layout.addWidget(self.session_btn)
        
        layout.addWidget(header)
        
        # Main content
        content = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Team panel
        left_panel = QFrame()
        left_panel.setStyleSheet("background: #0a0a0a;")
        left_layout = QVBoxLayout(left_panel)
        
        team_title = QLabel("👥 Team Members")
        team_title.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
        left_layout.addWidget(team_title)
        
        # Team members list
        self.team_list = QVBoxLayout()
        self.team_list.setSpacing(4)
        
        team_container = QWidget()
        team_container.setLayout(self.team_list)
        
        team_scroll = QScrollArea()
        team_scroll.setWidget(team_container)
        team_scroll.setWidgetResizable(True)
        team_scroll.setStyleSheet("""
            QScrollArea { border: none; background: transparent; }
            QScrollBar:vertical { background: #111; width: 8px; }
            QScrollBar::handle:vertical { background: #333; border-radius: 4px; }
        """)
        left_layout.addWidget(team_scroll, 1)
        
        # Invite button
        invite_btn = QPushButton("➕ Invite Member")
        invite_btn.setStyleSheet("""
            QPushButton {
                background: #1a1a1a;
                color: #888;
                border: 1px solid #333;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #252525; color: #00ff00; }
        """)
        left_layout.addWidget(invite_btn)
        
        # Role assignment
        roles_group = QGroupBox("🎖️ Roles")
        roles_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        roles_layout = QVBoxLayout(roles_group)
        
        roles = [
            ("👑 Lead", "Alpha"),
            ("💥 Exploitation", "Bravo, Charlie"),
            ("🔍 Recon", "Delta"),
            ("📝 Documentation", "Echo")
        ]
        
        for role, assigned in roles:
            role_frame = QHBoxLayout()
            
            role_label = QLabel(role)
            role_label.setStyleSheet("color: #888;")
            role_frame.addWidget(role_label)
            
            role_frame.addStretch()
            
            assigned_label = QLabel(assigned)
            assigned_label.setStyleSheet("color: #00ff00; font-size: 10px;")
            role_frame.addWidget(assigned_label)
            
            roles_layout.addLayout(role_frame)
        
        left_layout.addWidget(roles_group)
        
        content.addWidget(left_panel)
        
        # Center - Chat and activity
        center_panel = QFrame()
        center_panel.setStyleSheet("background: #0a0a0a;")
        center_layout = QVBoxLayout(center_panel)
        
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: #1a1a1a;
                color: #888;
                padding: 8px 16px;
                border: 1px solid #333;
            }
            QTabBar::tab:selected {
                background: #002200;
                color: #00ff00;
                border-bottom: 2px solid #00ff00;
            }
        """)
        
        # Chat tab
        chat_tab = QWidget()
        chat_layout = QVBoxLayout(chat_tab)
        
        # Messages
        self.messages_layout = QVBoxLayout()
        self.messages_layout.setSpacing(8)
        
        messages_container = QWidget()
        messages_container.setLayout(self.messages_layout)
        
        messages_scroll = QScrollArea()
        messages_scroll.setWidget(messages_container)
        messages_scroll.setWidgetResizable(True)
        messages_scroll.setStyleSheet("""
            QScrollArea { border: none; background: transparent; }
            QScrollBar:vertical { background: #111; width: 8px; }
            QScrollBar::handle:vertical { background: #333; border-radius: 4px; }
        """)
        chat_layout.addWidget(messages_scroll, 1)
        
        # Input
        input_frame = QFrame()
        input_frame.setStyleSheet("background: #111; border: 1px solid #333; border-radius: 6px;")
        input_layout = QHBoxLayout(input_frame)
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message or /command...")
        self.message_input.setStyleSheet("""
            QLineEdit {
                background: transparent;
                color: #00ff00;
                border: none;
                padding: 8px;
            }
        """)
        input_layout.addWidget(self.message_input, 1)
        
        # Quick actions
        share_btn = QPushButton("📎")
        share_btn.setToolTip("Share Resource")
        share_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #888;
                border: none;
                padding: 8px;
                font-size: 16px;
            }
            QPushButton:hover { color: #00ff00; }
        """)
        input_layout.addWidget(share_btn)
        
        finding_btn = QPushButton("🚨")
        finding_btn.setToolTip("Report Finding")
        finding_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #888;
                border: none;
                padding: 8px;
                font-size: 16px;
            }
            QPushButton:hover { color: #ff0000; }
        """)
        input_layout.addWidget(finding_btn)
        
        send_btn = QPushButton("📤")
        send_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover { background: #004400; }
        """)
        send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(send_btn)
        
        chat_layout.addWidget(input_frame)
        
        tabs.addTab(chat_tab, "💬 Team Chat")
        
        # Activity tab
        activity_tab = QWidget()
        activity_layout = QVBoxLayout(activity_tab)
        
        self.activity_list = QListWidget()
        self.activity_list.setStyleSheet("""
            QListWidget {
                background: transparent;
                color: #00ff00;
                border: none;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #222;
            }
            QListWidget::item:hover { background: #1a1a1a; }
        """)
        activity_layout.addWidget(self.activity_list)
        
        tabs.addTab(activity_tab, "📊 Activity")
        
        # Targets tab
        targets_tab = QWidget()
        targets_layout = QVBoxLayout(targets_tab)
        
        targets_table = QTableWidget(5, 4)
        targets_table.setHorizontalHeaderLabels(['Target', 'Assignee', 'Status', 'Progress'])
        targets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        targets_table.setStyleSheet("""
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
        
        targets_data = [
            ('192.168.1.100', 'Alpha', '✅ Complete', '100%'),
            ('192.168.1.101', 'Bravo', '🔄 In Progress', '65%'),
            ('192.168.1.102', 'Charlie', '🔄 In Progress', '30%'),
            ('192.168.1.103', 'Delta', '⏳ Pending', '0%'),
            ('192.168.1.104', 'Unassigned', '⏳ Pending', '0%')
        ]
        
        for i, (target, assignee, status, progress) in enumerate(targets_data):
            targets_table.setItem(i, 0, QTableWidgetItem(target))
            targets_table.setItem(i, 1, QTableWidgetItem(assignee))
            targets_table.setItem(i, 2, QTableWidgetItem(status))
            targets_table.setItem(i, 3, QTableWidgetItem(progress))
        
        targets_layout.addWidget(targets_table)
        
        tabs.addTab(targets_tab, "🎯 Targets")
        
        center_layout.addWidget(tabs)
        
        content.addWidget(center_panel)
        
        # Right - Shared resources
        right_panel = QFrame()
        right_panel.setStyleSheet("background: #0a0a0a;")
        right_layout = QVBoxLayout(right_panel)
        
        resources_title = QLabel("📁 Shared Resources")
        resources_title.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
        right_layout.addWidget(resources_title)
        
        # Resources list
        self.resources_layout = QVBoxLayout()
        self.resources_layout.setSpacing(4)
        
        resources_container = QWidget()
        resources_container.setLayout(self.resources_layout)
        
        resources_scroll = QScrollArea()
        resources_scroll.setWidget(resources_container)
        resources_scroll.setWidgetResizable(True)
        resources_scroll.setStyleSheet("""
            QScrollArea { border: none; background: transparent; }
            QScrollBar:vertical { background: #111; width: 8px; }
            QScrollBar::handle:vertical { background: #333; border-radius: 4px; }
        """)
        right_layout.addWidget(resources_scroll, 1)
        
        # Upload button
        upload_btn = QPushButton("📤 Share Resource")
        upload_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #004400; }
        """)
        right_layout.addWidget(upload_btn)
        
        # Session stats
        stats_group = QGroupBox("📊 Session Stats")
        stats_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        stats_layout = QVBoxLayout(stats_group)
        
        stats = [
            ("Targets Scanned", "5/10"),
            ("Findings", "12"),
            ("Credentials", "3"),
            ("Session Duration", "2h 35m")
        ]
        
        for stat_name, stat_value in stats:
            stat_row = QHBoxLayout()
            
            name_label = QLabel(stat_name)
            name_label.setStyleSheet("color: #888;")
            stat_row.addWidget(name_label)
            
            stat_row.addStretch()
            
            value_label = QLabel(stat_value)
            value_label.setStyleSheet("color: #00ff00; font-weight: bold;")
            stat_row.addWidget(value_label)
            
            stats_layout.addLayout(stat_row)
        
        # Progress bar
        overall_progress = QProgressBar()
        overall_progress.setRange(0, 100)
        overall_progress.setValue(45)
        overall_progress.setFormat("Overall: 45%")
        overall_progress.setStyleSheet("""
            QProgressBar {
                background: #111;
                border: 1px solid #333;
                border-radius: 4px;
                height: 20px;
                text-align: center;
                color: #00ff00;
            }
            QProgressBar::chunk {
                background: #00ff00;
                border-radius: 3px;
            }
        """)
        stats_layout.addWidget(overall_progress)
        
        right_layout.addWidget(stats_group)
        
        content.addWidget(right_panel)
        content.setSizes([200, 550, 250])
        
        layout.addWidget(content, 1)
    
    def load_demo_data(self):
        """Load demo data for the collaboration hub"""
        # Team members
        members = [
            {'name': 'Alpha (You)', 'avatar': '👤', 'role': 'Lead', 'status': 'online', 'activity': 'Scanning 192.168.1.101'},
            {'name': 'Bravo', 'avatar': '🧑', 'role': 'Exploitation', 'status': 'online', 'activity': 'Testing SQLi'},
            {'name': 'Charlie', 'avatar': '👨', 'role': 'Exploitation', 'status': 'busy', 'activity': 'In exploitation'},
            {'name': 'Delta', 'avatar': '👩', 'role': 'Recon', 'status': 'online', 'activity': 'OSINT gathering'},
            {'name': 'Echo', 'avatar': '🧔', 'role': 'Documentation', 'status': 'away', 'activity': 'Writing report'}
        ]
        
        for member in members:
            widget = TeamMemberWidget(member)
            self.team_list.addWidget(widget)
        
        # Messages
        messages = [
            {'sender': 'Bravo', 'content': 'Found a potential SQL injection on the login form!', 'time': '14:32', 'is_own': False, 'type': 'text'},
            {'sender': 'You', 'content': 'Great find! Can you share the payload?', 'time': '14:33', 'is_own': True, 'type': 'text'},
            {'sender': 'Bravo', 'content': "' OR '1'='1' --", 'time': '14:34', 'is_own': False, 'type': 'command'},
            {'sender': 'Delta', 'content': 'I found their admin email on LinkedIn', 'time': '14:35', 'is_own': False, 'type': 'text'},
            {'sender': 'Charlie', 'content': 'Got a shell on .102!', 'time': '14:38', 'is_own': False, 'type': 'finding'}
        ]
        
        for msg in messages:
            widget = ChatMessageWidget(msg)
            self.messages_layout.addWidget(widget)
        
        # Resources
        resources = [
            {'name': 'nmap_results.xml', 'type': 'file', 'shared_by': 'Alpha'},
            {'name': '192.168.1.100', 'type': 'target', 'shared_by': 'Delta'},
            {'name': 'admin:P@ssw0rd123', 'type': 'credential', 'shared_by': 'Bravo'},
            {'name': 'SQLi - Login Form', 'type': 'finding', 'shared_by': 'Charlie'}
        ]
        
        for resource in resources:
            widget = SharedResourceWidget(resource)
            self.resources_layout.addWidget(widget)
        
        # Activity
        activities = [
            "14:38 | Charlie obtained shell access on 192.168.1.102",
            "14:35 | Delta shared target information",
            "14:34 | Bravo discovered SQL injection vulnerability",
            "14:30 | Alpha completed port scan on 192.168.1.101",
            "14:25 | Session started by Alpha"
        ]
        
        for activity in activities:
            item = QListWidgetItem(activity)
            self.activity_list.addItem(item)
    
    def toggle_session(self):
        if self.session_active:
            self.session_active = False
            self.session_btn.setText("🚀 Start Session")
            self.session_btn.setStyleSheet("""
                QPushButton {
                    background: #003300;
                    color: #00ff00;
                    border: 1px solid #00ff00;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #004400; }
            """)
        else:
            self.session_active = True
            self.session_btn.setText("⏹️ End Session")
            self.session_btn.setStyleSheet("""
                QPushButton {
                    background: #330000;
                    color: #ff0000;
                    border: 1px solid #ff0000;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #440000; }
            """)
    
    def send_message(self):
        text = self.message_input.text()
        if text.strip():
            msg = {
                'sender': 'You',
                'content': text,
                'time': datetime.now().strftime('%H:%M'),
                'is_own': True,
                'type': 'command' if text.startswith('/') else 'text'
            }
            widget = ChatMessageWidget(msg)
            self.messages_layout.addWidget(widget)
            self.message_input.clear()
