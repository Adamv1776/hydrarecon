"""
Active Directory Attack Suite Page
Comprehensive AD enumeration and exploitation interface
"""

import asyncio
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QPlainTextEdit, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.ad_attacks import (
    ActiveDirectoryAttacks, ADAttackType, PrivilegeLevel,
    ADUser, ADComputer, ADGroup, DomainInfo, KerberosTicket, Credential
)


class ADWorker(QThread):
    """Background worker for AD operations"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.func(*self.args, **self.kwargs))
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class ADAttacksPage(QWidget):
    """Active Directory Attack Suite GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ad = ActiveDirectoryAttacks()
        self.workers = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🏢 Active Directory Attack Suite")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #00ccff;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Warning
        warning = QLabel("⚠️ FOR AUTHORIZED PENETRATION TESTING ONLY - REQUIRES PROPER AUTHORIZATION")
        warning.setStyleSheet("""
            background: #00ccff22;
            border: 2px solid #00ccff;
            color: #00ccff;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
        """)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #333;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #00ccff;
                color: #000;
            }
        """)
        
        tabs.addTab(self.create_enum_tab(), "🔍 Enumeration")
        tabs.addTab(self.create_kerberos_tab(), "🎫 Kerberos Attacks")
        tabs.addTab(self.create_credential_tab(), "🔑 Credential Attacks")
        tabs.addTab(self.create_delegation_tab(), "🔗 Delegation Abuse")
        tabs.addTab(self.create_paths_tab(), "🗺️ Attack Paths")
        tabs.addTab(self.create_persistence_tab(), "⚓ Persistence")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QLabel("Active Directory Attack Suite Ready")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #00ccff;
        """)
        layout.addWidget(self.status_bar)
    
    def create_enum_tab(self) -> QWidget:
        """Create enumeration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Connection settings
        conn_group = QGroupBox("Domain Connection")
        conn_group.setStyleSheet("""
            QGroupBox { font-weight: bold; border: 2px solid #00ccff; border-radius: 8px; margin-top: 10px; padding-top: 10px; }
            QGroupBox::title { color: #00ccff; }
        """)
        conn_layout = QFormLayout(conn_group)
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("corp.local")
        conn_layout.addRow("Domain:", self.domain_input)
        
        self.dc_input = QLineEdit()
        self.dc_input.setPlaceholderText("dc01.corp.local (auto-detect if empty)")
        conn_layout.addRow("Domain Controller:", self.dc_input)
        
        self.ad_username = QLineEdit()
        self.ad_username.setPlaceholderText("user@corp.local")
        conn_layout.addRow("Username:", self.ad_username)
        
        self.ad_password = QLineEdit()
        self.ad_password.setEchoMode(QLineEdit.EchoMode.Password)
        conn_layout.addRow("Password:", self.ad_password)
        
        self.use_ldaps = QCheckBox("Use LDAPS (636)")
        conn_layout.addRow("", self.use_ldaps)
        
        enum_btn = QPushButton("🔍 Enumerate Domain")
        enum_btn.clicked.connect(self.enumerate_domain)
        enum_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #00ccff, #0088ff);
                color: #000;
                font-weight: bold;
                padding: 15px;
                font-size: 14px;
            }
        """)
        conn_layout.addRow("", enum_btn)
        
        layout.addWidget(conn_group)
        
        # Domain info
        info_group = QGroupBox("Domain Information")
        info_layout = QVBoxLayout(info_group)
        
        self.domain_info_text = QPlainTextEdit()
        self.domain_info_text.setReadOnly(True)
        self.domain_info_text.setMaximumHeight(150)
        self.domain_info_text.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        info_layout.addWidget(self.domain_info_text)
        
        layout.addWidget(info_group)
        
        # Statistics cards
        stats_group = QGroupBox("Attack Surface")
        stats_layout = QHBoxLayout(stats_group)
        
        self.stat_cards = {}
        stat_items = [
            ("Users", "users", "#00ccff"),
            ("Computers", "computers", "#ff6600"),
            ("Kerberoastable", "kerberoastable", "#ff0044"),
            ("AS-REP Roast", "asrep", "#ff00ff"),
            ("Delegatable", "delegatable", "#ffaa00"),
            ("DCs", "dcs", "#00ff88"),
        ]
        
        for name, key, color in stat_items:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: linear-gradient(135deg, {color}22, {color}44);
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 10px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            
            count = QLabel("0")
            count.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
            count.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            label = QLabel(name)
            label.setStyleSheet("font-size: 10px; color: #888;")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(count)
            card_layout.addWidget(label)
            
            self.stat_cards[key] = count
            stats_layout.addWidget(card)
        
        layout.addWidget(stats_group)
        
        # Enumerated objects tabs
        objects_tabs = QTabWidget()
        
        # Users tab
        users_widget = QWidget()
        users_layout = QVBoxLayout(users_widget)
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(6)
        self.users_table.setHorizontalHeaderLabels([
            "Username", "Privileged", "Kerberoastable", "AS-REP", "Delegation", "SPNs"
        ])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        users_layout.addWidget(self.users_table)
        objects_tabs.addTab(users_widget, "👤 Users")
        
        # Computers tab
        computers_widget = QWidget()
        computers_layout = QVBoxLayout(computers_widget)
        self.computers_table = QTableWidget()
        self.computers_table.setColumnCount(5)
        self.computers_table.setHorizontalHeaderLabels([
            "Name", "OS", "Is DC", "Delegation", "LAPS"
        ])
        self.computers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        computers_layout.addWidget(self.computers_table)
        objects_tabs.addTab(computers_widget, "💻 Computers")
        
        # Groups tab
        groups_widget = QWidget()
        groups_layout = QVBoxLayout(groups_widget)
        self.groups_table = QTableWidget()
        self.groups_table.setColumnCount(3)
        self.groups_table.setHorizontalHeaderLabels([
            "Name", "Admin Count", "Members"
        ])
        self.groups_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        groups_layout.addWidget(self.groups_table)
        objects_tabs.addTab(groups_widget, "👥 Groups")
        
        layout.addWidget(objects_tabs)
        
        return widget
    
    def create_kerberos_tab(self) -> QWidget:
        """Create Kerberos attacks tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Attack options
        attack_group = QGroupBox("Kerberos Attack Options")
        attack_layout = QVBoxLayout(attack_group)
        
        # Kerberoasting
        kerb_layout = QHBoxLayout()
        kerb_layout.addWidget(QLabel("Kerberoasting:"))
        
        self.kerb_target = QLineEdit()
        self.kerb_target.setPlaceholderText("Target user (empty = all kerberoastable)")
        kerb_layout.addWidget(self.kerb_target)
        
        kerb_btn = QPushButton("🎫 Kerberoast")
        kerb_btn.clicked.connect(self.kerberoast)
        kerb_btn.setStyleSheet("background: #ff0044; color: #fff; font-weight: bold;")
        kerb_layout.addWidget(kerb_btn)
        
        attack_layout.addLayout(kerb_layout)
        
        # AS-REP Roasting
        asrep_layout = QHBoxLayout()
        asrep_layout.addWidget(QLabel("AS-REP Roasting:"))
        
        self.asrep_target = QLineEdit()
        self.asrep_target.setPlaceholderText("Target user (empty = all AS-REP roastable)")
        asrep_layout.addWidget(self.asrep_target)
        
        asrep_btn = QPushButton("🎫 AS-REP Roast")
        asrep_btn.clicked.connect(self.asrep_roast)
        asrep_btn.setStyleSheet("background: #ff00ff; color: #fff; font-weight: bold;")
        asrep_layout.addWidget(asrep_btn)
        
        attack_layout.addLayout(asrep_layout)
        
        layout.addWidget(attack_group)
        
        # Ticket forging
        forge_group = QGroupBox("Ticket Forging")
        forge_layout = QFormLayout(forge_group)
        
        self.krbtgt_hash = QLineEdit()
        self.krbtgt_hash.setPlaceholderText("NTLM hash of krbtgt account")
        forge_layout.addRow("krbtgt Hash:", self.krbtgt_hash)
        
        self.golden_user = QLineEdit("Administrator")
        forge_layout.addRow("Impersonate User:", self.golden_user)
        
        forge_btns = QHBoxLayout()
        golden_btn = QPushButton("🥇 Forge Golden Ticket")
        golden_btn.clicked.connect(self.forge_golden_ticket)
        golden_btn.setStyleSheet("background: #ffd700; color: #000; font-weight: bold;")
        forge_btns.addWidget(golden_btn)
        
        silver_btn = QPushButton("🥈 Forge Silver Ticket")
        silver_btn.clicked.connect(self.forge_silver_ticket)
        silver_btn.setStyleSheet("background: #c0c0c0; color: #000; font-weight: bold;")
        forge_btns.addWidget(silver_btn)
        
        forge_layout.addRow("", forge_btns)
        
        layout.addWidget(forge_group)
        
        # Captured tickets
        tickets_group = QGroupBox("Captured Tickets")
        tickets_layout = QVBoxLayout(tickets_group)
        
        self.tickets_table = QTableWidget()
        self.tickets_table.setColumnCount(5)
        self.tickets_table.setHorizontalHeaderLabels([
            "Type", "Service", "User", "Encryption", "Action"
        ])
        self.tickets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tickets_layout.addWidget(self.tickets_table)
        
        export_layout = QHBoxLayout()
        export_hashcat = QPushButton("📤 Export for Hashcat")
        export_hashcat.clicked.connect(self.export_hashcat)
        export_layout.addWidget(export_hashcat)
        
        export_john = QPushButton("📤 Export for John")
        export_john.clicked.connect(self.export_john)
        export_layout.addWidget(export_john)
        
        export_layout.addStretch()
        tickets_layout.addLayout(export_layout)
        
        layout.addWidget(tickets_group)
        
        return widget
    
    def create_credential_tab(self) -> QWidget:
        """Create credential attacks tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # DCSync
        dcsync_group = QGroupBox("DCSync Attack")
        dcsync_layout = QFormLayout(dcsync_group)
        
        self.dcsync_target = QLineEdit()
        self.dcsync_target.setPlaceholderText("Target user (empty = all privileged)")
        dcsync_layout.addRow("Target User:", self.dcsync_target)
        
        dcsync_btn = QPushButton("🔄 Perform DCSync")
        dcsync_btn.clicked.connect(self.perform_dcsync)
        dcsync_btn.setStyleSheet("background: #ff0044; color: #fff; font-weight: bold; padding: 10px;")
        dcsync_layout.addRow("", dcsync_btn)
        
        layout.addWidget(dcsync_group)
        
        # Pass the Hash
        pth_group = QGroupBox("Pass-the-Hash / Overpass-the-Hash")
        pth_layout = QFormLayout(pth_group)
        
        self.pth_target = QLineEdit()
        self.pth_target.setPlaceholderText("Target host (IP or hostname)")
        pth_layout.addRow("Target:", self.pth_target)
        
        self.pth_user = QLineEdit()
        self.pth_user.setPlaceholderText("domain\\username")
        pth_layout.addRow("Username:", self.pth_user)
        
        self.pth_hash = QLineEdit()
        self.pth_hash.setPlaceholderText("NTLM hash")
        pth_layout.addRow("NT Hash:", self.pth_hash)
        
        self.pth_command = QLineEdit("whoami")
        pth_layout.addRow("Command:", self.pth_command)
        
        pth_btns = QHBoxLayout()
        pth_btn = QPushButton("🔓 Pass-the-Hash")
        pth_btn.clicked.connect(self.pass_the_hash)
        pth_btns.addWidget(pth_btn)
        
        opth_btn = QPushButton("🎫 Overpass-the-Hash")
        opth_btn.clicked.connect(self.overpass_the_hash)
        pth_btns.addWidget(opth_btn)
        
        pth_layout.addRow("", pth_btns)
        
        layout.addWidget(pth_group)
        
        # Captured credentials
        creds_group = QGroupBox("Captured Credentials")
        creds_layout = QVBoxLayout(creds_group)
        
        self.creds_table = QTableWidget()
        self.creds_table.setColumnCount(5)
        self.creds_table.setHorizontalHeaderLabels([
            "Username", "Domain", "Type", "Value", "Source"
        ])
        self.creds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        creds_layout.addWidget(self.creds_table)
        
        layout.addWidget(creds_group)
        
        # Command output
        output_group = QGroupBox("Command Output")
        output_layout = QVBoxLayout(output_group)
        
        self.cred_output = QPlainTextEdit()
        self.cred_output.setReadOnly(True)
        self.cred_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        output_layout.addWidget(self.cred_output)
        
        layout.addWidget(output_group)
        
        return widget
    
    def create_delegation_tab(self) -> QWidget:
        """Create delegation abuse tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Find delegation targets
        find_group = QGroupBox("Find Delegation Targets")
        find_layout = QVBoxLayout(find_group)
        
        find_btn = QPushButton("🔍 Find Delegation Targets")
        find_btn.clicked.connect(self.find_delegation)
        find_btn.setStyleSheet("background: #00ccff; color: #000; font-weight: bold; padding: 10px;")
        find_layout.addWidget(find_btn)
        
        layout.addWidget(find_group)
        
        # Delegation types
        delegation_tabs = QTabWidget()
        
        # Unconstrained
        unconst_widget = QWidget()
        unconst_layout = QVBoxLayout(unconst_widget)
        
        unconst_info = QLabel("""
Unconstrained Delegation allows a service to impersonate any user to any service.
If compromised, can capture TGTs of users connecting to the service.
Attack: Coerce authentication from DC, capture TGT, use for DCSync.
        """)
        unconst_info.setWordWrap(True)
        unconst_info.setStyleSheet("color: #888; padding: 10px;")
        unconst_layout.addWidget(unconst_info)
        
        self.unconstrained_table = QTableWidget()
        self.unconstrained_table.setColumnCount(3)
        self.unconstrained_table.setHorizontalHeaderLabels(["Name", "Type", "DN"])
        self.unconstrained_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        unconst_layout.addWidget(self.unconstrained_table)
        
        delegation_tabs.addTab(unconst_widget, "Unconstrained")
        
        # Constrained
        const_widget = QWidget()
        const_layout = QVBoxLayout(const_widget)
        
        const_info = QLabel("""
Constrained Delegation (with protocol transition) allows impersonation to specific services.
Attack: Use S4U2Self and S4U2Proxy to get TGS for target service as any user.
        """)
        const_info.setWordWrap(True)
        const_info.setStyleSheet("color: #888; padding: 10px;")
        const_layout.addWidget(const_info)
        
        self.constrained_table = QTableWidget()
        self.constrained_table.setColumnCount(2)
        self.constrained_table.setHorizontalHeaderLabels(["Account", "Allowed Targets"])
        self.constrained_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        const_layout.addWidget(self.constrained_table)
        
        delegation_tabs.addTab(const_widget, "Constrained")
        
        # RBCD
        rbcd_widget = QWidget()
        rbcd_layout = QVBoxLayout(rbcd_widget)
        
        rbcd_info = QLabel("""
Resource-Based Constrained Delegation allows controlling which accounts can delegate TO a resource.
Attack: If you can write msDS-AllowedToActOnBehalfOfOtherIdentity, add your own account.
        """)
        rbcd_info.setWordWrap(True)
        rbcd_info.setStyleSheet("color: #888; padding: 10px;")
        rbcd_layout.addWidget(rbcd_info)
        
        self.rbcd_table = QTableWidget()
        self.rbcd_table.setColumnCount(2)
        self.rbcd_table.setHorizontalHeaderLabels(["Target", "Allowed Principals"])
        self.rbcd_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        rbcd_layout.addWidget(self.rbcd_table)
        
        delegation_tabs.addTab(rbcd_widget, "Resource-Based")
        
        layout.addWidget(delegation_tabs)
        
        # Abuse delegation
        abuse_group = QGroupBox("Abuse Constrained Delegation")
        abuse_layout = QFormLayout(abuse_group)
        
        self.cd_source = QLineEdit()
        self.cd_source.setPlaceholderText("Source account with delegation")
        abuse_layout.addRow("Source Account:", self.cd_source)
        
        self.cd_hash = QLineEdit()
        self.cd_hash.setPlaceholderText("NTLM hash of source account")
        abuse_layout.addRow("Source Hash:", self.cd_hash)
        
        self.cd_target_spn = QLineEdit()
        self.cd_target_spn.setPlaceholderText("cifs/dc01.corp.local")
        abuse_layout.addRow("Target SPN:", self.cd_target_spn)
        
        self.cd_impersonate = QLineEdit("Administrator")
        abuse_layout.addRow("Impersonate:", self.cd_impersonate)
        
        abuse_btn = QPushButton("🔗 Abuse Delegation")
        abuse_btn.clicked.connect(self.abuse_delegation)
        abuse_btn.setStyleSheet("background: #ff6600; color: #000; font-weight: bold;")
        abuse_layout.addRow("", abuse_btn)
        
        layout.addWidget(abuse_group)
        
        return widget
    
    def create_paths_tab(self) -> QWidget:
        """Create attack paths tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Path generation
        gen_group = QGroupBox("Generate Attack Paths")
        gen_layout = QFormLayout(gen_group)
        
        self.path_start = QLineEdit()
        self.path_start.setPlaceholderText("Starting user/computer")
        gen_layout.addRow("Start From:", self.path_start)
        
        self.path_target = QComboBox()
        self.path_target.addItems([
            "Domain Admins",
            "Enterprise Admins",
            "Domain Controllers",
            "Specific User",
            "Specific Computer"
        ])
        gen_layout.addRow("Target:", self.path_target)
        
        gen_btn = QPushButton("🗺️ Generate Attack Paths")
        gen_btn.clicked.connect(self.generate_paths)
        gen_btn.setStyleSheet("background: #00ff88; color: #000; font-weight: bold; padding: 10px;")
        gen_layout.addRow("", gen_btn)
        
        layout.addWidget(gen_group)
        
        # Attack paths display
        paths_group = QGroupBox("Discovered Attack Paths")
        paths_layout = QVBoxLayout(paths_group)
        
        self.paths_tree = QTreeWidget()
        self.paths_tree.setHeaderLabels(["Path / Step", "Technique", "Success Rate"])
        self.paths_tree.setColumnWidth(0, 300)
        paths_layout.addWidget(self.paths_tree)
        
        layout.addWidget(paths_group)
        
        # BloodHound export
        export_group = QGroupBox("Export")
        export_layout = QHBoxLayout(export_group)
        
        bloodhound_btn = QPushButton("🩸 Export to BloodHound")
        bloodhound_btn.clicked.connect(self.export_bloodhound)
        export_layout.addWidget(bloodhound_btn)
        
        json_btn = QPushButton("📄 Export JSON")
        json_btn.clicked.connect(self.export_json)
        export_layout.addWidget(json_btn)
        
        export_layout.addStretch()
        
        layout.addWidget(export_group)
        
        return widget
    
    def create_persistence_tab(self) -> QWidget:
        """Create persistence tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Persistence options
        options_group = QGroupBox("Persistence Mechanisms")
        options_layout = QVBoxLayout(options_group)
        
        persistence_options = self.ad.generate_persistence_options()
        
        self.persistence_list = QListWidget()
        for opt in persistence_options:
            item = QListWidgetItem(f"⚓ {opt['name']}")
            item.setData(Qt.ItemDataRole.UserRole, opt)
            self.persistence_list.addItem(item)
        self.persistence_list.itemClicked.connect(self.show_persistence_details)
        options_layout.addWidget(self.persistence_list)
        
        layout.addWidget(options_group)
        
        # Details
        details_group = QGroupBox("Persistence Details")
        details_layout = QVBoxLayout(details_group)
        
        self.persistence_details = QPlainTextEdit()
        self.persistence_details.setReadOnly(True)
        self.persistence_details.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ccff;
            }
        """)
        details_layout.addWidget(self.persistence_details)
        
        layout.addWidget(details_group)
        
        # Implementation
        impl_group = QGroupBox("Implement Persistence")
        impl_layout = QFormLayout(impl_group)
        
        self.persist_hash = QLineEdit()
        self.persist_hash.setPlaceholderText("Required hash (krbtgt for Golden, service for Silver)")
        impl_layout.addRow("Hash:", self.persist_hash)
        
        impl_btn = QPushButton("⚓ Implement Persistence")
        impl_btn.clicked.connect(self.implement_persistence)
        impl_btn.setStyleSheet("background: #ff0044; color: #fff; font-weight: bold;")
        impl_layout.addRow("", impl_btn)
        
        layout.addWidget(impl_group)
        
        return widget
    
    # ========== Event Handlers ==========
    
    def enumerate_domain(self):
        """Enumerate domain"""
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Error", "Enter a domain name")
            return
        
        self.status_bar.setText("🔍 Enumerating domain...")
        
        dc = self.dc_input.text().strip() or None
        username = self.ad_username.text().strip()
        password = self.ad_password.text()
        
        worker = ADWorker(self.ad.enumerate_domain, domain, username, password, self.use_ldaps.isChecked())
        worker.result_ready.connect(self.on_domain_enumerated)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
        
        # Also enumerate users/computers/groups
        worker2 = ADWorker(self.ad.enumerate_users, dc or "", domain, username, password)
        worker2.result_ready.connect(self.on_users_enumerated)
        worker2.start()
        self.workers.append(worker2)
        
        worker3 = ADWorker(self.ad.enumerate_computers, dc or "", domain, username, password)
        worker3.result_ready.connect(self.on_computers_enumerated)
        worker3.start()
        self.workers.append(worker3)
        
        worker4 = ADWorker(self.ad.enumerate_groups, dc or "", domain, username, password)
        worker4.result_ready.connect(self.on_groups_enumerated)
        worker4.start()
        self.workers.append(worker4)
    
    def on_domain_enumerated(self, info: DomainInfo):
        """Handle domain enumeration complete"""
        text = f"""Domain: {info.name}
DNS Name: {info.dns_name}
SID: {info.sid}
Domain Controllers: {', '.join(info.domain_controllers)}
Functional Level: {info.functional_level}

Password Policy:
  Min Length: {info.password_policy.get('min_length', 'N/A')}
  Complexity: {info.password_policy.get('complexity', 'N/A')}
  Lockout Threshold: {info.password_policy.get('lockout_threshold', 'N/A')}
"""
        self.domain_info_text.setPlainText(text)
        self.status_bar.setText(f"✅ Domain enumerated: {info.name}")
    
    def on_users_enumerated(self, users: list):
        """Handle users enumerated"""
        self.users_table.setRowCount(0)
        
        for user in users:
            row = self.users_table.rowCount()
            self.users_table.insertRow(row)
            
            self.users_table.setItem(row, 0, QTableWidgetItem(user.sam_account_name))
            
            priv = QTableWidgetItem("✅" if user.privileged or user.admin_count else "")
            if user.privileged:
                priv.setForeground(QColor("#ff0044"))
            self.users_table.setItem(row, 1, priv)
            
            kerb = QTableWidgetItem("✅" if user.service_principal_names else "")
            if user.service_principal_names:
                kerb.setForeground(QColor("#ff6600"))
            self.users_table.setItem(row, 2, kerb)
            
            asrep = QTableWidgetItem("✅" if user.dont_require_preauth else "")
            if user.dont_require_preauth:
                asrep.setForeground(QColor("#ff00ff"))
            self.users_table.setItem(row, 3, asrep)
            
            deleg = QTableWidgetItem("✅" if user.trusted_for_delegation else "")
            self.users_table.setItem(row, 4, deleg)
            
            self.users_table.setItem(row, 5, QTableWidgetItem(
                ", ".join(user.service_principal_names) if user.service_principal_names else ""
            ))
        
        self.update_stats()
    
    def on_computers_enumerated(self, computers: list):
        """Handle computers enumerated"""
        self.computers_table.setRowCount(0)
        
        for comp in computers:
            row = self.computers_table.rowCount()
            self.computers_table.insertRow(row)
            
            self.computers_table.setItem(row, 0, QTableWidgetItem(comp.name))
            self.computers_table.setItem(row, 1, QTableWidgetItem(comp.operating_system))
            
            dc = QTableWidgetItem("✅" if comp.is_dc else "")
            if comp.is_dc:
                dc.setForeground(QColor("#00ff88"))
            self.computers_table.setItem(row, 2, dc)
            
            deleg = QTableWidgetItem("✅" if comp.trusted_for_delegation else "")
            if comp.trusted_for_delegation:
                deleg.setForeground(QColor("#ffaa00"))
            self.computers_table.setItem(row, 3, deleg)
            
            self.computers_table.setItem(row, 4, QTableWidgetItem(
                "Yes" if comp.laps_password else ""
            ))
        
        self.update_stats()
    
    def on_groups_enumerated(self, groups: list):
        """Handle groups enumerated"""
        self.groups_table.setRowCount(0)
        
        for group in groups:
            row = self.groups_table.rowCount()
            self.groups_table.insertRow(row)
            
            self.groups_table.setItem(row, 0, QTableWidgetItem(group.name))
            self.groups_table.setItem(row, 1, QTableWidgetItem("✅" if group.admin_count else ""))
            self.groups_table.setItem(row, 2, QTableWidgetItem(str(len(group.members))))
    
    def update_stats(self):
        """Update statistics cards"""
        stats = self.ad.get_statistics()
        
        if "users" in self.stat_cards:
            self.stat_cards["users"].setText(str(stats.get("total_users", 0)))
        if "computers" in self.stat_cards:
            self.stat_cards["computers"].setText(str(stats.get("total_computers", 0)))
        if "kerberoastable" in self.stat_cards:
            self.stat_cards["kerberoastable"].setText(str(stats.get("kerberoastable", 0)))
        if "asrep" in self.stat_cards:
            self.stat_cards["asrep"].setText(str(stats.get("asreproastable", 0)))
        if "delegatable" in self.stat_cards:
            self.stat_cards["delegatable"].setText(str(stats.get("delegatable", 0)))
        if "dcs" in self.stat_cards:
            self.stat_cards["dcs"].setText(str(stats.get("dcs", 0)))
    
    def kerberoast(self):
        """Perform Kerberoasting"""
        domain = self.domain_input.text().strip()
        dc = self.dc_input.text().strip()
        username = self.ad_username.text().strip()
        password = self.ad_password.text()
        target = self.kerb_target.text().strip() or None
        
        if not domain:
            QMessageBox.warning(self, "Error", "Enumerate domain first")
            return
        
        self.status_bar.setText("🎫 Kerberoasting...")
        
        targets = [target] if target else None
        worker = ADWorker(self.ad.kerberoast, dc, domain, username, password, targets)
        worker.result_ready.connect(self.on_tickets_received)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def asrep_roast(self):
        """Perform AS-REP Roasting"""
        domain = self.domain_input.text().strip()
        dc = self.dc_input.text().strip()
        target = self.asrep_target.text().strip() or None
        
        if not domain:
            QMessageBox.warning(self, "Error", "Enumerate domain first")
            return
        
        self.status_bar.setText("🎫 AS-REP Roasting...")
        
        targets = [target] if target else None
        worker = ADWorker(self.ad.asrep_roast, dc, domain, targets)
        worker.result_ready.connect(self.on_tickets_received)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def on_tickets_received(self, tickets: list):
        """Handle tickets received"""
        for ticket in tickets:
            row = self.tickets_table.rowCount()
            self.tickets_table.insertRow(row)
            
            self.tickets_table.setItem(row, 0, QTableWidgetItem(ticket.ticket_type.upper()))
            self.tickets_table.setItem(row, 1, QTableWidgetItem(ticket.spn or ticket.service))
            self.tickets_table.setItem(row, 2, QTableWidgetItem(ticket.username))
            self.tickets_table.setItem(row, 3, QTableWidgetItem(f"etype {ticket.encryption_type}"))
            
            copy_btn = QPushButton("📋")
            copy_btn.clicked.connect(lambda checked, h=ticket.hash_value: self.copy_hash(h))
            self.tickets_table.setCellWidget(row, 4, copy_btn)
        
        self.status_bar.setText(f"🎫 Captured {len(tickets)} tickets")
    
    def copy_hash(self, hash_value: str):
        """Copy hash to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(hash_value)
        self.status_bar.setText("📋 Hash copied to clipboard")
    
    def forge_golden_ticket(self):
        """Forge golden ticket"""
        domain = self.domain_input.text().strip()
        krbtgt_hash = self.krbtgt_hash.text().strip()
        user = self.golden_user.text().strip()
        
        if not domain or not krbtgt_hash:
            QMessageBox.warning(self, "Error", "Enter domain and krbtgt hash")
            return
        
        domain_sid = self.ad.domain_info.sid if self.ad.domain_info else ""
        
        worker = ADWorker(self.ad.forge_golden_ticket, domain, domain_sid, krbtgt_hash, user)
        worker.result_ready.connect(lambda t: self.on_tickets_received([t]))
        worker.start()
        self.workers.append(worker)
    
    def forge_silver_ticket(self):
        """Forge silver ticket"""
        QMessageBox.information(self, "Silver Ticket", "Configure service hash and target to forge silver ticket")
    
    def perform_dcsync(self):
        """Perform DCSync"""
        domain = self.domain_input.text().strip()
        dc = self.dc_input.text().strip()
        username = self.ad_username.text().strip()
        password = self.ad_password.text()
        target = self.dcsync_target.text().strip() or None
        
        if not domain:
            QMessageBox.warning(self, "Error", "Enumerate domain first")
            return
        
        self.status_bar.setText("🔄 Performing DCSync...")
        
        worker = ADWorker(self.ad.dcsync, dc, domain, username, password, target)
        worker.result_ready.connect(self.on_credentials_received)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def on_credentials_received(self, creds: list):
        """Handle credentials received"""
        for cred in creds:
            row = self.creds_table.rowCount()
            self.creds_table.insertRow(row)
            
            self.creds_table.setItem(row, 0, QTableWidgetItem(cred.username))
            self.creds_table.setItem(row, 1, QTableWidgetItem(cred.domain))
            self.creds_table.setItem(row, 2, QTableWidgetItem(cred.credential_type))
            self.creds_table.setItem(row, 3, QTableWidgetItem(cred.value))
            self.creds_table.setItem(row, 4, QTableWidgetItem(cred.source))
        
        self.status_bar.setText(f"🔑 Captured {len(creds)} credentials")
    
    def pass_the_hash(self):
        """Execute pass-the-hash"""
        target = self.pth_target.text().strip()
        user = self.pth_user.text().strip()
        nt_hash = self.pth_hash.text().strip()
        command = self.pth_command.text().strip()
        
        if not all([target, user, nt_hash]):
            QMessageBox.warning(self, "Error", "Fill all PTH fields")
            return
        
        domain = user.split('\\')[0] if '\\' in user else ""
        username = user.split('\\')[1] if '\\' in user else user
        
        worker = ADWorker(self.ad.pass_the_hash, target, domain, username, nt_hash, command)
        worker.result_ready.connect(lambda r: self.cred_output.setPlainText(r.get("output", "")))
        worker.start()
        self.workers.append(worker)
    
    def overpass_the_hash(self):
        """Execute overpass-the-hash"""
        domain = self.domain_input.text().strip()
        user = self.pth_user.text().strip()
        nt_hash = self.pth_hash.text().strip()
        
        if not all([domain, user, nt_hash]):
            QMessageBox.warning(self, "Error", "Fill domain and PTH fields")
            return
        
        username = user.split('\\')[1] if '\\' in user else user
        
        worker = ADWorker(self.ad.overpass_the_hash, domain, username, nt_hash)
        worker.result_ready.connect(lambda t: self.on_tickets_received([t]))
        worker.start()
        self.workers.append(worker)
    
    def find_delegation(self):
        """Find delegation targets"""
        worker = ADWorker(self.ad.find_delegation_targets)
        worker.result_ready.connect(self.on_delegation_found)
        worker.start()
        self.workers.append(worker)
    
    def on_delegation_found(self, results: dict):
        """Handle delegation targets found"""
        # Unconstrained
        self.unconstrained_table.setRowCount(0)
        for item in results.get("unconstrained_delegation", []):
            row = self.unconstrained_table.rowCount()
            self.unconstrained_table.insertRow(row)
            self.unconstrained_table.setItem(row, 0, QTableWidgetItem(item["name"]))
            self.unconstrained_table.setItem(row, 1, QTableWidgetItem(item["type"]))
            self.unconstrained_table.setItem(row, 2, QTableWidgetItem(item["dn"]))
        
        # Constrained
        self.constrained_table.setRowCount(0)
        for item in results.get("constrained_delegation", []):
            row = self.constrained_table.rowCount()
            self.constrained_table.insertRow(row)
            self.constrained_table.setItem(row, 0, QTableWidgetItem(item["name"]))
            self.constrained_table.setItem(row, 1, QTableWidgetItem(", ".join(item["targets"])))
        
        self.status_bar.setText(f"🔗 Found delegation targets")
    
    def abuse_delegation(self):
        """Abuse constrained delegation"""
        source = self.cd_source.text().strip()
        source_hash = self.cd_hash.text().strip()
        target_spn = self.cd_target_spn.text().strip()
        impersonate = self.cd_impersonate.text().strip()
        
        if not all([source, source_hash, target_spn]):
            QMessageBox.warning(self, "Error", "Fill all delegation abuse fields")
            return
        
        worker = ADWorker(self.ad.abuse_constrained_delegation, source, source_hash, target_spn, impersonate)
        worker.result_ready.connect(lambda t: self.on_tickets_received([t]))
        worker.start()
        self.workers.append(worker)
    
    def generate_paths(self):
        """Generate attack paths"""
        start = self.path_start.text().strip() or "current_user"
        target = self.path_target.currentText()
        
        paths = self.ad.generate_attack_paths(start, target)
        
        self.paths_tree.clear()
        
        for i, path in enumerate(paths):
            path_item = QTreeWidgetItem([
                f"Path {i+1}: {path.source} → {path.target}",
                "",
                f"{path.success_probability:.0%}"
            ])
            
            for step in path.steps:
                step_item = QTreeWidgetItem([
                    f"  ↳ {step.get('target', '')}",
                    step.get('technique', ''),
                    ""
                ])
                path_item.addChild(step_item)
            
            self.paths_tree.addTopLevelItem(path_item)
        
        self.paths_tree.expandAll()
        self.status_bar.setText(f"🗺️ Generated {len(paths)} attack paths")
    
    def show_persistence_details(self, item):
        """Show persistence mechanism details"""
        opt = item.data(Qt.ItemDataRole.UserRole)
        if opt:
            text = f"""
{opt['name']}
{'=' * 40}

Description:
{opt['description']}

Requirements:
{chr(10).join('  • ' + r for r in opt['requirements'])}

Stealth Level: {opt['stealth'].upper()}
"""
            self.persistence_details.setPlainText(text)
    
    def implement_persistence(self):
        """Implement selected persistence"""
        current = self.persistence_list.currentItem()
        if not current:
            QMessageBox.warning(self, "Error", "Select a persistence mechanism")
            return
        
        opt = current.data(Qt.ItemDataRole.UserRole)
        QMessageBox.information(self, "Persistence", f"Implementing {opt['name']}...")
    
    def export_hashcat(self):
        """Export tickets for hashcat"""
        hashes = self.ad.export_hashcat_format()
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Hashes", "kerberos_hashes.txt",
            "Text Files (*.txt)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(hashes)
            self.status_bar.setText(f"📤 Exported to {filepath}")
    
    def export_john(self):
        """Export for John the Ripper"""
        self.export_hashcat()  # Same format
    
    def export_bloodhound(self):
        """Export to BloodHound format"""
        import json
        data = self.ad.export_bloodhound()
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export BloodHound", "bloodhound_data.json",
            "JSON Files (*.json)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            self.status_bar.setText(f"🩸 Exported to {filepath}")
    
    def export_json(self):
        """Export all data as JSON"""
        import json
        data = {
            "domain": self.ad.domain_info.__dict__ if self.ad.domain_info else {},
            "users": [u.__dict__ for u in self.ad.users.values()],
            "computers": [c.__dict__ for c in self.ad.computers.values()],
            "statistics": self.ad.get_statistics()
        }
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "ad_data.json",
            "JSON Files (*.json)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            self.status_bar.setText(f"📄 Exported to {filepath}")
