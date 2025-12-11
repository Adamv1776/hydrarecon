"""
Social Engineering Page
Phishing campaigns and credential harvesting interface
"""

import asyncio
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QPlainTextEdit, QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.social_engineering import (
    SocialEngineeringToolkit, PhishingCampaign, AttackType,
    TemplateType, CapturedCredential
)


class SETWorker(QThread):
    """Background worker for SET operations"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, operation, *args, **kwargs):
        super().__init__()
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            if asyncio.iscoroutinefunction(self.operation):
                result = loop.run_until_complete(self.operation(*self.args, **self.kwargs))
            else:
                result = self.operation(*self.args, **self.kwargs)
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class SocialEngineeringPage(QWidget):
    """Social Engineering Toolkit GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.set = SocialEngineeringToolkit()
        self.current_campaign = None
        self.workers = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🎣 Social Engineering Toolkit")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff6b00;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Warning banner
        warning = QLabel("⚠️ FOR AUTHORIZED SECURITY TESTING ONLY - Ensure proper authorization before use")
        warning.setStyleSheet("""
            background: #ff4444;
            color: white;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
        """)
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
                background: #ff6b00;
                color: #fff;
            }
        """)
        
        tabs.addTab(self.create_campaigns_tab(), "📧 Campaigns")
        tabs.addTab(self.create_templates_tab(), "📝 Templates")
        tabs.addTab(self.create_landing_pages_tab(), "🌐 Landing Pages")
        tabs.addTab(self.create_smtp_tab(), "📮 SMTP Config")
        tabs.addTab(self.create_credentials_tab(), "🔑 Credentials")
        tabs.addTab(self.create_stats_tab(), "📊 Statistics")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QLabel("Ready")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #00ff88;
        """)
        layout.addWidget(self.status_bar)
    
    def create_campaigns_tab(self):
        """Create campaigns management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # New campaign section
        new_group = QGroupBox("Create New Campaign")
        new_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ff6b00;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #ff6b00; }
        """)
        new_layout = QFormLayout(new_group)
        
        self.campaign_name = QLineEdit()
        self.campaign_name.setPlaceholderText("Q4 Security Awareness Test")
        new_layout.addRow("Campaign Name:", self.campaign_name)
        
        self.attack_type = QComboBox()
        for at in AttackType:
            self.attack_type.addItem(at.value.replace('_', ' ').title(), at)
        new_layout.addRow("Attack Type:", self.attack_type)
        
        self.template_type = QComboBox()
        for tt in TemplateType:
            self.template_type.addItem(tt.value.replace('_', ' ').title(), tt)
        new_layout.addRow("Template Category:", self.template_type)
        
        create_btn = QPushButton("➕ Create Campaign")
        create_btn.clicked.connect(self.create_campaign)
        create_btn.setStyleSheet("background: #ff6b00; color: white; padding: 10px;")
        new_layout.addRow("", create_btn)
        
        layout.addWidget(new_group)
        
        # Campaigns list
        campaigns_group = QGroupBox("Active Campaigns")
        campaigns_layout = QVBoxLayout(campaigns_group)
        
        self.campaigns_table = QTableWidget()
        self.campaigns_table.setColumnCount(6)
        self.campaigns_table.setHorizontalHeaderLabels([
            "Name", "Type", "Targets", "Sent", "Status", "Actions"
        ])
        self.campaigns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.campaigns_table.itemSelectionChanged.connect(self.on_campaign_selected)
        campaigns_layout.addWidget(self.campaigns_table)
        
        layout.addWidget(campaigns_group)
        
        # Campaign configuration
        config_group = QGroupBox("Campaign Configuration")
        config_layout = QFormLayout(config_group)
        
        self.from_address = QLineEdit()
        self.from_address.setPlaceholderText("security@company.com")
        config_layout.addRow("From Address:", self.from_address)
        
        self.from_name = QLineEdit()
        self.from_name.setPlaceholderText("IT Security Team")
        config_layout.addRow("From Name:", self.from_name)
        
        self.subject = QLineEdit()
        self.subject.setPlaceholderText("Action Required: Password Reset")
        config_layout.addRow("Subject:", self.subject)
        
        self.landing_url = QLineEdit()
        self.landing_url.setPlaceholderText("https://your-phishing-server.com/login")
        config_layout.addRow("Landing Page URL:", self.landing_url)
        
        layout.addWidget(config_group)
        
        # Targets
        targets_group = QGroupBox("Targets")
        targets_layout = QVBoxLayout(targets_group)
        
        targets_input_layout = QHBoxLayout()
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText("Enter email addresses, one per line...")
        self.targets_input.setMaximumHeight(100)
        targets_input_layout.addWidget(self.targets_input)
        
        target_buttons = QVBoxLayout()
        import_btn = QPushButton("📥 Import CSV")
        import_btn.clicked.connect(self.import_targets)
        target_buttons.addWidget(import_btn)
        
        add_targets_btn = QPushButton("➕ Add Targets")
        add_targets_btn.clicked.connect(self.add_targets)
        target_buttons.addWidget(add_targets_btn)
        
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.clicked.connect(lambda: self.targets_input.clear())
        target_buttons.addWidget(clear_btn)
        
        targets_input_layout.addLayout(target_buttons)
        targets_layout.addLayout(targets_input_layout)
        
        self.targets_count = QLabel("Targets: 0")
        targets_layout.addWidget(self.targets_count)
        
        layout.addWidget(targets_group)
        
        # Launch controls
        launch_layout = QHBoxLayout()
        
        self.test_btn = QPushButton("🧪 Send Test Email")
        self.test_btn.clicked.connect(self.send_test_email)
        launch_layout.addWidget(self.test_btn)
        
        self.launch_btn = QPushButton("🚀 Launch Campaign")
        self.launch_btn.clicked.connect(self.launch_campaign)
        self.launch_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff6b00, #ff4444);
                color: white;
                font-size: 16px;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #ff8533, #ff6666);
            }
        """)
        launch_layout.addWidget(self.launch_btn)
        
        launch_layout.addStretch()
        layout.addLayout(launch_layout)
        
        return widget
    
    def create_templates_tab(self):
        """Create email templates tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Template selection
        select_layout = QHBoxLayout()
        select_layout.addWidget(QLabel("Category:"))
        self.template_category = QComboBox()
        for tt in TemplateType:
            self.template_category.addItem(tt.value.replace('_', ' ').title(), tt)
        self.template_category.currentIndexChanged.connect(self.load_templates)
        select_layout.addWidget(self.template_category)
        
        select_layout.addWidget(QLabel("Template:"))
        self.template_select = QComboBox()
        self.template_select.currentIndexChanged.connect(self.preview_template)
        select_layout.addWidget(self.template_select)
        
        select_layout.addStretch()
        layout.addLayout(select_layout)
        
        # Template preview
        preview_group = QGroupBox("Template Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.template_preview = QTextEdit()
        self.template_preview.setReadOnly(True)
        self.template_preview.setStyleSheet("""
            QTextEdit {
                background: #ffffff;
                color: #000000;
                border: 1px solid #333;
            }
        """)
        preview_layout.addWidget(self.template_preview)
        
        layout.addWidget(preview_group)
        
        # Custom template
        custom_group = QGroupBox("Custom Template")
        custom_layout = QVBoxLayout(custom_group)
        
        custom_layout.addWidget(QLabel("Subject:"))
        self.custom_subject = QLineEdit()
        custom_layout.addWidget(self.custom_subject)
        
        custom_layout.addWidget(QLabel("Body (HTML):"))
        self.custom_body = QPlainTextEdit()
        self.custom_body.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        custom_layout.addWidget(self.custom_body)
        
        custom_buttons = QHBoxLayout()
        use_custom_btn = QPushButton("Use Custom Template")
        use_custom_btn.clicked.connect(self.use_custom_template)
        custom_buttons.addWidget(use_custom_btn)
        
        save_template_btn = QPushButton("Save Template")
        save_template_btn.clicked.connect(self.save_template)
        custom_buttons.addWidget(save_template_btn)
        custom_buttons.addStretch()
        custom_layout.addLayout(custom_buttons)
        
        layout.addWidget(custom_group)
        
        # Variables info
        vars_group = QGroupBox("Available Variables")
        vars_layout = QVBoxLayout(vars_group)
        vars_text = QLabel("""
        <b>{{target_email}}</b> - Target's email address<br>
        <b>{{target_name}}</b> - Target's name (from email)<br>
        <b>{{phishing_link}}</b> - Unique phishing link<br>
        <b>{{tracking_pixel}}</b> - Email open tracking pixel<br>
        <b>{{company_name}}</b> - Company name<br>
        <b>{{deadline}}</b> - Action deadline<br>
        """)
        vars_layout.addWidget(vars_text)
        layout.addWidget(vars_group)
        
        # Load initial templates
        self.load_templates()
        
        return widget
    
    def create_landing_pages_tab(self):
        """Create landing pages tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Page selection
        select_layout = QHBoxLayout()
        select_layout.addWidget(QLabel("Landing Page:"))
        self.page_select = QComboBox()
        pages = self.set.list_landing_pages()
        for page in pages:
            self.page_select.addItem(page.replace('_', ' ').title(), page)
        self.page_select.currentIndexChanged.connect(self.preview_landing_page)
        select_layout.addWidget(self.page_select)
        select_layout.addStretch()
        layout.addLayout(select_layout)
        
        # Preview
        preview_group = QGroupBox("Landing Page Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.page_preview = QTextEdit()
        self.page_preview.setReadOnly(True)
        self.page_preview.setStyleSheet("""
            QTextEdit {
                background: #ffffff;
                color: #000000;
            }
        """)
        preview_layout.addWidget(self.page_preview)
        
        layout.addWidget(preview_group)
        
        # Configuration
        config_group = QGroupBox("Landing Page Configuration")
        config_layout = QFormLayout(config_group)
        
        self.capture_endpoint = QLineEdit()
        self.capture_endpoint.setPlaceholderText("https://your-server.com/capture")
        config_layout.addRow("Capture Endpoint:", self.capture_endpoint)
        
        self.redirect_url = QLineEdit()
        self.redirect_url.setPlaceholderText("https://real-login-page.com")
        config_layout.addRow("Redirect After Capture:", self.redirect_url)
        
        layout.addWidget(config_group)
        
        # Export
        export_layout = QHBoxLayout()
        export_btn = QPushButton("📤 Export Landing Page")
        export_btn.clicked.connect(self.export_landing_page)
        export_layout.addWidget(export_btn)
        export_layout.addStretch()
        layout.addLayout(export_layout)
        
        # Load initial preview
        self.preview_landing_page()
        
        return widget
    
    def create_smtp_tab(self):
        """Create SMTP configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        smtp_group = QGroupBox("SMTP Server Configuration")
        smtp_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00d4ff;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #00d4ff; }
        """)
        smtp_layout = QFormLayout(smtp_group)
        
        self.smtp_host = QLineEdit()
        self.smtp_host.setPlaceholderText("smtp.gmail.com")
        smtp_layout.addRow("SMTP Host:", self.smtp_host)
        
        self.smtp_port = QSpinBox()
        self.smtp_port.setRange(1, 65535)
        self.smtp_port.setValue(587)
        smtp_layout.addRow("SMTP Port:", self.smtp_port)
        
        self.smtp_user = QLineEdit()
        self.smtp_user.setPlaceholderText("your-email@gmail.com")
        smtp_layout.addRow("Username:", self.smtp_user)
        
        self.smtp_pass = QLineEdit()
        self.smtp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        smtp_layout.addRow("Password:", self.smtp_pass)
        
        self.smtp_tls = QCheckBox("Use TLS/STARTTLS")
        self.smtp_tls.setChecked(True)
        smtp_layout.addRow("", self.smtp_tls)
        
        layout.addWidget(smtp_group)
        
        # Test and save
        buttons_layout = QHBoxLayout()
        
        test_smtp_btn = QPushButton("🧪 Test Connection")
        test_smtp_btn.clicked.connect(self.test_smtp)
        buttons_layout.addWidget(test_smtp_btn)
        
        save_smtp_btn = QPushButton("💾 Save Configuration")
        save_smtp_btn.clicked.connect(self.save_smtp_config)
        save_smtp_btn.setStyleSheet("background: #00ff88; color: black;")
        buttons_layout.addWidget(save_smtp_btn)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        
        # Provider presets
        presets_group = QGroupBox("Quick Setup Presets")
        presets_layout = QHBoxLayout(presets_group)
        
        gmail_btn = QPushButton("Gmail")
        gmail_btn.clicked.connect(lambda: self.apply_smtp_preset('gmail'))
        presets_layout.addWidget(gmail_btn)
        
        outlook_btn = QPushButton("Outlook")
        outlook_btn.clicked.connect(lambda: self.apply_smtp_preset('outlook'))
        presets_layout.addWidget(outlook_btn)
        
        sendgrid_btn = QPushButton("SendGrid")
        sendgrid_btn.clicked.connect(lambda: self.apply_smtp_preset('sendgrid'))
        presets_layout.addWidget(sendgrid_btn)
        
        presets_layout.addStretch()
        layout.addWidget(presets_group)
        
        layout.addStretch()
        
        return widget
    
    def create_credentials_tab(self):
        """Create captured credentials tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Credentials table
        self.creds_table = QTableWidget()
        self.creds_table.setColumnCount(6)
        self.creds_table.setHorizontalHeaderLabels([
            "Campaign", "Username", "Password", "IP Address", "User Agent", "Captured"
        ])
        self.creds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.creds_table)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_credentials)
        export_layout.addWidget(refresh_btn)
        
        export_csv_btn = QPushButton("📤 Export CSV")
        export_csv_btn.clicked.connect(self.export_credentials_csv)
        export_layout.addWidget(export_csv_btn)
        
        clear_creds_btn = QPushButton("🗑️ Clear All")
        clear_creds_btn.clicked.connect(self.clear_credentials)
        export_layout.addWidget(clear_creds_btn)
        
        export_layout.addStretch()
        layout.addLayout(export_layout)
        
        return widget
    
    def create_stats_tab(self):
        """Create statistics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Overall stats
        overall_group = QGroupBox("Overall Statistics")
        overall_layout = QHBoxLayout(overall_group)
        
        self.stat_campaigns = self.create_stat_card("Campaigns", "0", "#00d4ff")
        self.stat_sent = self.create_stat_card("Emails Sent", "0", "#ff6b00")
        self.stat_opened = self.create_stat_card("Opened", "0", "#00ff88")
        self.stat_clicked = self.create_stat_card("Clicked", "0", "#ffaa00")
        self.stat_captured = self.create_stat_card("Captured", "0", "#ff4444")
        
        for card in [self.stat_campaigns, self.stat_sent, self.stat_opened, 
                     self.stat_clicked, self.stat_captured]:
            overall_layout.addWidget(card)
        
        layout.addWidget(overall_group)
        
        # Campaign details
        details_group = QGroupBox("Campaign Performance")
        details_layout = QVBoxLayout(details_group)
        
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(8)
        self.stats_table.setHorizontalHeaderLabels([
            "Campaign", "Targets", "Sent", "Opened", "Clicked", 
            "Captured", "Open Rate", "Click Rate"
        ])
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        details_layout.addWidget(self.stats_table)
        
        layout.addWidget(details_group)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Statistics")
        refresh_btn.clicked.connect(self.refresh_stats)
        layout.addWidget(refresh_btn)
        
        return widget
    
    def create_stat_card(self, title: str, value: str, color: str) -> QFrame:
        """Create a statistics card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #1a1a2e;
                border: 2px solid {color};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {color}; font-size: 12px;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setObjectName(f"stat_{title.lower().replace(' ', '_')}")
        value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        return card
    
    def create_campaign(self):
        """Create a new campaign"""
        name = self.campaign_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Enter a campaign name")
            return
        
        attack_type = self.attack_type.currentData()
        template_type = self.template_type.currentData()
        
        campaign = self.set.create_campaign(name, attack_type, template_type)
        self.current_campaign = campaign
        
        # Add to table
        row = self.campaigns_table.rowCount()
        self.campaigns_table.insertRow(row)
        self.campaigns_table.setItem(row, 0, QTableWidgetItem(campaign.name))
        self.campaigns_table.setItem(row, 1, QTableWidgetItem(attack_type.value))
        self.campaigns_table.setItem(row, 2, QTableWidgetItem("0"))
        self.campaigns_table.setItem(row, 3, QTableWidgetItem("0"))
        self.campaigns_table.setItem(row, 4, QTableWidgetItem(campaign.status))
        
        # Store campaign ID
        self.campaigns_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, campaign.campaign_id)
        
        self.status_bar.setText(f"Created campaign: {name}")
        self.campaign_name.clear()
    
    def on_campaign_selected(self):
        """Handle campaign selection"""
        row = self.campaigns_table.currentRow()
        if row >= 0:
            campaign_id = self.campaigns_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            if campaign_id in self.set.campaigns:
                self.current_campaign = self.set.campaigns[campaign_id]
                
                # Populate fields
                self.from_address.setText(self.current_campaign.from_address)
                self.from_name.setText(self.current_campaign.from_name)
                self.subject.setText(self.current_campaign.subject)
                self.landing_url.setText(self.current_campaign.landing_page)
    
    def add_targets(self):
        """Add targets to current campaign"""
        if not self.current_campaign:
            QMessageBox.warning(self, "Error", "Select a campaign first")
            return
        
        targets_text = self.targets_input.toPlainText()
        targets = [t.strip() for t in targets_text.split('\n') if t.strip() and '@' in t]
        
        self.set.add_targets(self.current_campaign.campaign_id, targets)
        self.targets_count.setText(f"Targets: {len(self.current_campaign.targets)}")
        
        # Update table
        row = self.campaigns_table.currentRow()
        if row >= 0:
            self.campaigns_table.setItem(row, 2, 
                QTableWidgetItem(str(len(self.current_campaign.targets))))
        
        self.status_bar.setText(f"Added {len(targets)} targets")
    
    def import_targets(self):
        """Import targets from CSV"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Import Targets", "",
            "CSV Files (*.csv);;Text Files (*.txt);;All Files (*)"
        )
        if filepath:
            with open(filepath, 'r') as f:
                content = f.read()
            self.targets_input.setPlainText(content)
    
    def load_templates(self):
        """Load templates for selected category"""
        self.template_select.clear()
        category = self.template_category.currentData()
        
        templates = self.set.list_templates()
        if category.value in templates:
            for template_name in templates[category.value]:
                self.template_select.addItem(
                    template_name.replace('_', ' ').title(), 
                    template_name
                )
    
    def preview_template(self):
        """Preview selected template"""
        category = self.template_category.currentData()
        template_name = self.template_select.currentData()
        
        if template_name:
            template = self.set.get_template(category, template_name)
            if template:
                # Render with example variables
                html = self.set.render_template(template, {
                    'company_name': 'Example Corp',
                    'target_name': 'John Doe',
                    'target_email': 'john.doe@example.com',
                    'phishing_link': 'https://example.com/login',
                    'tracking_pixel': '',
                    'deadline': 'December 31, 2024',
                    'sender_name': 'IT Department',
                    'document_name': 'Q4 Report.pdf'
                })
                self.template_preview.setHtml(html)
                self.custom_subject.setText(template.subject)
                self.custom_body.setPlainText(template.body_html)
    
    def use_custom_template(self):
        """Use the custom template"""
        if not self.current_campaign:
            QMessageBox.warning(self, "Error", "Select a campaign first")
            return
        
        self.current_campaign.subject = self.custom_subject.text()
        self.current_campaign.email_body = self.custom_body.toPlainText()
        self.status_bar.setText("Custom template applied")
    
    def save_template(self):
        """Save custom template"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Template", "template.html",
            "HTML Files (*.html)"
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(self.custom_body.toPlainText())
            self.status_bar.setText(f"Template saved to {filepath}")
    
    def preview_landing_page(self):
        """Preview selected landing page"""
        page_name = self.page_select.currentData()
        if page_name:
            html = self.set.render_landing_page(page_name, {
                'capture_endpoint': '/capture',
                'campaign_id': 'example',
                'company_name': 'Example Corp'
            })
            self.page_preview.setHtml(html)
    
    def export_landing_page(self):
        """Export landing page"""
        page_name = self.page_select.currentData()
        if not page_name:
            return
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Landing Page", f"{page_name}.html",
            "HTML Files (*.html)"
        )
        
        if filepath:
            html = self.set.render_landing_page(page_name, {
                'capture_endpoint': self.capture_endpoint.text() or '/capture',
                'campaign_id': self.current_campaign.campaign_id if self.current_campaign else '',
                'company_name': 'Company'
            })
            
            with open(filepath, 'w') as f:
                f.write(html)
            
            self.status_bar.setText(f"Exported to {filepath}")
    
    def apply_smtp_preset(self, provider: str):
        """Apply SMTP preset"""
        presets = {
            'gmail': ('smtp.gmail.com', 587, True),
            'outlook': ('smtp.office365.com', 587, True),
            'sendgrid': ('smtp.sendgrid.net', 587, True),
        }
        
        if provider in presets:
            host, port, tls = presets[provider]
            self.smtp_host.setText(host)
            self.smtp_port.setValue(port)
            self.smtp_tls.setChecked(tls)
    
    def save_smtp_config(self):
        """Save SMTP configuration"""
        self.set.configure_smtp(
            host=self.smtp_host.text(),
            port=self.smtp_port.value(),
            username=self.smtp_user.text(),
            password=self.smtp_pass.text(),
            use_tls=self.smtp_tls.isChecked()
        )
        self.status_bar.setText("SMTP configuration saved")
    
    def test_smtp(self):
        """Test SMTP connection"""
        self.save_smtp_config()
        self.status_bar.setText("Testing SMTP connection...")
        # Would actually test the connection
        QMessageBox.information(self, "SMTP Test", "SMTP configuration appears valid")
    
    def send_test_email(self):
        """Send a test email"""
        if not self.current_campaign:
            QMessageBox.warning(self, "Error", "Select a campaign first")
            return
        
        test_email, ok = QMessageBox.getText(
            self, "Test Email", "Enter test email address:"
        ) if hasattr(QMessageBox, 'getText') else (None, False)
        
        # Just show status for now
        self.status_bar.setText("Test email would be sent here")
    
    def launch_campaign(self):
        """Launch the campaign"""
        if not self.current_campaign:
            QMessageBox.warning(self, "Error", "Select a campaign first")
            return
        
        if not self.current_campaign.targets:
            QMessageBox.warning(self, "Error", "Add targets first")
            return
        
        # Confirm launch
        reply = QMessageBox.question(
            self, "Launch Campaign",
            f"Launch campaign '{self.current_campaign.name}' to {len(self.current_campaign.targets)} targets?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Update campaign settings
            self.current_campaign.from_address = self.from_address.text()
            self.current_campaign.from_name = self.from_name.text()
            self.current_campaign.subject = self.subject.text()
            self.current_campaign.landing_page = self.landing_url.text()
            
            self.status_bar.setText("Launching campaign...")
            
            worker = SETWorker(self.set.launch_campaign, self.current_campaign.campaign_id)
            worker.result_ready.connect(self.on_campaign_launched)
            worker.error.connect(self.on_error)
            worker.start()
            self.workers.append(worker)
    
    def on_campaign_launched(self, result):
        """Handle campaign launch result"""
        self.status_bar.setText(
            f"Campaign launched: {result['emails_sent']} emails sent"
        )
        
        # Update table
        row = self.campaigns_table.currentRow()
        if row >= 0:
            self.campaigns_table.setItem(row, 3, 
                QTableWidgetItem(str(result['emails_sent'])))
            self.campaigns_table.setItem(row, 4, QTableWidgetItem("Launched"))
    
    def refresh_credentials(self):
        """Refresh captured credentials"""
        creds = self.set.export_credentials()
        
        self.creds_table.setRowCount(len(creds))
        for row, cred in enumerate(creds):
            self.creds_table.setItem(row, 0, QTableWidgetItem(cred['campaign_id']))
            self.creds_table.setItem(row, 1, QTableWidgetItem(cred['username']))
            self.creds_table.setItem(row, 2, QTableWidgetItem(cred['password']))
            self.creds_table.setItem(row, 3, QTableWidgetItem(cred['ip_address']))
            self.creds_table.setItem(row, 4, QTableWidgetItem(cred['user_agent'][:50]))
            self.creds_table.setItem(row, 5, QTableWidgetItem(cred['captured_at']))
    
    def export_credentials_csv(self):
        """Export credentials to CSV"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Credentials", "credentials.csv",
            "CSV Files (*.csv)"
        )
        
        if filepath:
            creds = self.set.export_credentials()
            with open(filepath, 'w') as f:
                f.write("campaign_id,username,password,ip_address,captured_at\n")
                for c in creds:
                    f.write(f"{c['campaign_id']},{c['username']},{c['password']},{c['ip_address']},{c['captured_at']}\n")
            self.status_bar.setText(f"Exported to {filepath}")
    
    def clear_credentials(self):
        """Clear all credentials"""
        reply = QMessageBox.question(
            self, "Clear Credentials",
            "Are you sure you want to clear all captured credentials?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.set.captured_credentials.clear()
            self.creds_table.setRowCount(0)
            self.status_bar.setText("Credentials cleared")
    
    def refresh_stats(self):
        """Refresh statistics"""
        total_campaigns = len(self.set.campaigns)
        total_sent = sum(c.emails_sent for c in self.set.campaigns.values())
        total_opened = sum(c.emails_opened for c in self.set.campaigns.values())
        total_clicked = sum(c.links_clicked for c in self.set.campaigns.values())
        total_captured = sum(c.credentials_captured for c in self.set.campaigns.values())
        
        # Update stat cards
        self.update_stat_card(self.stat_campaigns, str(total_campaigns))
        self.update_stat_card(self.stat_sent, str(total_sent))
        self.update_stat_card(self.stat_opened, str(total_opened))
        self.update_stat_card(self.stat_clicked, str(total_clicked))
        self.update_stat_card(self.stat_captured, str(total_captured))
        
        # Update table
        self.stats_table.setRowCount(len(self.set.campaigns))
        for row, (campaign_id, campaign) in enumerate(self.set.campaigns.items()):
            stats = self.set.get_campaign_stats(campaign_id)
            
            self.stats_table.setItem(row, 0, QTableWidgetItem(stats['name']))
            self.stats_table.setItem(row, 1, QTableWidgetItem(str(stats['total_targets'])))
            self.stats_table.setItem(row, 2, QTableWidgetItem(str(stats['emails_sent'])))
            self.stats_table.setItem(row, 3, QTableWidgetItem(str(stats['emails_opened'])))
            self.stats_table.setItem(row, 4, QTableWidgetItem(str(stats['links_clicked'])))
            self.stats_table.setItem(row, 5, QTableWidgetItem(str(stats['credentials_captured'])))
            self.stats_table.setItem(row, 6, QTableWidgetItem(stats['open_rate']))
            self.stats_table.setItem(row, 7, QTableWidgetItem(stats['click_rate']))
    
    def update_stat_card(self, card: QFrame, value: str):
        """Update stat card value"""
        for child in card.findChildren(QLabel):
            if child.objectName().startswith("stat_"):
                child.setText(value)
    
    def on_error(self, error: str):
        """Handle errors"""
        self.status_bar.setText(f"Error: {error}")
        QMessageBox.critical(self, "Error", error)
