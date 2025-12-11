"""
Cloud Security Scanner Page
Multi-cloud security assessment interface for AWS, Azure, and GCP
"""

import asyncio
import os
import json
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

from core.cloud_security import (
    CloudSecurityScanner, CloudProvider, Severity, ResourceType, ScanResult
)


class CloudScanWorker(QThread):
    """Background worker for cloud scanning"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, scanner, provider, resource_types=None, checks=None):
        super().__init__()
        self.scanner = scanner
        self.provider = provider
        self.resource_types = resource_types
        self.checks = checks
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                self.scanner.scan(self.provider, self.resource_types, self.checks)
            )
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class CloudSecurityPage(QWidget):
    """Cloud Security Scanner GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = CloudSecurityScanner()
        self.current_result = None
        self.workers = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("☁️ Cloud Security Scanner")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #00d4ff;
            padding: 10px;
        """)
        layout.addWidget(header)
        
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
                background: #00d4ff;
                color: #000;
            }
        """)
        
        tabs.addTab(self.create_aws_tab(), "🟠 AWS")
        tabs.addTab(self.create_azure_tab(), "🔵 Azure")
        tabs.addTab(self.create_gcp_tab(), "🔴 GCP")
        tabs.addTab(self.create_results_tab(), "📊 Results")
        tabs.addTab(self.create_compliance_tab(), "📋 Compliance")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QLabel("Configure cloud credentials to start scanning")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #00d4ff;
        """)
        layout.addWidget(self.status_bar)
    
    def create_aws_tab(self) -> QWidget:
        """Create AWS configuration and scanning tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Credentials
        creds_group = QGroupBox("AWS Credentials")
        creds_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ff9900;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #ff9900; }
        """)
        creds_layout = QFormLayout(creds_group)
        
        self.aws_access_key = QLineEdit()
        self.aws_access_key.setPlaceholderText("AKIA...")
        creds_layout.addRow("Access Key ID:", self.aws_access_key)
        
        self.aws_secret_key = QLineEdit()
        self.aws_secret_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.aws_secret_key.setPlaceholderText("Secret Access Key")
        creds_layout.addRow("Secret Access Key:", self.aws_secret_key)
        
        self.aws_session_token = QLineEdit()
        self.aws_session_token.setPlaceholderText("Optional - for assumed roles")
        creds_layout.addRow("Session Token:", self.aws_session_token)
        
        self.aws_region = QComboBox()
        self.aws_region.addItems([
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-northeast-1", "ap-southeast-1", "ap-southeast-2"
        ])
        creds_layout.addRow("Region:", self.aws_region)
        
        configure_aws_btn = QPushButton("🔐 Configure AWS Credentials")
        configure_aws_btn.clicked.connect(self.configure_aws)
        configure_aws_btn.setStyleSheet("background: #ff9900; color: #000; font-weight: bold;")
        creds_layout.addRow("", configure_aws_btn)
        
        layout.addWidget(creds_group)
        
        # Scan options
        scan_group = QGroupBox("Scan Options")
        scan_layout = QVBoxLayout(scan_group)
        
        scan_layout.addWidget(QLabel("Select resources to scan:"))
        
        self.aws_resource_checks = {}
        aws_resources = [
            ("S3 Buckets", "s3"),
            ("EC2 Instances", "ec2"),
            ("IAM Users/Roles", "iam"),
            ("RDS Databases", "rds"),
            ("Security Groups", "sg"),
            ("Lambda Functions", "lambda"),
            ("CloudTrail", "cloudtrail"),
            ("Secrets Manager", "secrets"),
            ("KMS Keys", "kms"),
        ]
        
        checks_layout = QHBoxLayout()
        for name, key in aws_resources:
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.aws_resource_checks[key] = cb
            checks_layout.addWidget(cb)
        
        scan_layout.addLayout(checks_layout)
        
        scan_btn = QPushButton("🔍 Start AWS Security Scan")
        scan_btn.clicked.connect(self.scan_aws)
        scan_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff9900, #ff6600);
                color: #000;
                font-weight: bold;
                padding: 15px;
                font-size: 14px;
            }
        """)
        scan_layout.addWidget(scan_btn)
        
        layout.addWidget(scan_group)
        
        # AWS specific findings
        findings_group = QGroupBox("AWS Security Findings")
        findings_layout = QVBoxLayout(findings_group)
        
        self.aws_findings_table = QTableWidget()
        self.aws_findings_table.setColumnCount(5)
        self.aws_findings_table.setHorizontalHeaderLabels([
            "Severity", "Finding", "Resource", "Recommendation", "Compliance"
        ])
        self.aws_findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        findings_layout.addWidget(self.aws_findings_table)
        
        layout.addWidget(findings_group)
        
        return widget
    
    def create_azure_tab(self) -> QWidget:
        """Create Azure configuration and scanning tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Credentials
        creds_group = QGroupBox("Azure Credentials")
        creds_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #0078d4;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #0078d4; }
        """)
        creds_layout = QFormLayout(creds_group)
        
        self.azure_tenant = QLineEdit()
        self.azure_tenant.setPlaceholderText("Tenant ID (GUID)")
        creds_layout.addRow("Tenant ID:", self.azure_tenant)
        
        self.azure_client_id = QLineEdit()
        self.azure_client_id.setPlaceholderText("Application (Client) ID")
        creds_layout.addRow("Client ID:", self.azure_client_id)
        
        self.azure_client_secret = QLineEdit()
        self.azure_client_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.azure_client_secret.setPlaceholderText("Client Secret")
        creds_layout.addRow("Client Secret:", self.azure_client_secret)
        
        self.azure_subscription = QLineEdit()
        self.azure_subscription.setPlaceholderText("Subscription ID")
        creds_layout.addRow("Subscription ID:", self.azure_subscription)
        
        configure_azure_btn = QPushButton("🔐 Configure Azure Credentials")
        configure_azure_btn.clicked.connect(self.configure_azure)
        configure_azure_btn.setStyleSheet("background: #0078d4; color: #fff; font-weight: bold;")
        creds_layout.addRow("", configure_azure_btn)
        
        layout.addWidget(creds_group)
        
        # Scan options
        scan_group = QGroupBox("Scan Options")
        scan_layout = QVBoxLayout(scan_group)
        
        self.azure_resource_checks = {}
        azure_resources = [
            ("Storage Accounts", "storage"),
            ("Virtual Machines", "vm"),
            ("Key Vaults", "keyvault"),
            ("SQL Databases", "sql"),
            ("Network Security Groups", "nsg"),
            ("App Services", "appservice"),
            ("AKS Clusters", "aks"),
        ]
        
        checks_layout = QHBoxLayout()
        for name, key in azure_resources:
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.azure_resource_checks[key] = cb
            checks_layout.addWidget(cb)
        
        scan_layout.addLayout(checks_layout)
        
        scan_btn = QPushButton("🔍 Start Azure Security Scan")
        scan_btn.clicked.connect(self.scan_azure)
        scan_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #0078d4, #00bcf2);
                color: #fff;
                font-weight: bold;
                padding: 15px;
                font-size: 14px;
            }
        """)
        scan_layout.addWidget(scan_btn)
        
        layout.addWidget(scan_group)
        
        # Azure findings
        findings_group = QGroupBox("Azure Security Findings")
        findings_layout = QVBoxLayout(findings_group)
        
        self.azure_findings_table = QTableWidget()
        self.azure_findings_table.setColumnCount(5)
        self.azure_findings_table.setHorizontalHeaderLabels([
            "Severity", "Finding", "Resource", "Recommendation", "Compliance"
        ])
        self.azure_findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        findings_layout.addWidget(self.azure_findings_table)
        
        layout.addWidget(findings_group)
        
        return widget
    
    def create_gcp_tab(self) -> QWidget:
        """Create GCP configuration and scanning tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Credentials
        creds_group = QGroupBox("GCP Credentials")
        creds_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ea4335;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #ea4335; }
        """)
        creds_layout = QFormLayout(creds_group)
        
        self.gcp_project = QLineEdit()
        self.gcp_project.setPlaceholderText("my-project-123")
        creds_layout.addRow("Project ID:", self.gcp_project)
        
        sa_layout = QHBoxLayout()
        self.gcp_service_account = QLineEdit()
        self.gcp_service_account.setPlaceholderText("Path to service account JSON")
        sa_layout.addWidget(self.gcp_service_account)
        
        browse_sa_btn = QPushButton("📂")
        browse_sa_btn.clicked.connect(self.browse_gcp_sa)
        sa_layout.addWidget(browse_sa_btn)
        
        creds_layout.addRow("Service Account:", sa_layout)
        
        configure_gcp_btn = QPushButton("🔐 Configure GCP Credentials")
        configure_gcp_btn.clicked.connect(self.configure_gcp)
        configure_gcp_btn.setStyleSheet("background: #ea4335; color: #fff; font-weight: bold;")
        creds_layout.addRow("", configure_gcp_btn)
        
        layout.addWidget(creds_group)
        
        # Scan options
        scan_group = QGroupBox("Scan Options")
        scan_layout = QVBoxLayout(scan_group)
        
        self.gcp_resource_checks = {}
        gcp_resources = [
            ("Cloud Storage", "gcs"),
            ("Compute Instances", "compute"),
            ("GKE Clusters", "gke"),
            ("Cloud SQL", "cloudsql"),
            ("Firewall Rules", "firewall"),
            ("IAM Service Accounts", "iam"),
            ("Cloud Functions", "functions"),
        ]
        
        checks_layout = QHBoxLayout()
        for name, key in gcp_resources:
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.gcp_resource_checks[key] = cb
            checks_layout.addWidget(cb)
        
        scan_layout.addLayout(checks_layout)
        
        scan_btn = QPushButton("🔍 Start GCP Security Scan")
        scan_btn.clicked.connect(self.scan_gcp)
        scan_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ea4335, #fbbc04);
                color: #000;
                font-weight: bold;
                padding: 15px;
                font-size: 14px;
            }
        """)
        scan_layout.addWidget(scan_btn)
        
        layout.addWidget(scan_group)
        
        # GCP findings
        findings_group = QGroupBox("GCP Security Findings")
        findings_layout = QVBoxLayout(findings_group)
        
        self.gcp_findings_table = QTableWidget()
        self.gcp_findings_table.setColumnCount(5)
        self.gcp_findings_table.setHorizontalHeaderLabels([
            "Severity", "Finding", "Resource", "Recommendation", "Compliance"
        ])
        self.gcp_findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        findings_layout.addWidget(self.gcp_findings_table)
        
        layout.addWidget(findings_group)
        
        return widget
    
    def create_results_tab(self) -> QWidget:
        """Create combined results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Summary statistics
        stats_group = QGroupBox("Scan Summary")
        stats_layout = QHBoxLayout(stats_group)
        
        # Severity cards
        self.severity_cards = {}
        severity_colors = {
            "critical": "#ff0044",
            "high": "#ff6600",
            "medium": "#ffaa00",
            "low": "#00ccff",
            "info": "#888888"
        }
        
        for severity, color in severity_colors.items():
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
            
            count_label = QLabel("0")
            count_label.setStyleSheet(f"font-size: 32px; font-weight: bold; color: {color};")
            count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_label = QLabel(severity.upper())
            name_label.setStyleSheet("font-size: 12px; color: #888;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(count_label)
            card_layout.addWidget(name_label)
            
            self.severity_cards[severity] = count_label
            stats_layout.addWidget(card)
        
        layout.addWidget(stats_group)
        
        # All findings
        all_findings_group = QGroupBox("All Security Findings")
        all_layout = QVBoxLayout(all_findings_group)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Provider:"))
        self.filter_provider = QComboBox()
        self.filter_provider.addItems(["All", "AWS", "Azure", "GCP"])
        self.filter_provider.currentTextChanged.connect(self.filter_findings)
        filter_layout.addWidget(self.filter_provider)
        
        filter_layout.addWidget(QLabel("Severity:"))
        self.filter_severity = QComboBox()
        self.filter_severity.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.filter_severity.currentTextChanged.connect(self.filter_findings)
        filter_layout.addWidget(self.filter_severity)
        
        filter_layout.addStretch()
        
        export_btn = QPushButton("📤 Export Results")
        export_btn.clicked.connect(self.export_results)
        filter_layout.addWidget(export_btn)
        
        all_layout.addLayout(filter_layout)
        
        self.all_findings_table = QTableWidget()
        self.all_findings_table.setColumnCount(6)
        self.all_findings_table.setHorizontalHeaderLabels([
            "Provider", "Severity", "Finding", "Resource", "Recommendation", "Compliance"
        ])
        self.all_findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.all_findings_table.itemDoubleClicked.connect(self.show_finding_details)
        all_layout.addWidget(self.all_findings_table)
        
        layout.addWidget(all_findings_group)
        
        return widget
    
    def create_compliance_tab(self) -> QWidget:
        """Create compliance reporting tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Framework selection
        framework_group = QGroupBox("Compliance Frameworks")
        framework_layout = QVBoxLayout(framework_group)
        
        self.compliance_frameworks = {}
        frameworks = [
            ("CIS AWS Foundations Benchmark", "CIS AWS"),
            ("CIS Azure Foundations Benchmark", "CIS Azure"),
            ("CIS GCP Foundations Benchmark", "CIS GCP"),
            ("PCI-DSS v4.0", "PCI-DSS"),
            ("HIPAA", "HIPAA"),
            ("GDPR", "GDPR"),
            ("SOC 2", "SOC2"),
            ("NIST 800-53", "NIST"),
        ]
        
        frameworks_grid = QHBoxLayout()
        for name, key in frameworks:
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.compliance_frameworks[key] = cb
            frameworks_grid.addWidget(cb)
        
        framework_layout.addLayout(frameworks_grid)
        
        generate_report_btn = QPushButton("📋 Generate Compliance Report")
        generate_report_btn.clicked.connect(self.generate_compliance_report)
        framework_layout.addWidget(generate_report_btn)
        
        layout.addWidget(framework_group)
        
        # Compliance status
        status_group = QGroupBox("Compliance Status")
        status_layout = QVBoxLayout(status_group)
        
        self.compliance_tree = QTreeWidget()
        self.compliance_tree.setHeaderLabels(["Framework / Control", "Status", "Findings"])
        self.compliance_tree.setColumnWidth(0, 400)
        status_layout.addWidget(self.compliance_tree)
        
        layout.addWidget(status_group)
        
        # Report output
        report_group = QGroupBox("Compliance Report")
        report_layout = QVBoxLayout(report_group)
        
        self.compliance_report = QPlainTextEdit()
        self.compliance_report.setReadOnly(True)
        self.compliance_report.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        report_layout.addWidget(self.compliance_report)
        
        report_buttons = QHBoxLayout()
        
        save_report_btn = QPushButton("💾 Save Report")
        save_report_btn.clicked.connect(self.save_compliance_report)
        report_buttons.addWidget(save_report_btn)
        
        report_buttons.addStretch()
        report_layout.addLayout(report_buttons)
        
        layout.addWidget(report_group)
        
        return widget
    
    def browse_gcp_sa(self):
        """Browse for GCP service account file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select Service Account JSON", "",
            "JSON Files (*.json)"
        )
        if filepath:
            self.gcp_service_account.setText(filepath)
    
    def configure_aws(self):
        """Configure AWS credentials"""
        access_key = self.aws_access_key.text().strip()
        secret_key = self.aws_secret_key.text().strip()
        region = self.aws_region.currentText()
        session_token = self.aws_session_token.text().strip()
        
        if not access_key or not secret_key:
            QMessageBox.warning(self, "Error", "Enter Access Key and Secret Key")
            return
        
        success = self.scanner.configure_aws(access_key, secret_key, region, session_token)
        
        if success:
            self.status_bar.setText("✅ AWS credentials configured successfully")
            QMessageBox.information(self, "Success", "AWS credentials configured")
        else:
            self.status_bar.setText("❌ Failed to configure AWS credentials")
            QMessageBox.warning(self, "Error", "Failed to validate AWS credentials")
    
    def configure_azure(self):
        """Configure Azure credentials"""
        tenant = self.azure_tenant.text().strip()
        client_id = self.azure_client_id.text().strip()
        client_secret = self.azure_client_secret.text().strip()
        subscription = self.azure_subscription.text().strip()
        
        if not all([tenant, client_id, client_secret, subscription]):
            QMessageBox.warning(self, "Error", "Fill all Azure credential fields")
            return
        
        success = self.scanner.configure_azure(tenant, client_id, client_secret, subscription)
        
        if success:
            self.status_bar.setText("✅ Azure credentials configured successfully")
            QMessageBox.information(self, "Success", "Azure credentials configured")
        else:
            self.status_bar.setText("❌ Failed to configure Azure credentials")
    
    def configure_gcp(self):
        """Configure GCP credentials"""
        project_id = self.gcp_project.text().strip()
        sa_path = self.gcp_service_account.text().strip()
        
        if not project_id:
            QMessageBox.warning(self, "Error", "Enter Project ID")
            return
        
        # Read service account file if provided
        sa_json = ""
        if sa_path and os.path.exists(sa_path):
            with open(sa_path, 'r') as f:
                sa_json = f.read()
        
        success = self.scanner.configure_gcp(sa_json, project_id)
        
        if success:
            self.status_bar.setText("✅ GCP credentials configured successfully")
            QMessageBox.information(self, "Success", "GCP credentials configured")
        else:
            self.status_bar.setText("❌ Failed to configure GCP credentials")
    
    def scan_aws(self):
        """Start AWS security scan"""
        if CloudProvider.AWS not in self.scanner.credentials:
            QMessageBox.warning(self, "Error", "Configure AWS credentials first")
            return
        
        self.status_bar.setText("🔍 Scanning AWS resources...")
        
        worker = CloudScanWorker(self.scanner, CloudProvider.AWS)
        worker.result_ready.connect(lambda r: self.on_scan_complete(r, self.aws_findings_table))
        worker.error.connect(self.on_scan_error)
        worker.start()
        self.workers.append(worker)
    
    def scan_azure(self):
        """Start Azure security scan"""
        if CloudProvider.AZURE not in self.scanner.credentials:
            QMessageBox.warning(self, "Error", "Configure Azure credentials first")
            return
        
        self.status_bar.setText("🔍 Scanning Azure resources...")
        
        worker = CloudScanWorker(self.scanner, CloudProvider.AZURE)
        worker.result_ready.connect(lambda r: self.on_scan_complete(r, self.azure_findings_table))
        worker.error.connect(self.on_scan_error)
        worker.start()
        self.workers.append(worker)
    
    def scan_gcp(self):
        """Start GCP security scan"""
        if CloudProvider.GCP not in self.scanner.credentials:
            QMessageBox.warning(self, "Error", "Configure GCP credentials first")
            return
        
        self.status_bar.setText("🔍 Scanning GCP resources...")
        
        worker = CloudScanWorker(self.scanner, CloudProvider.GCP)
        worker.result_ready.connect(lambda r: self.on_scan_complete(r, self.gcp_findings_table))
        worker.error.connect(self.on_scan_error)
        worker.start()
        self.workers.append(worker)
    
    def on_scan_complete(self, result: ScanResult, table: QTableWidget):
        """Handle scan completion"""
        self.current_result = result
        
        # Update provider-specific table
        table.setRowCount(0)
        for finding in result.findings:
            row = table.rowCount()
            table.insertRow(row)
            
            severity_item = QTableWidgetItem(finding.severity.value.upper())
            severity_colors = {
                "critical": QColor(255, 0, 68),
                "high": QColor(255, 102, 0),
                "medium": QColor(255, 170, 0),
                "low": QColor(0, 204, 255),
                "informational": QColor(136, 136, 136)
            }
            severity_item.setForeground(severity_colors.get(finding.severity.value, QColor(255, 255, 255)))
            table.setItem(row, 0, severity_item)
            
            table.setItem(row, 1, QTableWidgetItem(finding.title))
            table.setItem(row, 2, QTableWidgetItem(finding.resource.name if finding.resource else ""))
            table.setItem(row, 3, QTableWidgetItem(finding.recommendation[:80] + "..." if len(finding.recommendation) > 80 else finding.recommendation))
            table.setItem(row, 4, QTableWidgetItem(", ".join(finding.compliance_frameworks)))
        
        # Update all findings table
        self.update_all_findings()
        
        # Update statistics
        self.update_statistics()
        
        self.status_bar.setText(f"✅ Scan complete: {len(result.findings)} findings, {result.resources_scanned} resources scanned")
    
    def on_scan_error(self, error: str):
        """Handle scan error"""
        self.status_bar.setText(f"❌ Scan error: {error}")
        QMessageBox.critical(self, "Scan Error", error)
    
    def update_all_findings(self):
        """Update the combined findings table"""
        self.all_findings_table.setRowCount(0)
        
        for finding in self.scanner.findings:
            row = self.all_findings_table.rowCount()
            self.all_findings_table.insertRow(row)
            
            self.all_findings_table.setItem(row, 0, QTableWidgetItem(finding.provider.value.upper()))
            
            severity_item = QTableWidgetItem(finding.severity.value.upper())
            severity_colors = {
                "critical": QColor(255, 0, 68),
                "high": QColor(255, 102, 0),
                "medium": QColor(255, 170, 0),
                "low": QColor(0, 204, 255),
                "informational": QColor(136, 136, 136)
            }
            severity_item.setForeground(severity_colors.get(finding.severity.value, QColor(255, 255, 255)))
            self.all_findings_table.setItem(row, 1, severity_item)
            
            self.all_findings_table.setItem(row, 2, QTableWidgetItem(finding.title))
            self.all_findings_table.setItem(row, 3, QTableWidgetItem(finding.resource.name if finding.resource else ""))
            self.all_findings_table.setItem(row, 4, QTableWidgetItem(finding.recommendation[:60] + "..."))
            self.all_findings_table.setItem(row, 5, QTableWidgetItem(", ".join(finding.compliance_frameworks)))
    
    def update_statistics(self):
        """Update severity statistics cards"""
        stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in self.scanner.findings:
            sev = finding.severity.value
            if sev == "informational":
                sev = "info"
            if sev in stats:
                stats[sev] += 1
        
        for sev, count in stats.items():
            if sev in self.severity_cards:
                self.severity_cards[sev].setText(str(count))
    
    def filter_findings(self):
        """Filter findings based on selected criteria"""
        provider_filter = self.filter_provider.currentText().lower()
        severity_filter = self.filter_severity.currentText().lower()
        
        for row in range(self.all_findings_table.rowCount()):
            show = True
            
            if provider_filter != "all":
                provider = self.all_findings_table.item(row, 0).text().lower()
                if provider != provider_filter:
                    show = False
            
            if severity_filter != "all":
                severity = self.all_findings_table.item(row, 1).text().lower()
                if severity != severity_filter:
                    show = False
            
            self.all_findings_table.setRowHidden(row, not show)
    
    def show_finding_details(self, item):
        """Show detailed information about a finding"""
        row = item.row()
        title = self.all_findings_table.item(row, 2).text()
        
        # Find the finding
        for finding in self.scanner.findings:
            if finding.title == title:
                details = f"""
Finding: {finding.title}
Severity: {finding.severity.value.upper()}
Provider: {finding.provider.value.upper()}
Resource: {finding.resource.name if finding.resource else 'N/A'}

Description:
{finding.description}

Recommendation:
{finding.recommendation}

Compliance Frameworks:
{', '.join(finding.compliance_frameworks)}

Remediation Steps:
""" + "\n".join(f"  {i+1}. {step}" for i, step in enumerate(finding.remediation_steps))
                
                QMessageBox.information(self, "Finding Details", details)
                break
    
    def export_results(self):
        """Export scan results"""
        if not self.scanner.findings:
            QMessageBox.warning(self, "No Data", "No findings to export")
            return
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "cloud_security_findings.json",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if filepath:
            format = "json" if filepath.endswith(".json") else "csv"
            data = self.scanner.export_findings(format)
            
            with open(filepath, 'w') as f:
                f.write(data)
            
            self.status_bar.setText(f"Results exported to {filepath}")
    
    def generate_compliance_report(self):
        """Generate compliance report"""
        self.compliance_tree.clear()
        
        # Get selected frameworks
        selected_frameworks = [k for k, cb in self.compliance_frameworks.items() if cb.isChecked()]
        
        report_text = "=" * 60 + "\n"
        report_text += "CLOUD SECURITY COMPLIANCE REPORT\n"
        report_text += "=" * 60 + "\n\n"
        
        for framework in selected_frameworks:
            findings = self.scanner.get_compliance_report(framework)
            
            framework_item = QTreeWidgetItem([
                framework,
                f"{len(findings)} issues" if findings else "✅ Compliant",
                str(len(findings))
            ])
            
            if findings:
                framework_item.setForeground(1, QColor(255, 102, 0))
            else:
                framework_item.setForeground(1, QColor(0, 255, 136))
            
            for finding in findings:
                finding_item = QTreeWidgetItem([
                    f"  ↳ {finding.title}",
                    finding.severity.value.upper(),
                    finding.resource.name if finding.resource else ""
                ])
                framework_item.addChild(finding_item)
            
            self.compliance_tree.addTopLevelItem(framework_item)
            
            report_text += f"\n{framework}\n"
            report_text += "-" * 40 + "\n"
            if findings:
                for f in findings:
                    report_text += f"  [{f.severity.value.upper()}] {f.title}\n"
            else:
                report_text += "  ✅ No issues found\n"
        
        self.compliance_tree.expandAll()
        self.compliance_report.setPlainText(report_text)
    
    def save_compliance_report(self):
        """Save compliance report to file"""
        report = self.compliance_report.toPlainText()
        if not report:
            QMessageBox.warning(self, "No Report", "Generate a report first")
            return
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "compliance_report.txt",
            "Text Files (*.txt)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(report)
            self.status_bar.setText(f"Report saved to {filepath}")
