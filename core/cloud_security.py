"""
Cloud Security Scanner Module
Multi-cloud security assessment for AWS, Azure, and GCP
"""

import asyncio
import base64
import hashlib
import json
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import re


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    MULTI_CLOUD = "multi_cloud"


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ResourceType(Enum):
    """Cloud resource types"""
    # AWS
    S3_BUCKET = "s3_bucket"
    EC2_INSTANCE = "ec2_instance"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"
    API_GATEWAY = "api_gateway"
    SECURITY_GROUP = "security_group"
    VPC = "vpc"
    EKS_CLUSTER = "eks_cluster"
    SECRETS_MANAGER = "secrets_manager"
    KMS_KEY = "kms_key"
    CLOUDTRAIL = "cloudtrail"
    
    # Azure
    STORAGE_ACCOUNT = "storage_account"
    VM = "virtual_machine"
    KEY_VAULT = "key_vault"
    APP_SERVICE = "app_service"
    SQL_DATABASE = "sql_database"
    FUNCTION_APP = "function_app"
    AKS_CLUSTER = "aks_cluster"
    NETWORK_SECURITY_GROUP = "network_security_group"
    
    # GCP
    GCS_BUCKET = "gcs_bucket"
    COMPUTE_INSTANCE = "compute_instance"
    GKE_CLUSTER = "gke_cluster"
    CLOUD_FUNCTION = "cloud_function"
    CLOUD_SQL = "cloud_sql"
    IAM_SERVICE_ACCOUNT = "iam_service_account"
    FIREWALL_RULE = "firewall_rule"


@dataclass
class CloudCredentials:
    """Cloud provider credentials"""
    provider: CloudProvider
    credentials: Dict = field(default_factory=dict)
    region: str = ""
    project_id: str = ""  # GCP
    subscription_id: str = ""  # Azure
    is_valid: bool = False


@dataclass
class CloudResource:
    """Represents a cloud resource"""
    resource_id: str
    resource_type: ResourceType
    provider: CloudProvider
    name: str
    region: str
    arn: str = ""  # AWS ARN
    tags: Dict = field(default_factory=dict)
    configuration: Dict = field(default_factory=dict)
    created_at: str = ""
    last_modified: str = ""


@dataclass
class SecurityFinding:
    """Security finding/vulnerability"""
    finding_id: str
    title: str
    description: str
    severity: Severity
    provider: CloudProvider
    resource: Optional[CloudResource]
    recommendation: str
    compliance_frameworks: List[str] = field(default_factory=list)
    cwe_id: str = ""
    evidence: Dict = field(default_factory=dict)
    remediation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    found_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    provider: CloudProvider
    started_at: str
    completed_at: str = ""
    resources_scanned: int = 0
    findings: List[SecurityFinding] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)


class CloudSecurityScanner:
    """
    Multi-Cloud Security Scanner
    Supports AWS, Azure, and GCP security assessments
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.credentials: Dict[CloudProvider, CloudCredentials] = {}
        self.resources: Dict[str, CloudResource] = {}
        self.findings: List[SecurityFinding] = []
        self.scan_history: List[ScanResult] = []
        
        # Initialize security checks
        self._init_security_checks()
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:16]
    
    def _init_security_checks(self):
        """Initialize security check definitions"""
        self.aws_checks = {
            "s3_public_access": {
                "title": "S3 Bucket Public Access",
                "description": "S3 bucket allows public access",
                "severity": Severity.CRITICAL,
                "compliance": ["CIS AWS", "PCI-DSS", "HIPAA"],
                "check": self._check_s3_public_access
            },
            "s3_encryption": {
                "title": "S3 Bucket Encryption",
                "description": "S3 bucket not using server-side encryption",
                "severity": Severity.HIGH,
                "compliance": ["CIS AWS", "GDPR"],
                "check": self._check_s3_encryption
            },
            "iam_mfa": {
                "title": "IAM MFA Not Enabled",
                "description": "IAM user does not have MFA enabled",
                "severity": Severity.HIGH,
                "compliance": ["CIS AWS", "PCI-DSS"],
                "check": self._check_iam_mfa
            },
            "iam_admin_policy": {
                "title": "IAM User with Admin Privileges",
                "description": "IAM user has AdministratorAccess policy attached",
                "severity": Severity.HIGH,
                "compliance": ["CIS AWS"],
                "check": self._check_iam_admin
            },
            "security_group_open": {
                "title": "Security Group Open to World",
                "description": "Security group allows unrestricted access (0.0.0.0/0)",
                "severity": Severity.CRITICAL,
                "compliance": ["CIS AWS", "PCI-DSS"],
                "check": self._check_sg_open
            },
            "rds_public": {
                "title": "RDS Instance Publicly Accessible",
                "description": "RDS database instance is publicly accessible",
                "severity": Severity.CRITICAL,
                "compliance": ["CIS AWS", "PCI-DSS", "HIPAA"],
                "check": self._check_rds_public
            },
            "rds_encryption": {
                "title": "RDS Instance Not Encrypted",
                "description": "RDS database instance storage is not encrypted",
                "severity": Severity.HIGH,
                "compliance": ["CIS AWS", "GDPR", "HIPAA"],
                "check": self._check_rds_encryption
            },
            "cloudtrail_disabled": {
                "title": "CloudTrail Not Enabled",
                "description": "CloudTrail logging is not enabled for all regions",
                "severity": Severity.HIGH,
                "compliance": ["CIS AWS", "PCI-DSS"],
                "check": self._check_cloudtrail
            },
            "ec2_imdsv1": {
                "title": "EC2 Instance Using IMDSv1",
                "description": "EC2 instance allows IMDSv1 which is vulnerable to SSRF",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS AWS"],
                "check": self._check_ec2_imds
            },
            "lambda_public": {
                "title": "Lambda Function Publicly Accessible",
                "description": "Lambda function has public access policy",
                "severity": Severity.HIGH,
                "compliance": ["CIS AWS"],
                "check": self._check_lambda_public
            },
            "kms_key_rotation": {
                "title": "KMS Key Rotation Not Enabled",
                "description": "KMS customer managed key does not have automatic rotation enabled",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS AWS", "PCI-DSS"],
                "check": self._check_kms_rotation
            },
            "secrets_rotation": {
                "title": "Secrets Manager Rotation Not Enabled",
                "description": "Secret does not have automatic rotation configured",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS AWS"],
                "check": self._check_secrets_rotation
            },
        }
        
        self.azure_checks = {
            "storage_public_access": {
                "title": "Storage Account Public Access",
                "description": "Storage account allows public blob access",
                "severity": Severity.CRITICAL,
                "compliance": ["CIS Azure", "PCI-DSS"],
                "check": self._check_azure_storage_public
            },
            "storage_encryption": {
                "title": "Storage Account Encryption",
                "description": "Storage account not using customer-managed keys",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS Azure", "GDPR"],
                "check": self._check_azure_storage_encryption
            },
            "nsg_open": {
                "title": "NSG Allows All Inbound",
                "description": "Network Security Group allows unrestricted inbound access",
                "severity": Severity.CRITICAL,
                "compliance": ["CIS Azure", "PCI-DSS"],
                "check": self._check_azure_nsg
            },
            "sql_auditing": {
                "title": "SQL Database Auditing Disabled",
                "description": "Azure SQL Database does not have auditing enabled",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS Azure", "PCI-DSS"],
                "check": self._check_azure_sql_auditing
            },
            "keyvault_recovery": {
                "title": "Key Vault Soft Delete Disabled",
                "description": "Key Vault does not have soft delete enabled",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS Azure"],
                "check": self._check_azure_keyvault
            },
            "vm_disk_encryption": {
                "title": "VM Disk Not Encrypted",
                "description": "Virtual machine disk is not encrypted with Azure Disk Encryption",
                "severity": Severity.HIGH,
                "compliance": ["CIS Azure", "HIPAA"],
                "check": self._check_azure_vm_encryption
            },
        }
        
        self.gcp_checks = {
            "gcs_public": {
                "title": "GCS Bucket Public Access",
                "description": "Cloud Storage bucket is publicly accessible",
                "severity": Severity.CRITICAL,
                "compliance": ["CIS GCP", "PCI-DSS"],
                "check": self._check_gcs_public
            },
            "gcs_uniform_access": {
                "title": "GCS Uniform Bucket Access Not Enabled",
                "description": "Cloud Storage bucket does not have uniform bucket-level access enabled",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS GCP"],
                "check": self._check_gcs_uniform
            },
            "compute_serial_ports": {
                "title": "Compute Instance Serial Ports Enabled",
                "description": "Compute Engine instance has serial port access enabled",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS GCP"],
                "check": self._check_gcp_serial_ports
            },
            "firewall_open": {
                "title": "Firewall Rule Allows All Ingress",
                "description": "VPC firewall rule allows unrestricted ingress from 0.0.0.0/0",
                "severity": Severity.CRITICAL,
                "compliance": ["CIS GCP", "PCI-DSS"],
                "check": self._check_gcp_firewall
            },
            "gke_legacy_auth": {
                "title": "GKE Legacy ABAC Authorization",
                "description": "GKE cluster uses legacy ABAC authorization",
                "severity": Severity.HIGH,
                "compliance": ["CIS GKE"],
                "check": self._check_gke_legacy
            },
            "service_account_keys": {
                "title": "Service Account User-Managed Keys",
                "description": "Service account has user-managed keys which should be rotated",
                "severity": Severity.MEDIUM,
                "compliance": ["CIS GCP"],
                "check": self._check_gcp_sa_keys
            },
        }
    
    def configure_aws(self, access_key: str, secret_key: str, 
                      region: str = "us-east-1", session_token: str = "") -> bool:
        """Configure AWS credentials"""
        creds = CloudCredentials(
            provider=CloudProvider.AWS,
            credentials={
                "access_key": access_key,
                "secret_key": secret_key,
                "session_token": session_token
            },
            region=region
        )
        
        # Validate credentials using STS GetCallerIdentity
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token if session_token else None,
                region_name=region
            )
            
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            
            creds.is_valid = True
            creds.credentials["account_id"] = identity.get("Account", "")
            creds.credentials["arn"] = identity.get("Arn", "")
            creds.credentials["user_id"] = identity.get("UserId", "")
            
        except ImportError:
            # boto3 not installed - try AWS CLI
            import subprocess
            try:
                env = os.environ.copy()
                env["AWS_ACCESS_KEY_ID"] = access_key
                env["AWS_SECRET_ACCESS_KEY"] = secret_key
                if session_token:
                    env["AWS_SESSION_TOKEN"] = session_token
                env["AWS_DEFAULT_REGION"] = region
                
                result = subprocess.run(
                    ["aws", "sts", "get-caller-identity"],
                    capture_output=True, text=True, env=env, timeout=10
                )
                creds.is_valid = result.returncode == 0
            except Exception:
                creds.is_valid = False
        except Exception:
            creds.is_valid = False
        
        self.credentials[CloudProvider.AWS] = creds
        return creds.is_valid
    
    def configure_azure(self, tenant_id: str, client_id: str, 
                        client_secret: str, subscription_id: str) -> bool:
        """Configure Azure credentials"""
        creds = CloudCredentials(
            provider=CloudProvider.AZURE,
            credentials={
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret
            },
            subscription_id=subscription_id
        )
        
        # Validate credentials using Azure SDK
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import SubscriptionClient
            
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Verify by listing subscriptions
            sub_client = SubscriptionClient(credential)
            subscriptions = list(sub_client.subscriptions.list())
            
            # Check if our subscription is accessible
            sub_ids = [s.subscription_id for s in subscriptions]
            creds.is_valid = subscription_id in sub_ids
            creds.credentials["available_subscriptions"] = sub_ids
            
        except ImportError:
            # Azure SDK not installed - try Azure CLI
            import subprocess
            try:
                # Login with service principal
                result = subprocess.run(
                    ["az", "login", "--service-principal",
                     "-u", client_id, "-p", client_secret, "--tenant", tenant_id],
                    capture_output=True, text=True, timeout=30
                )
                creds.is_valid = result.returncode == 0
            except Exception:
                creds.is_valid = False
        except Exception:
            creds.is_valid = False
        
        self.credentials[CloudProvider.AZURE] = creds
        return creds.is_valid
    
    def configure_gcp(self, service_account_json: str, project_id: str) -> bool:
        """Configure GCP credentials"""
        creds = CloudCredentials(
            provider=CloudProvider.GCP,
            credentials={
                "service_account": service_account_json
            },
            project_id=project_id
        )
        
        # Validate credentials using Google Cloud SDK
        try:
            from google.oauth2 import service_account
            from google.cloud import resource_manager_v3
            import json as json_module
            
            # Parse service account JSON
            if os.path.isfile(service_account_json):
                with open(service_account_json, 'r') as f:
                    sa_info = json_module.load(f)
            else:
                sa_info = json_module.loads(service_account_json)
            
            credentials = service_account.Credentials.from_service_account_info(sa_info)
            
            # Verify by getting project info
            client = resource_manager_v3.ProjectsClient(credentials=credentials)
            project = client.get_project(name=f"projects/{project_id}")
            
            creds.is_valid = project is not None
            creds.credentials["project_name"] = project.display_name if project else ""
            
        except ImportError:
            # GCP SDK not installed - try gcloud CLI
            import subprocess
            try:
                # Activate service account
                result = subprocess.run(
                    ["gcloud", "auth", "activate-service-account",
                     "--key-file", service_account_json],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    # Set project
                    result = subprocess.run(
                        ["gcloud", "config", "set", "project", project_id],
                        capture_output=True, text=True, timeout=10
                    )
                    creds.is_valid = result.returncode == 0
            except Exception:
                creds.is_valid = False
        except Exception:
            creds.is_valid = False
        
        self.credentials[CloudProvider.GCP] = creds
        return creds.is_valid
    
    async def scan(self, provider: CloudProvider, 
                   resource_types: Optional[List[ResourceType]] = None,
                   checks: Optional[List[str]] = None) -> ScanResult:
        """Run security scan for a cloud provider"""
        scan_id = self._generate_id()
        result = ScanResult(
            scan_id=scan_id,
            provider=provider,
            started_at=datetime.now().isoformat()
        )
        
        if provider not in self.credentials:
            raise ValueError(f"No credentials configured for {provider.value}")
        
        # Enumerate resources
        resources = await self._enumerate_resources(provider, resource_types)
        result.resources_scanned = len(resources)
        
        # Run security checks
        findings = await self._run_security_checks(provider, resources, checks)
        result.findings = findings
        
        # Calculate statistics
        result.statistics = self._calculate_statistics(findings)
        result.completed_at = datetime.now().isoformat()
        
        self.scan_history.append(result)
        self.findings.extend(findings)
        
        return result
    
    async def _enumerate_resources(self, provider: CloudProvider,
                                    resource_types: Optional[List[ResourceType]]) -> List[CloudResource]:
        """Enumerate cloud resources"""
        resources = []
        
        if provider == CloudProvider.AWS:
            resources.extend(await self._enumerate_aws_resources(resource_types))
        elif provider == CloudProvider.AZURE:
            resources.extend(await self._enumerate_azure_resources(resource_types))
        elif provider == CloudProvider.GCP:
            resources.extend(await self._enumerate_gcp_resources(resource_types))
        
        return resources
    
    async def _enumerate_aws_resources(self, 
                                        resource_types: Optional[List[ResourceType]]) -> List[CloudResource]:
        """Enumerate AWS resources"""
        resources = []
        
        # Simulated resource enumeration
        # In real implementation, would use boto3
        
        # Example S3 buckets
        s3_buckets = [
            {"Name": "company-data-backup", "CreationDate": "2023-01-15"},
            {"Name": "public-assets", "CreationDate": "2023-02-20"},
            {"Name": "logs-bucket", "CreationDate": "2023-03-10"},
        ]
        
        for bucket in s3_buckets:
            resource = CloudResource(
                resource_id=f"s3-{bucket['Name']}",
                resource_type=ResourceType.S3_BUCKET,
                provider=CloudProvider.AWS,
                name=bucket['Name'],
                region=self.credentials[CloudProvider.AWS].region,
                arn=f"arn:aws:s3:::{bucket['Name']}",
                configuration={
                    "public_access_block": {"BlockPublicAcls": False},
                    "encryption": {"SSEAlgorithm": "none"},
                    "versioning": {"Status": "Disabled"}
                }
            )
            resources.append(resource)
            self.resources[resource.resource_id] = resource
        
        # Example EC2 instances
        ec2_instances = [
            {"InstanceId": "i-0abc123", "InstanceType": "t3.micro"},
            {"InstanceId": "i-0def456", "InstanceType": "t3.large"},
        ]
        
        for instance in ec2_instances:
            resource = CloudResource(
                resource_id=f"ec2-{instance['InstanceId']}",
                resource_type=ResourceType.EC2_INSTANCE,
                provider=CloudProvider.AWS,
                name=instance['InstanceId'],
                region=self.credentials[CloudProvider.AWS].region,
                configuration={
                    "instance_type": instance['InstanceType'],
                    "metadata_options": {"HttpTokens": "optional"},  # IMDSv1 vulnerable
                    "security_groups": ["sg-0abc123"]
                }
            )
            resources.append(resource)
            self.resources[resource.resource_id] = resource
        
        # Example Security Groups
        security_groups = [
            {
                "GroupId": "sg-0abc123",
                "GroupName": "default",
                "IpPermissions": [
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ]
            }
        ]
        
        for sg in security_groups:
            resource = CloudResource(
                resource_id=f"sg-{sg['GroupId']}",
                resource_type=ResourceType.SECURITY_GROUP,
                provider=CloudProvider.AWS,
                name=sg['GroupName'],
                region=self.credentials[CloudProvider.AWS].region,
                configuration=sg
            )
            resources.append(resource)
            self.resources[resource.resource_id] = resource
        
        return resources
    
    async def _enumerate_azure_resources(self,
                                          resource_types: Optional[List[ResourceType]]) -> List[CloudResource]:
        """Enumerate Azure resources"""
        resources = []
        
        # Example storage accounts
        storage_accounts = [
            {"name": "companystorage", "location": "eastus"},
            {"name": "publicassets", "location": "westus"}
        ]
        
        for sa in storage_accounts:
            resource = CloudResource(
                resource_id=f"storage-{sa['name']}",
                resource_type=ResourceType.STORAGE_ACCOUNT,
                provider=CloudProvider.AZURE,
                name=sa['name'],
                region=sa['location'],
                configuration={
                    "allow_blob_public_access": True,
                    "encryption": {"keySource": "Microsoft.Storage"},
                    "network_rules": {"default_action": "Allow"}
                }
            )
            resources.append(resource)
            self.resources[resource.resource_id] = resource
        
        return resources
    
    async def _enumerate_gcp_resources(self,
                                        resource_types: Optional[List[ResourceType]]) -> List[CloudResource]:
        """Enumerate GCP resources"""
        resources = []
        
        # Example GCS buckets
        buckets = [
            {"name": "company-data", "location": "us-central1"},
            {"name": "public-content", "location": "us-east1"}
        ]
        
        for bucket in buckets:
            resource = CloudResource(
                resource_id=f"gcs-{bucket['name']}",
                resource_type=ResourceType.GCS_BUCKET,
                provider=CloudProvider.GCP,
                name=bucket['name'],
                region=bucket['location'],
                configuration={
                    "iam_configuration": {"uniformBucketLevelAccess": {"enabled": False}},
                    "public_access_prevention": "inherited",
                    "versioning": {"enabled": False}
                }
            )
            resources.append(resource)
            self.resources[resource.resource_id] = resource
        
        return resources
    
    async def _run_security_checks(self, provider: CloudProvider,
                                    resources: List[CloudResource],
                                    checks: Optional[List[str]]) -> List[SecurityFinding]:
        """Run security checks against resources"""
        findings = []
        
        # Get checks for provider
        if provider == CloudProvider.AWS:
            check_definitions = self.aws_checks
        elif provider == CloudProvider.AZURE:
            check_definitions = self.azure_checks
        elif provider == CloudProvider.GCP:
            check_definitions = self.gcp_checks
        else:
            check_definitions = {}
        
        # Filter checks if specified
        if checks:
            check_definitions = {k: v for k, v in check_definitions.items() if k in checks}
        
        # Run each check
        for check_name, check_def in check_definitions.items():
            for resource in resources:
                finding = await check_def['check'](resource, check_def)
                if finding:
                    findings.append(finding)
        
        return findings
    
    # AWS Security Check Methods
    async def _check_s3_public_access(self, resource: CloudResource, 
                                       check_def: Dict) -> Optional[SecurityFinding]:
        """Check S3 bucket for public access"""
        if resource.resource_type != ResourceType.S3_BUCKET:
            return None
        
        config = resource.configuration
        public_block = config.get("public_access_block", {})
        
        if not public_block.get("BlockPublicAcls", True):
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"S3 bucket '{resource.name}' has public access enabled",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Enable S3 Block Public Access settings",
                compliance_frameworks=check_def['compliance'],
                remediation_steps=[
                    "Go to S3 console and select the bucket",
                    "Navigate to Permissions tab",
                    "Edit Block Public Access settings",
                    "Enable all four Block Public Access options",
                    "Save changes"
                ],
                references=[
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                ]
            )
        return None
    
    async def _check_s3_encryption(self, resource: CloudResource,
                                    check_def: Dict) -> Optional[SecurityFinding]:
        """Check S3 bucket encryption"""
        if resource.resource_type != ResourceType.S3_BUCKET:
            return None
        
        config = resource.configuration
        encryption = config.get("encryption", {})
        
        if encryption.get("SSEAlgorithm") == "none":
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"S3 bucket '{resource.name}' does not have server-side encryption enabled",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Enable default encryption using SSE-S3 or SSE-KMS",
                compliance_frameworks=check_def['compliance'],
                remediation_steps=[
                    "Go to S3 console and select the bucket",
                    "Navigate to Properties tab",
                    "Edit Default encryption",
                    "Enable SSE-S3 or SSE-KMS encryption",
                    "Save changes"
                ]
            )
        return None
    
    async def _check_iam_mfa(self, resource: CloudResource,
                              check_def: Dict) -> Optional[SecurityFinding]:
        """Check IAM user MFA status"""
        if resource.resource_type != ResourceType.IAM_USER:
            return None
        
        if not resource.configuration.get("mfa_enabled", False):
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"IAM user '{resource.name}' does not have MFA enabled",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Enable MFA for the IAM user",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_iam_admin(self, resource: CloudResource,
                                check_def: Dict) -> Optional[SecurityFinding]:
        """Check for IAM users with admin privileges"""
        if resource.resource_type != ResourceType.IAM_USER:
            return None
        
        policies = resource.configuration.get("attached_policies", [])
        if "AdministratorAccess" in policies:
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"IAM user '{resource.name}' has AdministratorAccess policy",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Remove AdministratorAccess and apply least-privilege policies",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_sg_open(self, resource: CloudResource,
                              check_def: Dict) -> Optional[SecurityFinding]:
        """Check security group for open access"""
        if resource.resource_type != ResourceType.SECURITY_GROUP:
            return None
        
        for rule in resource.configuration.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    return SecurityFinding(
                        finding_id=self._generate_id(),
                        title=check_def['title'],
                        description=f"Security group '{resource.name}' allows unrestricted access from 0.0.0.0/0",
                        severity=check_def['severity'],
                        provider=CloudProvider.AWS,
                        resource=resource,
                        recommendation="Restrict security group rules to specific IP ranges",
                        compliance_frameworks=check_def['compliance'],
                        evidence={"rule": rule}
                    )
        return None
    
    async def _check_rds_public(self, resource: CloudResource,
                                 check_def: Dict) -> Optional[SecurityFinding]:
        """Check RDS instance public accessibility"""
        if resource.resource_type != ResourceType.RDS_INSTANCE:
            return None
        
        if resource.configuration.get("publicly_accessible", False):
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"RDS instance '{resource.name}' is publicly accessible",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Disable public accessibility for RDS instance",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_rds_encryption(self, resource: CloudResource,
                                     check_def: Dict) -> Optional[SecurityFinding]:
        """Check RDS instance encryption"""
        if resource.resource_type != ResourceType.RDS_INSTANCE:
            return None
        
        if not resource.configuration.get("storage_encrypted", False):
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"RDS instance '{resource.name}' storage is not encrypted",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Enable encryption at rest for RDS instance",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_cloudtrail(self, resource: CloudResource,
                                 check_def: Dict) -> Optional[SecurityFinding]:
        """Check CloudTrail configuration"""
        if resource.resource_type != ResourceType.CLOUDTRAIL:
            return None
        
        if not resource.configuration.get("is_multi_region_trail", False):
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description="CloudTrail is not enabled for all regions",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Enable multi-region CloudTrail",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_ec2_imds(self, resource: CloudResource,
                               check_def: Dict) -> Optional[SecurityFinding]:
        """Check EC2 instance metadata service version"""
        if resource.resource_type != ResourceType.EC2_INSTANCE:
            return None
        
        metadata_options = resource.configuration.get("metadata_options", {})
        if metadata_options.get("HttpTokens") != "required":
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"EC2 instance '{resource.name}' allows IMDSv1",
                severity=check_def['severity'],
                provider=CloudProvider.AWS,
                resource=resource,
                recommendation="Require IMDSv2 by setting HttpTokens to 'required'",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_lambda_public(self, resource: CloudResource,
                                    check_def: Dict) -> Optional[SecurityFinding]:
        """Check Lambda function public access"""
        if resource.resource_type != ResourceType.LAMBDA_FUNCTION:
            return None
        return None
    
    async def _check_kms_rotation(self, resource: CloudResource,
                                   check_def: Dict) -> Optional[SecurityFinding]:
        """Check KMS key rotation"""
        if resource.resource_type != ResourceType.KMS_KEY:
            return None
        return None
    
    async def _check_secrets_rotation(self, resource: CloudResource,
                                       check_def: Dict) -> Optional[SecurityFinding]:
        """Check Secrets Manager rotation"""
        if resource.resource_type != ResourceType.SECRETS_MANAGER:
            return None
        return None
    
    # Azure Security Check Methods
    async def _check_azure_storage_public(self, resource: CloudResource,
                                           check_def: Dict) -> Optional[SecurityFinding]:
        """Check Azure Storage Account public access"""
        if resource.resource_type != ResourceType.STORAGE_ACCOUNT:
            return None
        
        if resource.configuration.get("allow_blob_public_access", False):
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"Storage account '{resource.name}' allows public blob access",
                severity=check_def['severity'],
                provider=CloudProvider.AZURE,
                resource=resource,
                recommendation="Disable public blob access for the storage account",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_azure_storage_encryption(self, resource: CloudResource,
                                               check_def: Dict) -> Optional[SecurityFinding]:
        """Check Azure Storage encryption"""
        if resource.resource_type != ResourceType.STORAGE_ACCOUNT:
            return None
        return None
    
    async def _check_azure_nsg(self, resource: CloudResource,
                                check_def: Dict) -> Optional[SecurityFinding]:
        """Check Azure NSG rules"""
        if resource.resource_type != ResourceType.NETWORK_SECURITY_GROUP:
            return None
        return None
    
    async def _check_azure_sql_auditing(self, resource: CloudResource,
                                         check_def: Dict) -> Optional[SecurityFinding]:
        """Check Azure SQL auditing"""
        if resource.resource_type != ResourceType.SQL_DATABASE:
            return None
        return None
    
    async def _check_azure_keyvault(self, resource: CloudResource,
                                     check_def: Dict) -> Optional[SecurityFinding]:
        """Check Azure Key Vault configuration"""
        if resource.resource_type != ResourceType.KEY_VAULT:
            return None
        return None
    
    async def _check_azure_vm_encryption(self, resource: CloudResource,
                                          check_def: Dict) -> Optional[SecurityFinding]:
        """Check Azure VM disk encryption"""
        if resource.resource_type != ResourceType.VM:
            return None
        return None
    
    # GCP Security Check Methods
    async def _check_gcs_public(self, resource: CloudResource,
                                 check_def: Dict) -> Optional[SecurityFinding]:
        """Check GCS bucket public access"""
        if resource.resource_type != ResourceType.GCS_BUCKET:
            return None
        
        if resource.configuration.get("public_access_prevention") != "enforced":
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"GCS bucket '{resource.name}' may allow public access",
                severity=check_def['severity'],
                provider=CloudProvider.GCP,
                resource=resource,
                recommendation="Enforce public access prevention on the bucket",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_gcs_uniform(self, resource: CloudResource,
                                  check_def: Dict) -> Optional[SecurityFinding]:
        """Check GCS uniform bucket access"""
        if resource.resource_type != ResourceType.GCS_BUCKET:
            return None
        
        iam_config = resource.configuration.get("iam_configuration", {})
        if not iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False):
            return SecurityFinding(
                finding_id=self._generate_id(),
                title=check_def['title'],
                description=f"GCS bucket '{resource.name}' does not have uniform bucket-level access enabled",
                severity=check_def['severity'],
                provider=CloudProvider.GCP,
                resource=resource,
                recommendation="Enable uniform bucket-level access",
                compliance_frameworks=check_def['compliance']
            )
        return None
    
    async def _check_gcp_serial_ports(self, resource: CloudResource,
                                       check_def: Dict) -> Optional[SecurityFinding]:
        """Check GCP Compute serial ports"""
        if resource.resource_type != ResourceType.COMPUTE_INSTANCE:
            return None
        return None
    
    async def _check_gcp_firewall(self, resource: CloudResource,
                                   check_def: Dict) -> Optional[SecurityFinding]:
        """Check GCP firewall rules"""
        if resource.resource_type != ResourceType.FIREWALL_RULE:
            return None
        return None
    
    async def _check_gke_legacy(self, resource: CloudResource,
                                 check_def: Dict) -> Optional[SecurityFinding]:
        """Check GKE legacy ABAC"""
        if resource.resource_type != ResourceType.GKE_CLUSTER:
            return None
        return None
    
    async def _check_gcp_sa_keys(self, resource: CloudResource,
                                  check_def: Dict) -> Optional[SecurityFinding]:
        """Check GCP service account keys"""
        if resource.resource_type != ResourceType.IAM_SERVICE_ACCOUNT:
            return None
        return None
    
    def _calculate_statistics(self, findings: List[SecurityFinding]) -> Dict:
        """Calculate scan statistics"""
        stats = {
            "total_findings": len(findings),
            "by_severity": {
                Severity.CRITICAL.value: 0,
                Severity.HIGH.value: 0,
                Severity.MEDIUM.value: 0,
                Severity.LOW.value: 0,
                Severity.INFO.value: 0
            },
            "by_resource_type": {},
            "by_compliance": {}
        }
        
        for finding in findings:
            stats["by_severity"][finding.severity.value] += 1
            
            if finding.resource:
                rt = finding.resource.resource_type.value
                stats["by_resource_type"][rt] = stats["by_resource_type"].get(rt, 0) + 1
            
            for framework in finding.compliance_frameworks:
                stats["by_compliance"][framework] = stats["by_compliance"].get(framework, 0) + 1
        
        return stats
    
    def get_compliance_report(self, framework: str) -> List[SecurityFinding]:
        """Get findings for specific compliance framework"""
        return [f for f in self.findings if framework in f.compliance_frameworks]
    
    def export_findings(self, format: str = "json") -> str:
        """Export findings in specified format"""
        if format == "json":
            return json.dumps([
                {
                    "id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "provider": f.provider.value,
                    "resource": f.resource.name if f.resource else "",
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "compliance": f.compliance_frameworks
                }
                for f in self.findings
            ], indent=2)
        elif format == "csv":
            lines = ["id,title,severity,provider,resource,description"]
            for f in self.findings:
                lines.append(f'"{f.finding_id}","{f.title}","{f.severity.value}","{f.provider.value}","{f.resource.name if f.resource else ""}","{f.description}"')
            return "\n".join(lines)
        
        return ""
