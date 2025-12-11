"""
HydraRecon Cloud Security Posture Management (CSPM) Module
Comprehensive multi-cloud security analysis and compliance
"""

import asyncio
import json
import os
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging

try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import asset_v1
    from google.cloud import securitycenter
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Cloud service providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA = "alibaba"
    ORACLE = "oracle"
    MULTI_CLOUD = "multi_cloud"


class ComplianceFramework(Enum):
    """Compliance frameworks"""
    CIS = "cis"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    FedRAMP = "fedramp"
    CUSTOM = "custom"


class ResourceType(Enum):
    """Cloud resource types"""
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    IAM = "iam"
    SECRETS = "secrets"
    LOGGING = "logging"
    ENCRYPTION = "encryption"
    CONTAINER = "container"
    SERVERLESS = "serverless"


class SeverityLevel(Enum):
    """Finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(Enum):
    """Finding status"""
    OPEN = "open"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


@dataclass
class CloudResource:
    """Cloud resource information"""
    resource_id: str
    resource_type: ResourceType
    provider: CloudProvider
    region: str
    name: str
    arn: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    properties: Dict[str, Any] = field(default_factory=dict)
    created: Optional[datetime] = None
    last_modified: Optional[datetime] = None


@dataclass
class SecurityFinding:
    """Security finding"""
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel
    resource: CloudResource
    compliance_framework: Optional[ComplianceFramework] = None
    compliance_control: Optional[str] = None
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    evidence: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class ComplianceCheck:
    """Compliance check definition"""
    check_id: str
    title: str
    description: str
    severity: SeverityLevel
    resource_type: ResourceType
    framework: ComplianceFramework
    control_id: str
    check_function: Optional[Callable] = None
    remediation: str = ""


@dataclass
class ComplianceReport:
    """Compliance report"""
    report_id: str
    framework: ComplianceFramework
    generated_at: datetime
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    findings: List[SecurityFinding] = field(default_factory=list)
    score: float = 0.0


class AWSSecurityAnalyzer:
    """AWS security analyzer"""
    
    def __init__(self, profile: Optional[str] = None, region: str = 'us-east-1'):
        self.profile = profile
        self.region = region
        self.session = None
        self.findings: List[SecurityFinding] = []
        
        if AWS_AVAILABLE:
            self._init_session()
            
    def _init_session(self):
        """Initialize AWS session"""
        try:
            if self.profile:
                self.session = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                self.session = boto3.Session(region_name=self.region)
        except Exception as e:
            logger.error(f"AWS session error: {e}")
            
    async def analyze_all(self) -> List[SecurityFinding]:
        """Analyze all AWS security configurations"""
        findings = []
        
        findings.extend(await self._analyze_s3())
        findings.extend(await self._analyze_iam())
        findings.extend(await self._analyze_ec2())
        findings.extend(await self._analyze_rds())
        findings.extend(await self._analyze_security_groups())
        findings.extend(await self._analyze_cloudtrail())
        findings.extend(await self._analyze_kms())
        findings.extend(await self._analyze_lambda())
        findings.extend(await self._analyze_vpc())
        findings.extend(await self._analyze_secrets_manager())
        
        self.findings = findings
        return findings
        
    async def _analyze_s3(self) -> List[SecurityFinding]:
        """Analyze S3 bucket security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()
            
            for bucket in buckets.get('Buckets', []):
                bucket_name = bucket['Name']
                resource = CloudResource(
                    resource_id=bucket_name,
                    resource_type=ResourceType.STORAGE,
                    provider=CloudProvider.AWS,
                    region='global',
                    name=bucket_name,
                    arn=f"arn:aws:s3:::{bucket_name}",
                    created=bucket.get('CreationDate')
                )
                
                # Check public access block
                try:
                    public_access = s3.get_public_access_block(Bucket=bucket_name)
                    config = public_access['PublicAccessBlockConfiguration']
                    
                    if not all([
                        config.get('BlockPublicAcls'),
                        config.get('IgnorePublicAcls'),
                        config.get('BlockPublicPolicy'),
                        config.get('RestrictPublicBuckets')
                    ]):
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-S3-PUBLIC-{bucket_name}",
                            title="S3 Public Access Not Fully Blocked",
                            description=f"Bucket {bucket_name} does not have all public access blocks enabled",
                            severity=SeverityLevel.HIGH,
                            resource=resource,
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="2.1.5",
                            remediation="Enable all public access block settings"
                        ))
                except ClientError:
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-S3-NOPAB-{bucket_name}",
                        title="S3 Public Access Block Not Configured",
                        description=f"Bucket {bucket_name} has no public access block configuration",
                        severity=SeverityLevel.HIGH,
                        resource=resource,
                        remediation="Configure public access block settings"
                    ))
                    
                # Check encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-S3-NOENC-{bucket_name}",
                        title="S3 Bucket Encryption Not Enabled",
                        description=f"Bucket {bucket_name} does not have default encryption",
                        severity=SeverityLevel.MEDIUM,
                        resource=resource,
                        compliance_framework=ComplianceFramework.CIS,
                        compliance_control="2.1.1",
                        remediation="Enable default encryption with SSE-S3 or SSE-KMS"
                    ))
                    
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-S3-NOVER-{bucket_name}",
                            title="S3 Bucket Versioning Not Enabled",
                            description=f"Bucket {bucket_name} does not have versioning enabled",
                            severity=SeverityLevel.LOW,
                            resource=resource,
                            remediation="Enable bucket versioning"
                        ))
                except ClientError:
                    pass
                    
                # Check logging
                try:
                    logging_config = s3.get_bucket_logging(Bucket=bucket_name)
                    if not logging_config.get('LoggingEnabled'):
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-S3-NOLOG-{bucket_name}",
                            title="S3 Bucket Logging Not Enabled",
                            description=f"Bucket {bucket_name} does not have access logging",
                            severity=SeverityLevel.LOW,
                            resource=resource,
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="2.1.3",
                            remediation="Enable server access logging"
                        ))
                except ClientError:
                    pass
                    
        except Exception as e:
            logger.error(f"S3 analysis error: {e}")
            
        return findings
        
    async def _analyze_iam(self) -> List[SecurityFinding]:
        """Analyze IAM security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            iam = self.session.client('iam')
            
            # Check for root account usage
            try:
                credential_report = iam.get_credential_report()
                # Parse CSV report for root account activity
            except ClientError:
                pass
                
            # Check password policy
            try:
                password_policy = iam.get_account_password_policy()
                policy = password_policy['PasswordPolicy']
                
                if policy.get('MinimumPasswordLength', 0) < 14:
                    findings.append(SecurityFinding(
                        finding_id="AWS-IAM-WEAKPWD",
                        title="Weak Password Policy",
                        description="Password minimum length is less than 14 characters",
                        severity=SeverityLevel.MEDIUM,
                        resource=CloudResource(
                            resource_id="password-policy",
                            resource_type=ResourceType.IAM,
                            provider=CloudProvider.AWS,
                            region='global',
                            name='PasswordPolicy'
                        ),
                        compliance_framework=ComplianceFramework.CIS,
                        compliance_control="1.8",
                        remediation="Set minimum password length to 14 or more"
                    ))
                    
                if not policy.get('RequireUppercaseCharacters'):
                    findings.append(SecurityFinding(
                        finding_id="AWS-IAM-NOUPPERCASE",
                        title="Password Policy Missing Uppercase Requirement",
                        description="Password policy does not require uppercase characters",
                        severity=SeverityLevel.LOW,
                        resource=CloudResource(
                            resource_id="password-policy",
                            resource_type=ResourceType.IAM,
                            provider=CloudProvider.AWS,
                            region='global',
                            name='PasswordPolicy'
                        ),
                        remediation="Enable uppercase character requirement"
                    ))
                    
            except ClientError:
                findings.append(SecurityFinding(
                    finding_id="AWS-IAM-NOPOLICY",
                    title="No Password Policy",
                    description="No IAM password policy is configured",
                    severity=SeverityLevel.HIGH,
                    resource=CloudResource(
                        resource_id="password-policy",
                        resource_type=ResourceType.IAM,
                        provider=CloudProvider.AWS,
                        region='global',
                        name='PasswordPolicy'
                    ),
                    compliance_framework=ComplianceFramework.CIS,
                    compliance_control="1.5-1.11",
                    remediation="Create IAM password policy"
                ))
                
            # Check for users without MFA
            users = iam.list_users()
            for user in users.get('Users', []):
                username = user['UserName']
                
                mfa_devices = iam.list_mfa_devices(UserName=username)
                if not mfa_devices.get('MFADevices'):
                    # Check if user has console access
                    try:
                        login_profile = iam.get_login_profile(UserName=username)
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-IAM-NOMFA-{username}",
                            title="User Without MFA",
                            description=f"User {username} has console access but no MFA enabled",
                            severity=SeverityLevel.HIGH,
                            resource=CloudResource(
                                resource_id=username,
                                resource_type=ResourceType.IAM,
                                provider=CloudProvider.AWS,
                                region='global',
                                name=username,
                                arn=user['Arn']
                            ),
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="1.2",
                            remediation="Enable MFA for the user"
                        ))
                    except ClientError:
                        pass
                        
                # Check for old access keys
                access_keys = iam.list_access_keys(UserName=username)
                for key in access_keys.get('AccessKeyMetadata', []):
                    create_date = key['CreateDate']
                    age_days = (datetime.now(create_date.tzinfo) - create_date).days
                    
                    if age_days > 90:
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-IAM-OLDKEY-{key['AccessKeyId']}",
                            title="Old Access Key",
                            description=f"Access key {key['AccessKeyId']} for user {username} is {age_days} days old",
                            severity=SeverityLevel.MEDIUM,
                            resource=CloudResource(
                                resource_id=key['AccessKeyId'],
                                resource_type=ResourceType.IAM,
                                provider=CloudProvider.AWS,
                                region='global',
                                name=f"{username}-key"
                            ),
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="1.4",
                            remediation="Rotate access keys every 90 days"
                        ))
                        
            # Check for inline policies
            for user in users.get('Users', []):
                inline_policies = iam.list_user_policies(UserName=user['UserName'])
                if inline_policies.get('PolicyNames'):
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-IAM-INLINE-{user['UserName']}",
                        title="User Has Inline Policies",
                        description=f"User {user['UserName']} has inline policies instead of managed policies",
                        severity=SeverityLevel.LOW,
                        resource=CloudResource(
                            resource_id=user['UserName'],
                            resource_type=ResourceType.IAM,
                            provider=CloudProvider.AWS,
                            region='global',
                            name=user['UserName'],
                            arn=user['Arn']
                        ),
                        remediation="Convert inline policies to managed policies"
                    ))
                    
        except Exception as e:
            logger.error(f"IAM analysis error: {e}")
            
        return findings
        
    async def _analyze_ec2(self) -> List[SecurityFinding]:
        """Analyze EC2 security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            ec2 = self.session.client('ec2')
            
            instances = ec2.describe_instances()
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    
                    resource = CloudResource(
                        resource_id=instance_id,
                        resource_type=ResourceType.COMPUTE,
                        provider=CloudProvider.AWS,
                        region=self.region,
                        name=self._get_name_tag(instance.get('Tags', [])),
                        properties=instance
                    )
                    
                    # Check if public IP and no EIP
                    if instance.get('PublicIpAddress') and not instance.get('EipAllocationId'):
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-EC2-PUBLICIP-{instance_id}",
                            title="EC2 Instance with Auto-Assigned Public IP",
                            description=f"Instance {instance_id} has an auto-assigned public IP",
                            severity=SeverityLevel.MEDIUM,
                            resource=resource,
                            remediation="Use Elastic IP or remove public IP"
                        ))
                        
                    # Check IMDSv2
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-EC2-IMDSv1-{instance_id}",
                            title="IMDSv1 Enabled",
                            description=f"Instance {instance_id} allows IMDSv1 which is less secure",
                            severity=SeverityLevel.MEDIUM,
                            resource=resource,
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="5.6",
                            remediation="Require IMDSv2 by setting HttpTokens to required"
                        ))
                        
                    # Check EBS encryption
                    for mapping in instance.get('BlockDeviceMappings', []):
                        ebs = mapping.get('Ebs', {})
                        volume_id = ebs.get('VolumeId')
                        
                        if volume_id:
                            volumes = ec2.describe_volumes(VolumeIds=[volume_id])
                            for volume in volumes.get('Volumes', []):
                                if not volume.get('Encrypted'):
                                    findings.append(SecurityFinding(
                                        finding_id=f"AWS-EC2-EBSNOENC-{volume_id}",
                                        title="Unencrypted EBS Volume",
                                        description=f"Volume {volume_id} attached to {instance_id} is not encrypted",
                                        severity=SeverityLevel.MEDIUM,
                                        resource=resource,
                                        compliance_framework=ComplianceFramework.CIS,
                                        compliance_control="2.2.1",
                                        remediation="Enable EBS encryption"
                                    ))
                                    
        except Exception as e:
            logger.error(f"EC2 analysis error: {e}")
            
        return findings
        
    async def _analyze_rds(self) -> List[SecurityFinding]:
        """Analyze RDS security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            rds = self.session.client('rds')
            
            instances = rds.describe_db_instances()
            for instance in instances.get('DBInstances', []):
                db_id = instance['DBInstanceIdentifier']
                
                resource = CloudResource(
                    resource_id=db_id,
                    resource_type=ResourceType.DATABASE,
                    provider=CloudProvider.AWS,
                    region=self.region,
                    name=db_id,
                    arn=instance['DBInstanceArn']
                )
                
                # Check public accessibility
                if instance.get('PubliclyAccessible'):
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-RDS-PUBLIC-{db_id}",
                        title="RDS Instance Publicly Accessible",
                        description=f"RDS instance {db_id} is publicly accessible",
                        severity=SeverityLevel.CRITICAL,
                        resource=resource,
                        compliance_framework=ComplianceFramework.CIS,
                        compliance_control="2.3.1",
                        remediation="Disable public accessibility"
                    ))
                    
                # Check encryption
                if not instance.get('StorageEncrypted'):
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-RDS-NOENC-{db_id}",
                        title="RDS Storage Not Encrypted",
                        description=f"RDS instance {db_id} does not have storage encryption",
                        severity=SeverityLevel.HIGH,
                        resource=resource,
                        compliance_framework=ComplianceFramework.CIS,
                        compliance_control="2.3.1",
                        remediation="Enable storage encryption"
                    ))
                    
                # Check backup retention
                if instance.get('BackupRetentionPeriod', 0) < 7:
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-RDS-BACKUP-{db_id}",
                        title="Short Backup Retention",
                        description=f"RDS instance {db_id} has backup retention less than 7 days",
                        severity=SeverityLevel.LOW,
                        resource=resource,
                        remediation="Increase backup retention to at least 7 days"
                    ))
                    
                # Check deletion protection
                if not instance.get('DeletionProtection'):
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-RDS-NODELETE-{db_id}",
                        title="Deletion Protection Disabled",
                        description=f"RDS instance {db_id} does not have deletion protection",
                        severity=SeverityLevel.MEDIUM,
                        resource=resource,
                        remediation="Enable deletion protection"
                    ))
                    
        except Exception as e:
            logger.error(f"RDS analysis error: {e}")
            
        return findings
        
    async def _analyze_security_groups(self) -> List[SecurityFinding]:
        """Analyze security group rules"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            ec2 = self.session.client('ec2')
            
            security_groups = ec2.describe_security_groups()
            for sg in security_groups.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                
                resource = CloudResource(
                    resource_id=sg_id,
                    resource_type=ResourceType.NETWORK,
                    provider=CloudProvider.AWS,
                    region=self.region,
                    name=sg.get('GroupName', sg_id)
                )
                
                # Check ingress rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        
                        if cidr == '0.0.0.0/0':
                            port = rule.get('FromPort')
                            protocol = rule.get('IpProtocol')
                            
                            # Critical ports
                            critical_ports = {
                                22: ('SSH', SeverityLevel.CRITICAL),
                                3389: ('RDP', SeverityLevel.CRITICAL),
                                3306: ('MySQL', SeverityLevel.HIGH),
                                5432: ('PostgreSQL', SeverityLevel.HIGH),
                                1433: ('MSSQL', SeverityLevel.HIGH),
                                27017: ('MongoDB', SeverityLevel.HIGH),
                            }
                            
                            if port in critical_ports:
                                service, severity = critical_ports[port]
                                findings.append(SecurityFinding(
                                    finding_id=f"AWS-SG-OPEN-{sg_id}-{port}",
                                    title=f"{service} Open to Internet",
                                    description=f"Security group {sg_id} allows {service} (port {port}) from 0.0.0.0/0",
                                    severity=severity,
                                    resource=resource,
                                    compliance_framework=ComplianceFramework.CIS,
                                    compliance_control="5.2",
                                    remediation=f"Restrict {service} access to specific IP ranges"
                                ))
                            elif protocol == '-1':
                                findings.append(SecurityFinding(
                                    finding_id=f"AWS-SG-ALLTRAFFIC-{sg_id}",
                                    title="All Traffic Allowed from Internet",
                                    description=f"Security group {sg_id} allows all traffic from 0.0.0.0/0",
                                    severity=SeverityLevel.CRITICAL,
                                    resource=resource,
                                    remediation="Remove unrestricted ingress rules"
                                ))
                                
        except Exception as e:
            logger.error(f"Security group analysis error: {e}")
            
        return findings
        
    async def _analyze_cloudtrail(self) -> List[SecurityFinding]:
        """Analyze CloudTrail configuration"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            cloudtrail = self.session.client('cloudtrail')
            
            trails = cloudtrail.describe_trails()
            if not trails.get('trailList'):
                findings.append(SecurityFinding(
                    finding_id="AWS-CT-NOTRAIL",
                    title="No CloudTrail Configured",
                    description="No CloudTrail trail is configured in this region",
                    severity=SeverityLevel.CRITICAL,
                    resource=CloudResource(
                        resource_id='cloudtrail',
                        resource_type=ResourceType.LOGGING,
                        provider=CloudProvider.AWS,
                        region=self.region,
                        name='CloudTrail'
                    ),
                    compliance_framework=ComplianceFramework.CIS,
                    compliance_control="3.1",
                    remediation="Create a CloudTrail trail"
                ))
            else:
                for trail in trails['trailList']:
                    trail_name = trail['Name']
                    
                    resource = CloudResource(
                        resource_id=trail_name,
                        resource_type=ResourceType.LOGGING,
                        provider=CloudProvider.AWS,
                        region=self.region,
                        name=trail_name,
                        arn=trail.get('TrailARN')
                    )
                    
                    # Check multi-region
                    if not trail.get('IsMultiRegionTrail'):
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-CT-NOREGION-{trail_name}",
                            title="CloudTrail Not Multi-Region",
                            description=f"Trail {trail_name} is not configured for multi-region",
                            severity=SeverityLevel.MEDIUM,
                            resource=resource,
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="3.1",
                            remediation="Enable multi-region for the trail"
                        ))
                        
                    # Check log file validation
                    if not trail.get('LogFileValidationEnabled'):
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-CT-NOVAL-{trail_name}",
                            title="Log File Validation Disabled",
                            description=f"Trail {trail_name} does not have log file validation",
                            severity=SeverityLevel.MEDIUM,
                            resource=resource,
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="3.2",
                            remediation="Enable log file validation"
                        ))
                        
                    # Check encryption
                    if not trail.get('KMSKeyId'):
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-CT-NOENC-{trail_name}",
                            title="CloudTrail Logs Not Encrypted",
                            description=f"Trail {trail_name} logs are not encrypted with KMS",
                            severity=SeverityLevel.MEDIUM,
                            resource=resource,
                            compliance_framework=ComplianceFramework.CIS,
                            compliance_control="3.7",
                            remediation="Enable KMS encryption for CloudTrail logs"
                        ))
                        
        except Exception as e:
            logger.error(f"CloudTrail analysis error: {e}")
            
        return findings
        
    async def _analyze_kms(self) -> List[SecurityFinding]:
        """Analyze KMS security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            kms = self.session.client('kms')
            
            keys = kms.list_keys()
            for key in keys.get('Keys', []):
                key_id = key['KeyId']
                
                # Get key details
                key_info = kms.describe_key(KeyId=key_id)
                metadata = key_info['KeyMetadata']
                
                if metadata['KeyManager'] == 'CUSTOMER':
                    resource = CloudResource(
                        resource_id=key_id,
                        resource_type=ResourceType.ENCRYPTION,
                        provider=CloudProvider.AWS,
                        region=self.region,
                        name=metadata.get('Description', key_id),
                        arn=metadata['Arn']
                    )
                    
                    # Check rotation
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get('KeyRotationEnabled'):
                            findings.append(SecurityFinding(
                                finding_id=f"AWS-KMS-NOROT-{key_id}",
                                title="KMS Key Rotation Disabled",
                                description=f"KMS key {key_id} does not have rotation enabled",
                                severity=SeverityLevel.MEDIUM,
                                resource=resource,
                                compliance_framework=ComplianceFramework.CIS,
                                compliance_control="3.8",
                                remediation="Enable automatic key rotation"
                            ))
                    except ClientError:
                        pass
                        
        except Exception as e:
            logger.error(f"KMS analysis error: {e}")
            
        return findings
        
    async def _analyze_lambda(self) -> List[SecurityFinding]:
        """Analyze Lambda security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            lambda_client = self.session.client('lambda')
            
            functions = lambda_client.list_functions()
            for func in functions.get('Functions', []):
                func_name = func['FunctionName']
                
                resource = CloudResource(
                    resource_id=func_name,
                    resource_type=ResourceType.SERVERLESS,
                    provider=CloudProvider.AWS,
                    region=self.region,
                    name=func_name,
                    arn=func['FunctionArn']
                )
                
                # Check for public access
                try:
                    policy = lambda_client.get_policy(FunctionName=func_name)
                    policy_doc = json.loads(policy['Policy'])
                    
                    for statement in policy_doc.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal.get('AWS') == '*':
                            findings.append(SecurityFinding(
                                finding_id=f"AWS-LAMBDA-PUBLIC-{func_name}",
                                title="Lambda Function Publicly Accessible",
                                description=f"Lambda function {func_name} has public access policy",
                                severity=SeverityLevel.HIGH,
                                resource=resource,
                                remediation="Restrict Lambda access to specific principals"
                            ))
                except ClientError:
                    pass
                    
                # Check for old runtimes
                runtime = func.get('Runtime', '')
                deprecated_runtimes = ['python2.7', 'python3.6', 'nodejs10.x', 'nodejs8.10']
                
                if runtime in deprecated_runtimes:
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-LAMBDA-OLDRT-{func_name}",
                        title="Deprecated Lambda Runtime",
                        description=f"Lambda function {func_name} uses deprecated runtime {runtime}",
                        severity=SeverityLevel.MEDIUM,
                        resource=resource,
                        remediation="Update to supported runtime version"
                    ))
                    
                # Check environment variables for secrets
                env_vars = func.get('Environment', {}).get('Variables', {})
                secret_patterns = ['password', 'secret', 'key', 'token', 'api_key']
                
                for key in env_vars:
                    if any(pattern in key.lower() for pattern in secret_patterns):
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-LAMBDA-SECRET-{func_name}-{key}",
                            title="Potential Secret in Environment Variable",
                            description=f"Lambda function {func_name} may have secret in variable {key}",
                            severity=SeverityLevel.MEDIUM,
                            resource=resource,
                            remediation="Use AWS Secrets Manager or Parameter Store"
                        ))
                        
        except Exception as e:
            logger.error(f"Lambda analysis error: {e}")
            
        return findings
        
    async def _analyze_vpc(self) -> List[SecurityFinding]:
        """Analyze VPC security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            ec2 = self.session.client('ec2')
            
            # Check VPC Flow Logs
            vpcs = ec2.describe_vpcs()
            for vpc in vpcs.get('Vpcs', []):
                vpc_id = vpc['VpcId']
                
                resource = CloudResource(
                    resource_id=vpc_id,
                    resource_type=ResourceType.NETWORK,
                    provider=CloudProvider.AWS,
                    region=self.region,
                    name=self._get_name_tag(vpc.get('Tags', []))
                )
                
                # Check flow logs
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )
                
                if not flow_logs.get('FlowLogs'):
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-VPC-NOFLOW-{vpc_id}",
                        title="VPC Flow Logs Disabled",
                        description=f"VPC {vpc_id} does not have flow logs enabled",
                        severity=SeverityLevel.MEDIUM,
                        resource=resource,
                        compliance_framework=ComplianceFramework.CIS,
                        compliance_control="3.9",
                        remediation="Enable VPC Flow Logs"
                    ))
                    
        except Exception as e:
            logger.error(f"VPC analysis error: {e}")
            
        return findings
        
    async def _analyze_secrets_manager(self) -> List[SecurityFinding]:
        """Analyze Secrets Manager security"""
        findings = []
        
        if not self.session:
            return findings
            
        try:
            secretsmanager = self.session.client('secretsmanager')
            
            secrets = secretsmanager.list_secrets()
            for secret in secrets.get('SecretList', []):
                secret_name = secret['Name']
                
                resource = CloudResource(
                    resource_id=secret_name,
                    resource_type=ResourceType.SECRETS,
                    provider=CloudProvider.AWS,
                    region=self.region,
                    name=secret_name,
                    arn=secret['ARN']
                )
                
                # Check rotation
                if not secret.get('RotationEnabled'):
                    findings.append(SecurityFinding(
                        finding_id=f"AWS-SM-NOROT-{hashlib.md5(secret_name.encode()).hexdigest()[:8]}",
                        title="Secret Rotation Disabled",
                        description=f"Secret {secret_name} does not have automatic rotation",
                        severity=SeverityLevel.LOW,
                        resource=resource,
                        remediation="Enable automatic secret rotation"
                    ))
                    
                # Check last accessed
                last_accessed = secret.get('LastAccessedDate')
                if last_accessed:
                    days_since = (datetime.now(last_accessed.tzinfo) - last_accessed).days
                    if days_since > 90:
                        findings.append(SecurityFinding(
                            finding_id=f"AWS-SM-UNUSED-{hashlib.md5(secret_name.encode()).hexdigest()[:8]}",
                            title="Potentially Unused Secret",
                            description=f"Secret {secret_name} not accessed in {days_since} days",
                            severity=SeverityLevel.LOW,
                            resource=resource,
                            remediation="Review and remove if unused"
                        ))
                        
        except Exception as e:
            logger.error(f"Secrets Manager analysis error: {e}")
            
        return findings
        
    def _get_name_tag(self, tags: List[Dict]) -> str:
        """Get Name tag value"""
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value', '')
        return ''


class CloudSecurityPostureManager:
    """Main CSPM integration class"""
    
    def __init__(self):
        self.aws_analyzer: Optional[AWSSecurityAnalyzer] = None
        self.findings: List[SecurityFinding] = []
        self.compliance_reports: Dict[str, ComplianceReport] = {}
        
    def configure_aws(self, profile: Optional[str] = None, region: str = 'us-east-1'):
        """Configure AWS analyzer"""
        self.aws_analyzer = AWSSecurityAnalyzer(profile, region)
        
    async def full_assessment(self) -> Dict[str, Any]:
        """Perform full cloud security assessment"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'summary': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'by_resource_type': {},
            'by_compliance': {}
        }
        
        # AWS analysis
        if self.aws_analyzer:
            aws_findings = await self.aws_analyzer.analyze_all()
            self.findings.extend(aws_findings)
            
        # Process findings
        for finding in self.findings:
            finding_dict = {
                'id': finding.finding_id,
                'title': finding.title,
                'description': finding.description,
                'severity': finding.severity.value,
                'resource_id': finding.resource.resource_id,
                'resource_type': finding.resource.resource_type.value,
                'provider': finding.resource.provider.value,
                'region': finding.resource.region,
                'remediation': finding.remediation,
                'compliance': {
                    'framework': finding.compliance_framework.value if finding.compliance_framework else None,
                    'control': finding.compliance_control
                }
            }
            
            results['findings'].append(finding_dict)
            results['summary']['total'] += 1
            results['summary'][finding.severity.value] += 1
            
            # By resource type
            res_type = finding.resource.resource_type.value
            if res_type not in results['by_resource_type']:
                results['by_resource_type'][res_type] = 0
            results['by_resource_type'][res_type] += 1
            
            # By compliance
            if finding.compliance_framework:
                framework = finding.compliance_framework.value
                if framework not in results['by_compliance']:
                    results['by_compliance'][framework] = 0
                results['by_compliance'][framework] += 1
                
        return results
        
    def generate_compliance_report(self, framework: ComplianceFramework) -> ComplianceReport:
        """Generate compliance report for framework"""
        framework_findings = [
            f for f in self.findings 
            if f.compliance_framework == framework
        ]
        
        report = ComplianceReport(
            report_id=hashlib.md5(f"{framework.value}-{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            framework=framework,
            generated_at=datetime.now(),
            findings=framework_findings,
            total_checks=len(framework_findings) + 50,  # Placeholder for passed checks
            failed_checks=len(framework_findings),
            passed_checks=50  # Placeholder
        )
        
        report.score = (report.passed_checks / report.total_checks) * 100 if report.total_checks > 0 else 0
        
        self.compliance_reports[framework.value] = report
        return report
        
    def generate_text_report(self) -> str:
        """Generate text report"""
        report = []
        
        report.append("=" * 60)
        report.append("CLOUD SECURITY POSTURE REPORT")
        report.append("=" * 60)
        report.append(f"\nGenerated: {datetime.now().isoformat()}")
        
        # Summary
        report.append(f"\n{'=' * 40}")
        report.append("SUMMARY")
        report.append("=" * 40)
        
        severity_counts = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }
        
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
            
        report.append(f"Total Findings: {len(self.findings)}")
        report.append(f"  Critical: {severity_counts['critical']}")
        report.append(f"  High: {severity_counts['high']}")
        report.append(f"  Medium: {severity_counts['medium']}")
        report.append(f"  Low: {severity_counts['low']}")
        report.append(f"  Info: {severity_counts['info']}")
        
        # Findings by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_findings = [f for f in self.findings if f.severity.value == severity]
            
            if severity_findings:
                report.append(f"\n{'=' * 40}")
                report.append(f"{severity.upper()} FINDINGS")
                report.append("=" * 40)
                
                for finding in severity_findings:
                    report.append(f"\n[{finding.finding_id}] {finding.title}")
                    report.append(f"  Resource: {finding.resource.resource_id}")
                    report.append(f"  Description: {finding.description}")
                    report.append(f"  Remediation: {finding.remediation}")
                    
        return "\n".join(report)
