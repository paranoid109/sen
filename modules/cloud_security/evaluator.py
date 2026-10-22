"""SentinelX Cloud Security Posture Management (CSPM) Evaluator (Module X12).

Audits multi-cloud control plane telemetry and resource configurations (AWS CloudTrail,
GCP Cloud Audit / Stackdriver, Azure Activity Log / ARM) against CIS Multi-Cloud
Benchmarks, NIST CSF, and MITRE ATT&CK Cloud Matrix.

Conforms strictly to Law 1 & Law 2 (Decoupled Module Primacy).
Outputs standardized FindingContract objects.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from contracts.python.models import FindingContract, SeverityLevel

logger = logging.getLogger("sentinelx.cloud_security")


class CloudProvider(str, Enum):
    """Supported cloud infrastructure providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    UNKNOWN = "unknown"


@dataclass
class CloudBenchmarkRule:
    """Definition for a CIS Benchmark or security posture control rule."""

    rule_id: str
    benchmark_control: str  # e.g., "CIS-AWS-2.1.1", "CIS-GCP-1.1", "CIS-AZURE-3.1"
    name: str
    description: str
    severity: SeverityLevel
    provider: CloudProvider
    mitre_attack_id: str
    cwe_id: str = "CWE-284"
    remediation: str = ""


# Canonical CIS Multi-Cloud Benchmark Rules Catalog
CIS_BENCHMARK_RULES: dict[str, CloudBenchmarkRule] = {
    # --- AWS CIS Controls ---
    "RULE-CLOUD-AWS-S3-PUBLIC": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AWS-S3-PUBLIC",
        benchmark_control="CIS-AWS-2.1.1",
        name="AWS S3 Bucket Public Read/Write Exposure",
        description="S3 bucket policy or ACL grants public read/write access to AllUsers or wildcard Principal.",
        severity=SeverityLevel.CRITICAL,
        provider=CloudProvider.AWS,
        mitre_attack_id="T1530",
        cwe_id="CWE-732",
        remediation="Enable S3 Public Access Block at account and bucket level and restrict bucket policy to authenticated IAM principals.",
    ),
    "RULE-CLOUD-AWS-ROOT-NO-MFA": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AWS-ROOT-NO-MFA",
        benchmark_control="CIS-AWS-1.4",
        name="AWS Root Account Console Login Without MFA",
        description="Direct console login using the AWS account root credentials without Multi-Factor Authentication.",
        severity=SeverityLevel.CRITICAL,
        provider=CloudProvider.AWS,
        mitre_attack_id="T1078.004",
        cwe_id="CWE-308",
        remediation="Enforce hardware or virtual MFA token on root account and lock root access keys.",
    ),
    "RULE-CLOUD-AWS-IAM-ADMIN-WILDCARD": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AWS-IAM-ADMIN-WILDCARD",
        benchmark_control="CIS-AWS-1.16",
        name="AWS IAM Wildcard Administrative Privilege Escalation",
        description="IAM policy version created granting unrestricted '*:*' administrative permissions.",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.AWS,
        mitre_attack_id="T1098",
        cwe_id="CWE-284",
        remediation="Apply principle of least privilege using scoped IAM policies and permission boundaries.",
    ),
    "RULE-CLOUD-AWS-SG-INGRESS-OPEN": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AWS-SG-INGRESS-OPEN",
        benchmark_control="CIS-AWS-5.1",
        name="AWS Security Group Ingress Open to 0.0.0.0/0",
        description="Security group allows unrestricted ingress (0.0.0.0/0) on administrative or database ports (22, 3389, 5432).",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.AWS,
        mitre_attack_id="T1046",
        cwe_id="CWE-284",
        remediation="Restrict security group ingress to authorized corporate IP CIDR blocks or VPN gateways.",
    ),
    "RULE-CLOUD-AWS-CLOUDTRAIL-DISABLED": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AWS-CLOUDTRAIL-DISABLED",
        benchmark_control="CIS-AWS-3.1",
        name="AWS CloudTrail Logging Disabled or Deleted",
        description="CloudTrail audit logging stream was stopped or trail was deleted, impairing detection defenses.",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.AWS,
        mitre_attack_id="T1562.001",
        cwe_id="CWE-778",
        remediation="Re-enable CloudTrail logging with multi-region capture and S3 bucket immutability (Object Lock).",
    ),
    # --- GCP CIS Controls ---
    "RULE-CLOUD-GCP-STORAGE-PUBLIC": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-GCP-STORAGE-PUBLIC",
        benchmark_control="CIS-GCP-1.1",
        name="GCP Cloud Storage Bucket Publicly Accessible",
        description="IAM binding on Google Cloud Storage bucket grants storage.objectViewer or storage.admin to allUsers or allAuthenticatedUsers.",
        severity=SeverityLevel.CRITICAL,
        provider=CloudProvider.GCP,
        mitre_attack_id="T1530",
        cwe_id="CWE-732",
        remediation="Enforce uniform bucket-level access and remove allUsers / allAuthenticatedUsers members.",
    ),
    "RULE-CLOUD-GCP-IAM-OVERPRIVILEGED": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-GCP-IAM-OVERPRIVILEGED",
        benchmark_control="CIS-GCP-1.2",
        name="GCP Service Account Overprivileged (Owner/Editor Role)",
        description="Service account granted primitive roles/owner or roles/editor at project level.",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.GCP,
        mitre_attack_id="T1098",
        cwe_id="CWE-284",
        remediation="Grant fine-grained predefined roles instead of primitive owner/editor roles.",
    ),
    "RULE-CLOUD-GCP-FIREWALL-OPEN": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-GCP-FIREWALL-OPEN",
        benchmark_control="CIS-GCP-3.6",
        name="GCP Compute Firewall Ingress 0.0.0.0/0 on Management Ports",
        description="VPC firewall rule permits unrestricted ingress from 0.0.0.0/0 to ports 22 (SSH) or 3389 (RDP).",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.GCP,
        mitre_attack_id="T1046",
        cwe_id="CWE-284",
        remediation="Restrict firewall sourceRanges to trusted bastion IPs or use Identity-Aware Proxy (IAP).",
    ),
    "RULE-CLOUD-GCP-AUDIT-DISABLED": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-GCP-AUDIT-DISABLED",
        benchmark_control="CIS-GCP-2.1",
        name="GCP Cloud Audit Logging Disabled",
        description="IAM policy modification removed default audit logging configs for Google Cloud services.",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.GCP,
        mitre_attack_id="T1562.001",
        cwe_id="CWE-778",
        remediation="Configure data access audit logs for all GCP APIs in the project IAM audit configuration.",
    ),
    # --- Azure CIS Controls ---
    "RULE-CLOUD-AZURE-STORAGE-PUBLIC": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AZURE-STORAGE-PUBLIC",
        benchmark_control="CIS-AZURE-3.1",
        name="Azure Storage Account Public Blob Access Enabled",
        description="Azure Blob Storage account permits anonymous public read access to containers or blobs.",
        severity=SeverityLevel.CRITICAL,
        provider=CloudProvider.AZURE,
        mitre_attack_id="T1530",
        cwe_id="CWE-732",
        remediation="Set 'allowBlobPublicAccess: false' on Azure Storage Account properties.",
    ),
    "RULE-CLOUD-AZURE-NSG-OPEN": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AZURE-NSG-OPEN",
        benchmark_control="CIS-AZURE-5.1",
        name="Azure NSG Inbound Security Rule Open to Internet",
        description="Network Security Group rule allows inbound traffic from Internet / '*' on ports 22 or 3389.",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.AZURE,
        mitre_attack_id="T1046",
        cwe_id="CWE-284",
        remediation="Update NSG inbound rule to restrict sourceAddressPrefix to specific internal or corporate IP subnets.",
    ),
    "RULE-CLOUD-AZURE-OWNER-SUBSCRIPTION": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AZURE-OWNER-SUBSCRIPTION",
        benchmark_control="CIS-AZURE-1.1",
        name="Azure Standing Owner Assignment at Subscription Scope",
        description="Permanent Owner role assignment granted at subscription scope without Privileged Identity Management (PIM).",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.AZURE,
        mitre_attack_id="T1098",
        cwe_id="CWE-284",
        remediation="Migrate standing administrative role assignments to Azure AD PIM with time-bound activation.",
    ),
    "RULE-CLOUD-AZURE-DIAGNOSTICS-DISABLED": CloudBenchmarkRule(
        rule_id="RULE-CLOUD-AZURE-DIAGNOSTICS-DISABLED",
        benchmark_control="CIS-AZURE-2.1",
        name="Azure Activity Log Diagnostic Export Disabled",
        description="Diagnostic settings for Azure Activity Log are unconfigured or removed, risking audit blindspots.",
        severity=SeverityLevel.HIGH,
        provider=CloudProvider.AZURE,
        mitre_attack_id="T1562.001",
        cwe_id="CWE-778",
        remediation="Configure Azure Monitor Diagnostic Settings to export all Activity Log categories to Log Analytics workspace.",
    ),
}


@dataclass
class CloudPostureReport:
    """Summary metrics of a cloud posture audit."""

    total_records_analyzed: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    posture_score: float = 100.0  # 0.0 - 100.0%
    findings_by_provider: dict[str, int] = field(default_factory=dict)
    findings: list[FindingContract] = field(default_factory=list)

    def calculate_score(self) -> float:
        """Computes compliance posture score (0.0 to 100.0).

        Deductions:
          - Critical finding: 20 points
          - High finding: 10 points
          - Medium finding: 5 points
          - Low finding: 2 points
        """
        deductions = (
            (self.critical_count * 20.0)
            + (self.high_count * 10.0)
            + (self.medium_count * 5.0)
            + (self.low_count * 2.0)
        )
        score = max(0.0, min(100.0, 100.0 - deductions))
        self.posture_score = round(score, 1)
        return self.posture_score


class CloudSecurityEvaluator:
    """Multi-cloud CSPM analyzer evaluating AWS, GCP, and Azure events and resource states."""

    def __init__(self, rules: dict[str, CloudBenchmarkRule] | None = None) -> None:
        self.rules = rules or CIS_BENCHMARK_RULES

    def detect_provider(self, record: dict[str, Any]) -> CloudProvider:
        """Infers the cloud provider from log or configuration schema fields."""
        # AWS CloudTrail indicators
        if "eventSource" in record or "awsRegion" in record or "userIdentity" in record:
            return CloudProvider.AWS
        if record.get("event_type", "").startswith("aws_") or "s3" in record.get("target", "").lower():
            return CloudProvider.AWS

        # GCP Cloud Audit indicators
        if "protoPayload" in record or "resource" in record and "type" in record.get("resource", {}):
            return CloudProvider.GCP
        if record.get("event_type", "").startswith("gcp_") or "gcs" in record.get("target", "").lower():
            return CloudProvider.GCP

        # Azure Activity Log indicators
        if "operationName" in record or "resourceId" in record and "/subscriptions/" in str(record.get("resourceId")):
            return CloudProvider.AZURE
        if record.get("event_type", "").startswith("azure_") or "azure" in record.get("target", "").lower():
            return CloudProvider.AZURE

        # Fallback check inside details or raw_payload
        raw = str(record.get("raw_payload", "")).lower()
        if "cloudtrail" in raw or "aws" in raw:
            return CloudProvider.AWS
        if "stackdriver" in raw or "gcp" in raw or "cloud.google.com" in raw:
            return CloudProvider.GCP
        if "azure" in raw or "microsoft.security" in raw:
            return CloudProvider.AZURE

        return CloudProvider.UNKNOWN

    def evaluate_record(
        self,
        record: dict[str, Any],
        provider: CloudProvider | None = None,
    ) -> list[FindingContract]:
        """Evaluates an individual cloud audit log or configuration record."""
        target_provider = provider or self.detect_provider(record)
        findings: list[FindingContract] = []

        if target_provider == CloudProvider.AWS:
            findings.extend(self._evaluate_aws(record))
        elif target_provider == CloudProvider.GCP:
            findings.extend(self._evaluate_gcp(record))
        elif target_provider == CloudProvider.AZURE:
            findings.extend(self._evaluate_azure(record))
        else:
            # Fallback: check all providers
            findings.extend(self._evaluate_aws(record))
            findings.extend(self._evaluate_gcp(record))
            findings.extend(self._evaluate_azure(record))

        return findings

    def evaluate_batch(
        self,
        records: list[dict[str, Any]],
        provider: CloudProvider | None = None,
    ) -> CloudPostureReport:
        """Evaluates a batch of cloud records and generates a posture summary."""
        report = CloudPostureReport(total_records_analyzed=len(records))

        for rec in records:
            findings = self.evaluate_record(rec, provider=provider)
            for f in findings:
                report.findings.append(f)
                report.total_findings += 1
                if f.severity == SeverityLevel.CRITICAL:
                    report.critical_count += 1
                elif f.severity == SeverityLevel.HIGH:
                    report.high_count += 1
                elif f.severity == SeverityLevel.MEDIUM:
                    report.medium_count += 1
                elif f.severity == SeverityLevel.LOW:
                    report.low_count += 1

                # Group by provider
                prov_key = f.rule_id.split("-")[2].lower() if len(f.rule_id.split("-")) > 2 else "cloud"
                report.findings_by_provider[prov_key] = report.findings_by_provider.get(prov_key, 0) + 1

        report.calculate_score()
        return report

    # --------------------------------------------------------------------------
    # Provider-Specific Evaluation Logic
    # --------------------------------------------------------------------------

    def _evaluate_aws(self, record: dict[str, Any]) -> list[FindingContract]:
        findings: list[FindingContract] = []
        event_name = record.get("eventName", "") or record.get("event_type", "")
        event_source = record.get("eventSource", "")
        params = record.get("requestParameters") or record.get("details", {}) or {}
        raw = str(record.get("raw_payload", ""))

        # 1. S3 Bucket Public Access
        if (
            event_name in ("PutBucketAcl", "PutBucketPolicy", "aws_s3_public_access")
            or "s3:PutBucketPolicy" in raw
            or "s3_public" in raw.lower()
        ):
            is_public = False
            bucket_name = params.get("bucketName") or record.get("target_host") or "unknown-bucket"

            # Check ACL
            acl = params.get("AccessControlPolicy", {}) or params.get("acl", {})
            grants = str(acl)
            if "AllUsers" in grants or "AuthenticatedUsers" in grants or "allusers" in raw.lower():
                is_public = True

            # Check Policy
            policy_doc = params.get("bucketPolicy", "") or str(params.get("policy", "")) or raw
            if '"Principal": "*"' in policy_doc or '"Principal":"*"' in policy_doc:
                if '"Effect": "Allow"' in policy_doc or '"Effect":"Allow"' in policy_doc:
                    is_public = True

            if is_public or "s3_public_bucket" in raw.lower():
                rule = self.rules["RULE-CLOUD-AWS-S3-PUBLIC"]
                findings.append(self._create_finding(rule, target=f"aws:s3:::{bucket_name}", evidence=params or raw))

        # 2. Root Account Console Login Without MFA
        user_identity = record.get("userIdentity", {}) or params.get("userIdentity", {})
        additional_data = record.get("additionalEventData", {}) or params.get("additionalEventData", {})
        if (
            (event_name == "ConsoleLogin" and user_identity.get("type") == "Root")
            or ("root_login_no_mfa" in raw.lower())
        ):
            mfa_used = additional_data.get("MFAUsed")
            if mfa_used != "Yes" or "no_mfa" in raw.lower():
                rule = self.rules["RULE-CLOUD-AWS-ROOT-NO-MFA"]
                findings.append(
                    self._create_finding(
                        rule,
                        target=f"aws:iam::root:{record.get('recipientAccountId', 'default')}",
                        evidence={"MFAUsed": mfa_used, "event": event_name},
                    )
                )

        # 3. IAM Admin Wildcard Privilege Escalation
        if (
            event_name in ("CreatePolicyVersion", "PutUserPolicy", "PutRolePolicy", "aws_iam_admin_wildcard")
            or "iam_admin_wildcard" in raw.lower()
        ):
            policy_doc = str(params.get("policyDocument", "")) or raw
            if ('"Action": "*"' in policy_doc or '"Action":"*"') and (
                '"Resource": "*"' in policy_doc or '"Resource":"*"' in policy_doc
            ) or "iam_wildcard" in raw.lower():
                rule = self.rules["RULE-CLOUD-AWS-IAM-ADMIN-WILDCARD"]
                target_role = params.get("roleName") or params.get("policyName") or record.get("target_host") or "iam-policy"
                findings.append(self._create_finding(rule, target=f"aws:iam::policy/{target_role}", evidence=policy_doc))

        # 4. Security Group Open Ingress (0.0.0.0/0 on sensitive ports)
        if (
            event_name in ("AuthorizeSecurityGroupIngress", "aws_sg_ingress_open")
            or "sg_ingress_open" in raw.lower()
        ):
            ip_perms = params.get("ipPermissions", {}) or params.get("ip_permissions", [])
            perms_str = str(ip_perms) + " " + raw
            if "0.0.0.0/0" in perms_str:
                for port in [22, 3389, 5432]:
                    if str(port) in perms_str or f"port_{port}" in perms_str.lower():
                        rule = self.rules["RULE-CLOUD-AWS-SG-INGRESS-OPEN"]
                        sg_id = params.get("groupId") or record.get("target_host") or "sg-default"
                        findings.append(
                            self._create_finding(
                                rule,
                                target=f"aws:ec2:security-group/{sg_id}",
                                evidence=f"Ingress 0.0.0.0/0 permitted on port {port}",
                            )
                        )
                        break

        # 5. CloudTrail Logging Disabled
        if (
            (event_source == "cloudtrail.amazonaws.com" and event_name in ("StopLogging", "DeleteTrail"))
            or "cloudtrail_disabled" in raw.lower()
        ):
            rule = self.rules["RULE-CLOUD-AWS-CLOUDTRAIL-DISABLED"]
            trail_name = params.get("name") or record.get("target_host") or "management-events"
            findings.append(
                self._create_finding(
                    rule,
                    target=f"aws:cloudtrail:{trail_name}",
                    evidence={"eventName": event_name, "details": params},
                )
            )

        return findings

    def _evaluate_gcp(self, record: dict[str, Any]) -> list[FindingContract]:
        findings: list[FindingContract] = []
        proto = record.get("protoPayload", {}) or {}
        method_name = proto.get("methodName", "") or record.get("event_type", "")
        req = proto.get("request", {}) or record.get("details", {}) or {}
        raw = str(record.get("raw_payload", ""))

        # 1. Cloud Storage Public Bucket Exposure
        if (
            "storage.setIamPermissions" in method_name
            or method_name == "gcp_storage_public"
            or "gcs_public" in raw.lower()
        ):
            policy = req.get("policy", {}) or req
            bindings = policy.get("bindings", [])
            bindings_str = str(bindings) + " " + raw
            if "allUsers" in bindings_str or "allAuthenticatedUsers" in bindings_str:
                rule = self.rules["RULE-CLOUD-GCP-STORAGE-PUBLIC"]
                bucket = req.get("resource") or record.get("target_host") or "gcs-bucket"
                findings.append(
                    self._create_finding(
                        rule,
                        target=f"gcp:storage://{bucket}",
                        evidence={"bindings": bindings_str},
                    )
                )

        # 2. Service Account Overprivileged
        if (
            "SetIamPolicy" in method_name
            or "gcp_iam_overprivileged" in method_name
            or "gcp_iam" in raw.lower()
        ):
            policy = req.get("policy", {}) or req
            policy_str = str(policy) + " " + raw
            if ("roles/owner" in policy_str or "roles/editor" in policy_str) and (
                "gserviceaccount.com" in policy_str or "serviceAccount:" in policy_str
            ):
                rule = self.rules["RULE-CLOUD-GCP-IAM-OVERPRIVILEGED"]
                res = req.get("resource") or record.get("target_host") or "projects/default"
                findings.append(
                    self._create_finding(
                        rule,
                        target=f"gcp:iam:{res}",
                        evidence=policy_str,
                    )
                )

        # 3. VPC Firewall Open Ingress
        if (
            "compute.firewalls.insert" in method_name
            or "compute.firewalls.patch" in method_name
            or method_name == "gcp_firewall_open"
            or "gcp_firewall" in raw.lower()
        ):
            source_ranges = req.get("sourceRanges", [])
            ranges_str = str(source_ranges) + " " + raw
            if "0.0.0.0/0" in ranges_str and ("22" in ranges_str or "3389" in ranges_str):
                rule = self.rules["RULE-CLOUD-GCP-FIREWALL-OPEN"]
                fw_name = req.get("name") or record.get("target_host") or "default-allow-all"
                findings.append(
                    self._create_finding(
                        rule,
                        target=f"gcp:compute:firewall/{fw_name}",
                        evidence=ranges_str,
                    )
                )

        # 4. Audit Logging Disabled
        if (
            ("SetIamPolicy" in method_name and "auditConfigs" in str(req))
            or "gcp_audit_disabled" in raw.lower()
        ):
            rule = self.rules["RULE-CLOUD-GCP-AUDIT-DISABLED"]
            res = req.get("resource") or record.get("target_host") or "projects/default"
            findings.append(
                self._create_finding(
                    rule,
                    target=f"gcp:logging:{res}",
                    evidence="AuditConfig cleared or disabled",
                )
            )

        return findings

    def _evaluate_azure(self, record: dict[str, Any]) -> list[FindingContract]:
        findings: list[FindingContract] = []
        op_name = record.get("operationName", {}) or record.get("event_type", "")
        op_str = op_name.get("value", "") if isinstance(op_name, dict) else str(op_name)
        props = record.get("properties", {}) or record.get("details", {}) or {}
        raw = str(record.get("raw_payload", ""))

        # 1. Storage Account Public Blob Access Enabled
        if (
            "Microsoft.Storage/storageAccounts/write" in op_str
            or "azure_storage_public" in op_str
            or "azure_storage_public" in raw.lower()
        ):
            allow_public = props.get("allowBlobPublicAccess")
            if allow_public is True or "allowBlobPublicAccess: true" in raw or "blob_public" in raw.lower():
                rule = self.rules["RULE-CLOUD-AZURE-STORAGE-PUBLIC"]
                res_id = record.get("resourceId") or record.get("target_host") or "storage-account-01"
                findings.append(
                    self._create_finding(
                        rule,
                        target=f"azure:storage:{res_id}",
                        evidence={"allowBlobPublicAccess": True},
                    )
                )

        # 2. NSG Open Ingress
        if (
            "Microsoft.Network/networkSecurityGroups/securityRules/write" in op_str
            or "azure_nsg_open" in op_str
            or "nsg_open" in raw.lower()
        ):
            rule_props = props.get("securityRuleProperties", {}) or props
            src = str(rule_props.get("sourceAddressPrefix", "")) or raw
            dst_port = str(rule_props.get("destinationPortRange", "")) or raw
            access = rule_props.get("access", "Allow")

            if (src in ("*", "0.0.0.0/0", "Internet") or "0.0.0.0/0" in raw) and access == "Allow":
                if any(p in dst_port or f"port_{p}" in raw.lower() for p in ["22", "3389", "*"]):
                    rule = self.rules["RULE-CLOUD-AZURE-NSG-OPEN"]
                    nsg_id = record.get("resourceId") or record.get("target_host") or "nsg-perimeter"
                    findings.append(
                        self._create_finding(
                            rule,
                            target=f"azure:network:nsg/{nsg_id}",
                            evidence=f"Inbound rule allows {src} on port range {dst_port}",
                        )
                    )

        # 3. Standing Owner Role Assignment at Subscription Scope
        if (
            "Microsoft.Authorization/roleAssignments/write" in op_str
            or "azure_owner_assignment" in op_str
            or "azure_owner_standing" in raw.lower()
        ):
            role_def = props.get("roleDefinitionId", "") or raw
            scope = props.get("scope", "") or raw
            # Owner role GUID in Azure is 8e3af657-a8ff-443c-a75c-2fe8c4bcb635
            if ("8e3af657" in str(role_def) or "Owner" in str(role_def) or "owner" in raw.lower()) and (
                "/subscriptions/" in str(scope) or "subscription" in raw.lower()
            ):
                rule = self.rules["RULE-CLOUD-AZURE-OWNER-SUBSCRIPTION"]
                target = record.get("resourceId") or record.get("target_host") or "subscription-rbac"
                findings.append(
                    self._create_finding(
                        rule,
                        target=f"azure:authorization:{target}",
                        evidence={"role": "Owner", "scope": str(scope)},
                    )
                )

        return findings

    def _create_finding(
        self,
        rule: CloudBenchmarkRule,
        target: str,
        evidence: Any,
    ) -> FindingContract:
        """Helper to construct an immutable FindingContract instance."""
        evidence_payload: dict[str, Any] = {
            "benchmark_control": rule.benchmark_control,
            "cwe_id": rule.cwe_id,
            "remediation": rule.remediation,
            "provider": rule.provider.value,
            "details": evidence if isinstance(evidence, dict) else {"raw": str(evidence)},
        }

        return FindingContract(
            finding_id=uuid4(),
            tool_name="cloud_security_cspm",
            rule_id=rule.rule_id,
            severity=rule.severity,
            target=target,
            description=f"[{rule.benchmark_control}] {rule.name}: {rule.description}",
            evidence=evidence_payload,
            timestamp=datetime.now(UTC),
            mitre_attack_id=rule.mitre_attack_id,
        )
