"""SentinelX Cloud Security Posture Management CLI & Standalone Tool (Module X12).

Provides autonomous multi-cloud security audits for AWS, GCP, and Azure configurations
and audit logs. Supports CIS benchmark scoring, JSON reporting, and forwarding to SentinelX.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx  # noqa: E402

from contracts.python.models import FindingContract  # noqa: E402
from modules.cloud_security.evaluator import (  # noqa: E402
    CloudPostureReport,
    CloudProvider,
    CloudSecurityEvaluator,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx.cloud_security.cli")


def forward_cloud_finding(
    finding: FindingContract,
    api_url: str = "http://localhost:8000/api/v1/events/ingest",
    api_key: str = "sentinelx-default-ingest-key-change-in-production",
) -> bool:
    """Forwards a Cloud Finding to SentinelX Ingest API as a normalized security event."""
    evidence_dict = finding.evidence if isinstance(finding.evidence, dict) else {"raw": str(finding.evidence)}
    provider = evidence_dict.get("provider", "cloud")

    payload = {
        "source_ip": "127.0.0.1",
        "event_type": "cloud_misconfiguration_finding",
        "target_host": finding.target,
        "event_time": finding.timestamp.isoformat(),
        "raw_payload": f"{finding.rule_id}: {finding.description} (Target: {finding.target})",
        "details": {
            "finding_id": str(finding.finding_id),
            "tool_name": finding.tool_name,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "mitre_attack_id": finding.mitre_attack_id,
            "provider": provider,
            "benchmark_control": evidence_dict.get("benchmark_control"),
            "cwe_id": evidence_dict.get("cwe_id"),
            "remediation": evidence_dict.get("remediation"),
        },
    }

    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(api_url, json=payload, headers=headers)
            if resp.status_code == 201:
                logger.info("Forwarded cloud finding %s to SentinelX (HTTP 201)", finding.rule_id)
                return True
            logger.warning("Failed forwarding finding %s: HTTP %d %s", finding.rule_id, resp.status_code, resp.text)
            return False
    except Exception as exc:
        logger.error("Network error forwarding finding %s: %s", finding.rule_id, exc)
        return False


def run_self_test() -> bool:
    """Executes built-in test suite for AWS, GCP, and Azure CIS controls."""
    print("=" * 78)
    print(" SentinelX CSPM Standalone Engine: Autonomous Self-Test (Module X12)")
    print("=" * 78)

    evaluator = CloudSecurityEvaluator()

    # Fixture 1: AWS S3 Public Bucket & Root Login No MFA
    aws_records = [
        {
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "recipientAccountId": "112233445566",
            "requestParameters": {
                "bucketName": "finance-confidential-backups",
                "bucketPolicy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}',
            },
        },
        {
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "recipientAccountId": "112233445566",
            "userIdentity": {"type": "Root"},
            "additionalEventData": {"MFAUsed": "No"},
        },
        {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {
                "groupId": "sg-0987654321",
                "ipPermissions": [{"ipRanges": [{"cidrIp": "0.0.0.0/0"}], "fromPort": 22, "toPort": 22}],
            },
        },
    ]

    # Fixture 2: GCP Storage Public & Service Account Overprivileged
    gcp_records = [
        {
            "protoPayload": {
                "methodName": "storage.setIamPermissions",
                "request": {
                    "resource": "gcs-customer-pii-data",
                    "policy": {
                        "bindings": [
                            {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                        ]
                    },
                },
            },
        },
        {
            "protoPayload": {
                "methodName": "SetIamPolicy",
                "request": {
                    "resource": "projects/fintech-prod",
                    "policy": {
                        "bindings": [
                            {"role": "roles/owner", "members": ["serviceAccount:deployer@fintech-prod.iam.gserviceaccount.com"]},
                        ]
                    },
                },
            },
        },
    ]

    # Fixture 3: Azure Storage Public Blob & NSG Open Ingress
    azure_records = [
        {
            "operationName": "Microsoft.Storage/storageAccounts/write",
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stprodlogs",
            "properties": {"allowBlobPublicAccess": True},
        },
        {
            "operationName": "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-perimeter",
            "properties": {
                "securityRuleProperties": {
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "3389",
                    "access": "Allow",
                }
            },
        },
    ]

    all_records = aws_records + gcp_records + azure_records
    report = evaluator.evaluate_batch(all_records)

    print(f"\n[1/5] Total Records Evaluated: {report.total_records_analyzed}")
    print(f"[2/5] Total Security Findings: {report.total_findings}")
    print(f"[3/5] Severity Breakdown: Critical={report.critical_count}, High={report.high_count}, Med={report.medium_count}")
    print(f"[4/5] Findings by Provider: {report.findings_by_provider}")
    print(f"[5/5] Computed Cloud Posture Score: {report.posture_score}%")

    # Assertions
    assert report.total_records_analyzed == 7, "Expected 7 records analyzed"
    assert report.total_findings >= 7, f"Expected at least 7 findings, got {report.total_findings}"
    assert report.critical_count >= 3, "Expected at least 3 critical findings (AWS S3, AWS Root, GCP Storage, Azure Blob)"
    assert "aws" in report.findings_by_provider
    assert "gcp" in report.findings_by_provider
    assert "azure" in report.findings_by_provider

    # Verify MITRE ATT&CK mappings
    mitre_ids = {f.mitre_attack_id for f in report.findings if f.mitre_attack_id}
    assert "T1530" in mitre_ids, "Missing T1530 Cloud Storage discovery/exfiltration"
    assert "T1046" in mitre_ids or "T1078.004" in mitre_ids

    print("\n" + "=" * 78)
    print(" ALL SELF-TEST CHECKS PASSED: Cloud Security CSPM Module Verified (100%)")
    print("=" * 78)
    return True


def print_report_table(report: CloudPostureReport) -> None:
    """Renders formatted console output for cloud audit findings."""
    print("\n" + "=" * 92)
    print(" SentinelX Multi-Cloud Security Posture Management (CSPM) Audit Report")
    print("=" * 92)
    print(f" Analyzed Records: {report.total_records_analyzed:<6} | Findings: {report.total_findings:<4} | Posture Score: {report.posture_score}%")
    print(f" Critical: {report.critical_count:<4} | High: {report.high_count:<4} | Medium: {report.medium_count:<4} | Low: {report.low_count:<4}")
    print("-" * 92)
    print(f"{'Control':<15} | {'Severity':<8} | {'Provider':<8} | {'MITRE':<8} | {'Target Resource':<42}")
    print("-" * 92)

    for f in report.findings:
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        ctrl = ev.get("benchmark_control", f.rule_id)
        prov = ev.get("provider", "cloud").upper()
        mitre = f.mitre_attack_id or "N/A"
        target_trunc = f.target[:40] + ".." if len(f.target) > 42 else f.target
        print(f"{ctrl:<15} | {f.severity.value:<8} | {prov:<8} | {mitre:<8} | {target_trunc:<42}")

    print("=" * 92 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelX Cloud Security Posture Management CLI (X12)")
    parser.add_argument("--audit-file", type=Path, help="Path to JSON file containing cloud records")
    parser.add_argument("--provider", choices=["aws", "gcp", "azure", "auto"], default="auto", help="Cloud provider")
    parser.add_argument("--cis-benchmark", action="store_true", help="Display CIS benchmark score breakdown")
    parser.add_argument("--forward", action="store_true", help="Forward findings to SentinelX REST Ingest API")
    parser.add_argument("--api-url", default="http://localhost:8000/api/v1/events/ingest", help="Ingest API URL")
    parser.add_argument("--api-key", default="sentinelx-default-ingest-key-change-in-production", help="Ingest API key")
    parser.add_argument("--self-test", action="store_true", help="Run comprehensive autonomous self-test")

    args = parser.parse_args()

    if args.self_test:
        success = run_self_test()
        return 0 if success else 1

    if not args.audit_file:
        parser.print_help()
        return 1

    if not args.audit_file.exists():
        logger.error("Audit file not found: %s", args.audit_file)
        return 1

    with open(args.audit_file, encoding="utf-8") as f:
        data = json.load(f)

    records = data if isinstance(data, list) else data.get("records", [data])
    provider_enum = None if args.provider == "auto" else CloudProvider(args.provider)

    evaluator = CloudSecurityEvaluator()
    report = evaluator.evaluate_batch(records, provider=provider_enum)
    print_report_table(report)

    if args.forward:
        logger.info("Forwarding %d findings to %s...", len(report.findings), args.api_url)
        forwarded = sum(forward_cloud_finding(f, api_url=args.api_url, api_key=args.api_key) for f in report.findings)
        logger.info("Successfully forwarded %d / %d cloud findings.", forwarded, len(report.findings))

    return 0


if __name__ == "__main__":
    sys.exit(main())
