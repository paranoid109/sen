"""Unit tests for SentinelX Cloud Security Posture Management (CSPM, Module X12)."""

from __future__ import annotations

from contracts.python.models import FindingContract, SeverityLevel
from modules.cloud_security.evaluator import (
    CloudProvider,
    CloudSecurityEvaluator,
)
from modules.cloud_security.standalone import run_self_test


def test_detect_cloud_providers():
    evaluator = CloudSecurityEvaluator()

    aws_rec = {"eventSource": "s3.amazonaws.com", "eventName": "PutBucketPolicy"}
    assert evaluator.detect_provider(aws_rec) == CloudProvider.AWS

    gcp_rec = {"protoPayload": {"methodName": "storage.setIamPermissions"}}
    assert evaluator.detect_provider(gcp_rec) == CloudProvider.GCP

    azure_rec = {"operationName": "Microsoft.Storage/storageAccounts/write", "resourceId": "/subscriptions/sub-1"}
    assert evaluator.detect_provider(azure_rec) == CloudProvider.AZURE


def test_aws_s3_public_bucket_finding():
    evaluator = CloudSecurityEvaluator()
    record = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketPolicy",
        "requestParameters": {
            "bucketName": "customer-pii-vault",
            "bucketPolicy": '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}',
        },
    }

    findings = evaluator.evaluate_record(record, provider=CloudProvider.AWS)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, FindingContract)
    assert f.rule_id == "RULE-CLOUD-AWS-S3-PUBLIC"
    assert f.severity == SeverityLevel.CRITICAL
    assert f.mitre_attack_id == "T1530"
    assert "customer-pii-vault" in f.target


def test_aws_root_login_without_mfa():
    evaluator = CloudSecurityEvaluator()
    record = {
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "recipientAccountId": "998877665544",
        "userIdentity": {"type": "Root"},
        "additionalEventData": {"MFAUsed": "No"},
    }

    findings = evaluator.evaluate_record(record, provider=CloudProvider.AWS)
    assert len(findings) == 1
    assert findings[0].rule_id == "RULE-CLOUD-AWS-ROOT-NO-MFA"
    assert findings[0].severity == SeverityLevel.CRITICAL
    assert findings[0].mitre_attack_id == "T1078.004"


def test_aws_security_group_open_ingress():
    evaluator = CloudSecurityEvaluator()
    record = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "requestParameters": {
            "groupId": "sg-public-ssh",
            "ipPermissions": [{"ipRanges": [{"cidrIp": "0.0.0.0/0"}], "fromPort": 22, "toPort": 22}],
        },
    }

    findings = evaluator.evaluate_record(record, provider=CloudProvider.AWS)
    assert len(findings) == 1
    assert findings[0].rule_id == "RULE-CLOUD-AWS-SG-INGRESS-OPEN"
    assert findings[0].mitre_attack_id == "T1046"


def test_gcp_public_storage_bucket():
    evaluator = CloudSecurityEvaluator()
    record = {
        "protoPayload": {
            "methodName": "storage.setIamPermissions",
            "request": {
                "resource": "gcs-financial-exports",
                "policy": {
                    "bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
                },
            },
        },
    }

    findings = evaluator.evaluate_record(record, provider=CloudProvider.GCP)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE-CLOUD-GCP-STORAGE-PUBLIC"
    assert f.severity == SeverityLevel.CRITICAL
    assert f.mitre_attack_id == "T1530"


def test_azure_storage_public_access():
    evaluator = CloudSecurityEvaluator()
    record = {
        "operationName": "Microsoft.Storage/storageAccounts/write",
        "resourceId": "/subscriptions/sub-01/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/stanalytics",
        "properties": {"allowBlobPublicAccess": True},
    }

    findings = evaluator.evaluate_record(record, provider=CloudProvider.AZURE)
    assert len(findings) == 1
    assert findings[0].rule_id == "RULE-CLOUD-AZURE-STORAGE-PUBLIC"
    assert findings[0].severity == SeverityLevel.CRITICAL


def test_batch_evaluation_and_posture_score():
    evaluator = CloudSecurityEvaluator()
    records = [
        # 1 Critical AWS S3
        {
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "requestParameters": {
                "bucketName": "leaked-data",
                "bucketPolicy": '{"Statement": [{"Effect": "Allow", "Principal": "*"}]}',
            },
        },
        # 1 High GCP Firewall
        {
            "protoPayload": {
                "methodName": "compute.firewalls.insert",
                "request": {"sourceRanges": ["0.0.0.0/0", "22"], "name": "allow-ssh-all"},
            },
        },
    ]

    report = evaluator.evaluate_batch(records)
    assert report.total_records_analyzed == 2
    assert report.total_findings == 2
    assert report.critical_count == 1
    assert report.high_count == 1
    # 100 - (20 + 10) = 70.0
    assert report.posture_score == 70.0


def test_cloud_security_self_test():
    assert run_self_test() is True
