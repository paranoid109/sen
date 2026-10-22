"""Unit Tests for Module X11: Digital Forensics Triage Capability Module."""

from __future__ import annotations

import uuid

from contracts.python.models import FindingContract, SeverityLevel
from modules.forensics.collector import (
    DigitalForensicsCollector,
    ForensicTriagePackage,
    ProcessInfo,
    SocketInfo,
)
from modules.forensics.standalone import run_self_test


def test_forensics_volatile_memory_capture() -> None:
    """Asserts volatile memory capture correctly identifies suspicious processes and ports."""
    collector = DigitalForensicsCollector(target_host="test-host-01")

    mock_procs = [
        ProcessInfo(pid=100, ppid=1, name="python3", cmdline="python3 server.py", user="app", memory_rss_bytes=1000),
        ProcessInfo(pid=200, ppid=100, name="bash", cmdline="/bin/bash -i", user="app", memory_rss_bytes=2000),
    ]
    mock_socks = [
        SocketInfo(protocol="TCP", local_ip="192.168.1.10", local_port=80, remote_ip="0.0.0.0", remote_port=0, state="LISTEN", pid=100),
        SocketInfo(protocol="TCP", local_ip="192.168.1.10", local_port=50000, remote_ip="203.0.113.1", remote_port=4444, state="ESTABLISHED", pid=200),
    ]

    mem = collector.collect_volatile_memory(mock_processes=mock_procs, mock_sockets=mock_socks)

    assert mem["total_processes"] == 2
    assert mem["suspicious_processes"] == 1
    assert mem["suspicious_sockets"] == 1
    suspicious_p = [p for p in mem["process_tree"] if p["is_suspicious"]]
    assert len(suspicious_p) == 1
    assert suspicious_p[0]["pid"] == 200


def test_forensics_disk_artifacts_and_fim() -> None:
    """Asserts FIM calculates valid SHA-256 hashes and auth log extracts entries."""
    collector = DigitalForensicsCollector(target_host="test-host-01")
    disk = collector.collect_disk_artifacts()

    assert "fim_checksums" in disk
    assert len(disk["fim_checksums"]) >= 4
    for item in disk["fim_checksums"]:
        assert len(item["sha256"]) == 64
        assert item["size_bytes"] > 0
    assert len(disk["auth_log_tail"]) > 0
    assert len(disk["shell_history"]) > 0


def test_forensics_package_manifest_and_chain_of_custody() -> None:
    """Asserts triage package contains full manifest and VERIFIED chain of custody status."""
    collector = DigitalForensicsCollector(target_host="srv-finance-01")
    inc_id = str(uuid.uuid4())

    package = collector.create_triage_package(incident_id=inc_id)

    assert isinstance(package, ForensicTriagePackage)
    assert package.incident_id == inc_id
    assert package.target_host == "srv-finance-01"
    assert package.chain_of_custody_status == "VERIFIED"
    assert len(package.manifest) >= 6

    # Verify manifest items have SHA-256 and timestamps
    for item in package.manifest:
        assert len(item.sha256) == 64
        assert item.size_bytes >= 0
        assert item.timestamp is not None


def test_forensics_root_sha256_tamper_evidence() -> None:
    """Asserts root SHA-256 is deterministic and changes if any underlying artifact is modified."""
    collector = DigitalForensicsCollector(target_host="srv-prod-01")
    inc_id = str(uuid.uuid4())

    custom_files_orig = {
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
        "/etc/shadow": "root:hash:19000:0:99999:7:::\n",
    }
    custom_files_tampered = {
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nhacker:x:0:0::/root:/bin/bash\n",  # backdoor account added
        "/etc/shadow": "root:hash:19000:0:99999:7:::\n",
    }

    pkg_orig = collector.create_triage_package(incident_id=inc_id, custom_files=custom_files_orig)
    pkg_tampered = collector.create_triage_package(incident_id=inc_id, custom_files=custom_files_tampered)

    assert len(pkg_orig.root_sha256) == 64
    assert len(pkg_tampered.root_sha256) == 64
    # Root SHA-256 must detect modification
    assert pkg_orig.root_sha256 != pkg_tampered.root_sha256


def test_forensics_finding_contract_emission() -> None:
    """Asserts collector emits standard FindingContract conforming to Law 2."""
    collector = DigitalForensicsCollector(target_host="srv-db-01")
    package = collector.create_triage_package(incident_id=str(uuid.uuid4()))
    finding = collector.generate_finding(package)

    assert isinstance(finding, FindingContract)
    assert finding.rule_id == "RULE-FORENSICS-TRIAGE-001"
    assert finding.mitre_attack_id == "T1059.004"
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.target == "srv-db-01"
    assert finding.evidence is not None
    assert "root_sha256" in finding.evidence


def test_forensics_scope_filtering() -> None:
    """Asserts scope parameter limits collection to memory, disk, or all."""
    collector = DigitalForensicsCollector(target_host="srv-web-01")
    inc_id = str(uuid.uuid4())

    pkg_mem = collector.create_triage_package(incident_id=inc_id, scope="memory")
    assert pkg_mem.volatile_memory != {}
    assert pkg_mem.disk_artifacts == {}
    assert any(m.artifact_type == "memory_snapshot" for m in pkg_mem.manifest)
    assert not any(m.artifact_type == "disk_snapshot" for m in pkg_mem.manifest)

    pkg_disk = collector.create_triage_package(incident_id=inc_id, scope="disk")
    assert pkg_disk.volatile_memory == {}
    assert pkg_disk.disk_artifacts != {}
    assert not any(m.artifact_type == "memory_snapshot" for m in pkg_disk.manifest)
    assert any(m.artifact_type == "disk_snapshot" for m in pkg_disk.manifest)


def test_forensics_verify_package_integrity() -> None:
    """Asserts verify_package_integrity passes on valid packages and detects tampering."""
    collector = DigitalForensicsCollector(target_host="srv-db-01")
    pkg = collector.create_triage_package(incident_id=str(uuid.uuid4()))

    valid, msg = collector.verify_package_integrity(pkg)
    assert valid is True
    assert "verified" in msg.lower()

    # Tamper with process tree inside memory snapshot
    pkg.volatile_memory["process_tree"].append({"pid": 9999, "name": "rootkit"})
    tampered_valid, tampered_msg = collector.verify_package_integrity(pkg)
    assert tampered_valid is False
    assert "mismatch" in tampered_msg.lower()


def test_forensics_standalone_self_test() -> None:
    """Asserts standalone runner self-test passes cleanly."""
    assert run_self_test() is True
