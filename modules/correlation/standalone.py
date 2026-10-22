"""Standalone CLI Runner for Advanced Correlation Engine Capability Module (X7).

Supports offline alert stream correlation, multi-stage attack reconstruction,
self-testing, and forwarding incidents to SentinelX (Law 1 & Law 2).
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from modules.correlation.analyzer import AdvancedCorrelationEngine


def run_self_test() -> int:
    """Executes built-in test suite asserting detection and multi-stage kill-chain correlation."""
    print("[*] Running AdvancedCorrelationEngine (Module X7) self-test suite...")
    failures = 0

    engine = AdvancedCorrelationEngine(time_window_hours=4)
    target_host = "srv-prod-app-01"
    base_time = datetime.now(UTC)

    # 1. Feed Stage 1 Alert: Port Scan (Reconnaissance, T1046)
    alert_recon = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-NET-001",
        "rule_name": "TCP SYN Port Scan",
        "mitre_attack_id": "T1046",
        "severity": "medium",
        "source_ip": "198.51.100.99",
        "target_host": target_host,
        "first_seen": (base_time - timedelta(minutes=30)).isoformat(),
    }
    inc_1 = engine.process_alert(alert_recon)
    if inc_1 is not None:
        print("[-] Premature incident generated on single stage (Reconnaissance).")
        failures += 1
    else:
        print("  [PASS] Single-stage alert staged in campaign DAG (no false incident).")

    # 2. Feed Stage 2 Alert: SQL Injection (Initial Access, T1190)
    alert_access = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-WEB-001",
        "rule_name": "SQL Injection Exploit",
        "mitre_attack_id": "T1190",
        "severity": "high",
        "source_ip": "198.51.100.42",
        "target_host": target_host,
        "first_seen": (base_time - timedelta(minutes=15)).isoformat(),
    }
    inc_2 = engine.process_alert(alert_access)
    if inc_2 is None or "Reconnaissance -> Initial Access" not in inc_2.title:
        print(f"[-] Failed to correlate Recon -> Initial Access campaign: {inc_2}")
        failures += 1
    else:
        print(f"  [PASS] Correlated 2-stage campaign: '{inc_2.title}' (Risk: {inc_2.risk_score}/100)")

    # 3. Feed Stage 3 Alert: LOLBAS Process (Execution, T1059.001)
    alert_exec = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-EDR-002",
        "rule_name": "LOLBAS Execution",
        "mitre_attack_id": "T1059.001",
        "severity": "high",
        "source_ip": "10.0.1.10",
        "target_host": target_host,
        "first_seen": (base_time - timedelta(minutes=5)).isoformat(),
    }
    inc_3 = engine.process_alert(alert_exec)
    if inc_3 is None or "Initial Access -> Execution" not in inc_3.title:
        print("[-] Failed to escalate to 3-stage campaign.")
        failures += 1
    else:
        print(f"  [PASS] Escalated to 3-stage campaign: '{inc_3.title}' (Risk: {inc_3.risk_score}/100)")

    # 4. Feed Stage 4 Alert: DNS Tunneling (Command & Control, T1071.004)
    alert_c2 = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-NET-002",
        "rule_name": "High-Entropy DNS Tunneling",
        "mitre_attack_id": "T1071.004",
        "severity": "critical",
        "source_ip": "10.0.1.10",
        "target_host": target_host,
        "first_seen": base_time.isoformat(),
    }
    inc_4 = engine.process_alert(alert_c2)
    if inc_4 is None or inc_4.severity != "critical" or len(inc_4.alert_ids) != 4:
        print("[-] Failed full kill-chain reconstruction.")
        failures += 1
    else:
        print(f"  [PASS] Full 4-Stage Kill-Chain Incident Verified: '{inc_4.title}' (Risk: {inc_4.risk_score}/100, Alerts: {len(inc_4.alert_ids)})")

    if failures == 0:
        print("[+] Module X7 (Advanced Correlation Engine) Self-Test PASSED (4/4 checks clean).\n")
        return 0
    else:
        print(f"[-] Module X7 Self-Test FAILED ({failures} errors).\n")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelX Advanced Correlation Engine Capability Module (X7)")
    parser.add_argument("--self-test", action="store_true", help="Execute built-in validation test suite")
    parser.add_argument("--file", type=str, help="Path to JSON file containing alerts array")
    parser.add_argument("--window-hours", type=int, default=4, help="Sliding temporal correlation window in hours")

    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if not args.file:
        parser.print_help()
        return 1

    path = Path(args.file)
    if not path.is_file():
        print(f"[-] File not found: {path}", file=sys.stderr)
        return 1

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"[-] Failed to parse JSON file {path}: {exc}", file=sys.stderr)
        return 1

    alerts = data if isinstance(data, list) else data.get("alerts", [data])
    engine = AdvancedCorrelationEngine(time_window_hours=args.window_hours)

    incidents = []
    for a in alerts:
        inc = engine.process_alert(a)
        if inc:
            incidents.append(inc)

    print(f"[*] Processed {len(alerts)} alerts; synthesized {len(incidents)} multi-stage incident(s).")
    for inc in incidents:
        print(json.dumps(inc.model_dump(mode="json"), indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
