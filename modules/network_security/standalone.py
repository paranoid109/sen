"""Standalone CLI Runner for Network Security Capability Module (X2).

Supports offline Zeek/NetFlow log analysis, PCAP packet analysis, self-testing,
and forward-streaming findings to the SentinelX Ingest API (Law 1 & Law 2).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from modules.network_security.analyzer import NetworkSecurityAnalyzer


def run_self_test() -> int:
    """Executes built-in test suite asserting detection on DNS tunneling, port sweeps, and C2."""
    analyzer = NetworkSecurityAnalyzer()
    print("[*] Running NetworkSecurityAnalyzer self-test suite...")

    failures = 0

    # 1. DNS Tunneling Test
    legit_dns = "www.google.com"
    exfil_dns = "v1-0-4-3-d98a2f7c00192e44b8a1c902e88a.tunnel.evilcorp.com"
    f_legit = analyzer.analyze_dns_query(legit_dns, "192.168.1.100")
    f_exfil = analyzer.analyze_dns_query(exfil_dns, "192.168.1.100")

    if f_legit is not None:
        print(f"[-] False positive on legitimate DNS query: {legit_dns}")
        failures += 1
    else:
        print("  [PASS] Legitimate DNS ignored.")

    if f_exfil is None or f_exfil.mitre_attack_id != "T1071.004":
        print(f"[-] Failed to detect DNS Tunneling: {exfil_dns}")
        failures += 1
    else:
        print(f"  [PASS] Detected DNS Exfiltration: {f_exfil.rule_id} ({f_exfil.mitre_attack_id})")

    # 2. Port Sweep Test
    src = "192.168.1.200"
    dst = "192.168.1.10"
    sweep_findings = []
    for port in range(1, 15):
        res = analyzer.analyze_flow(src, dst, port)
        sweep_findings.extend(res)

    if not sweep_findings or sweep_findings[0].mitre_attack_id != "T1046":
        print("[-] Failed to detect horizontal/vertical port sweep.")
        failures += 1
    else:
        print(f"  [PASS] Detected Port Sweep: {sweep_findings[0].rule_id} ({sweep_findings[0].mitre_attack_id})")

    # 3. C2 Beaconing Test
    beacon_src = "192.168.1.50"
    beacon_dst = "198.51.100.4"
    c2_findings = []
    base_time = 1700000000.0
    for i in range(7):
        # 10.0 seconds interval with microscopic jitter (0.01s)
        pkt_time = datetime.fromtimestamp(base_time + (i * 10.0) + (0.01 if i % 2 == 0 else -0.01), tz=UTC)
        res = analyzer.analyze_flow(beacon_src, beacon_dst, 4444, timestamp=pkt_time)
        c2_findings.extend(res)

    if not c2_findings or c2_findings[0].mitre_attack_id != "T1071":
        print("[-] Failed to detect C2 periodic beaconing.")
        failures += 1
    else:
        print(f"  [PASS] Detected C2 Beaconing: {c2_findings[0].rule_id} ({c2_findings[0].mitre_attack_id})")

    if failures == 0:
        print("[+] NetworkSecurityAnalyzer self-test passed: 3/3 attack vectors verified.")
        return 0
    else:
        print(f"[-] Self-test failed with {failures} failure(s).")
        return 1


def forward_finding_to_ingest(
    finding_dict: dict[str, Any],
    ingest_url: str,
    api_key: str,
) -> bool:
    """Forwards a normalized Finding as a Security Event to the SentinelX Ingest API."""
    import httpx

    evidence_obj = finding_dict.get("evidence")
    source_ip = "0.0.0.0"
    if isinstance(evidence_obj, dict):
        source_ip = evidence_obj.get("source_ip", "0.0.0.0")

    event_payload = {
        "event_type": "network_finding",
        "source_ip": source_ip,
        "target_host": str(finding_dict.get("target")),
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
        description="SentinelX Network Security Capability Module (X2)",
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Path to Zeek / Suricata / Netflow JSON log file to analyze",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        help="Path to raw binary PCAP dump to analyze",
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

    if not args.file and not args.pcap:
        parser.print_help()
        sys.exit(1)

    analyzer = NetworkSecurityAnalyzer()
    all_findings = []

    if args.file:
        if not args.file.exists():
            print(f"[-] Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, encoding="utf-8") as f:
            for line in f:
                findings = analyzer.parse_zeek_json_line(line)
                all_findings.extend(findings)

    if args.pcap:
        if not args.pcap.exists():
            print(f"[-] Error: PCAP file not found: {args.pcap}", file=sys.stderr)
            sys.exit(1)
        pcap_findings = analyzer.parse_pcap_file(args.pcap)
        all_findings.extend(pcap_findings)

    # Format findings output
    findings_dicts = [f.model_dump(mode="json") for f in all_findings]

    if args.json:
        print(json.dumps(findings_dicts, indent=2))
    else:
        print("\n========================================================")
        print(f" SentinelX Network Security Analyzer - Findings ({len(all_findings)})")
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
