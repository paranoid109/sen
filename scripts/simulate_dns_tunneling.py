"""DNS Tunneling & Data Exfiltration Attack Simulator.

Simulates DNS queries carrying encoded payloads / high-entropy exfiltration labels
against a monitored DNS server or gateway via SentinelX REST APIs.
Triggers detection rule RULE-NET-002 (MITRE ATT&CK T1071.004).
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from typing import Any

import httpx

SAMPLE_TUNNEL_QUERIES = [
    "v1-0-4-3-d98a2f7c00192e44b8a1c902e88a.tunnel.evilcorp.com",
    "a9f82d1c0042e88b9021a8f9001bca2d3345.data.exfil-dns.org",
    "c00192e44b8a1c902e88ad98a2f778a1bc29.stage2.command.net",
    "88f9a012bce9047128a9dc384910efab7721.beacon.darkc2.io",
]


def generate_dns_tunnel_event(
    target_host: str,
    target_ip: str,
    source_ip: str,
    query: str,
) -> dict[str, Any]:
    """Builds a SingleIngestRequest payload simulating a DNS tunneling security event."""
    now_utc = datetime.now(UTC).isoformat()
    return {
        "source_ip": source_ip,
        "destination_ip": target_ip,
        "destination_port": 53,
        "source_port": 54321,
        "event_type": "network_finding",
        "target_host": target_host,
        "event_time": now_utc,
        "raw_payload": f"DNS IN A {query} from {source_ip}",
        "details": {
            "query": query,
            "rule_id": "RULE-NET-DNS-001",
            "rule_name": "DNS Tunneling / Data Exfiltration Anomaly",
            "mitre_attack_id": "T1071.004",
            "technique": "DNS Tunneling",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS Tunneling Attack Simulator")
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
        "--target-ip",
        default="192.168.1.10",
        help="Target IP address (default: 192.168.1.10)",
    )
    parser.add_argument(
        "--source-ip",
        default="192.168.1.155",
        help="Source client IP address (default: 192.168.1.155)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=2,
        help="Number of tunneling queries to transmit",
    )

    args = parser.parse_args()

    print("=" * 65)
    print(" SentinelX Attack Simulator: DNS Tunneling Exfiltration (T1071.004)")
    print("=" * 65)
    print(f" Target Host  : {args.target_host} ({args.target_ip}:53)")
    print(f" Source Client: {args.source_ip}")
    print(f" API Endpoint : {args.api_url}/api/v1/events/ingest")
    print("-" * 65)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": args.api_key,
    }

    events = [
        generate_dns_tunnel_event(
            target_host=args.target_host,
            target_ip=args.target_ip,
            source_ip=args.source_ip,
            query=SAMPLE_TUNNEL_QUERIES[i % len(SAMPLE_TUNNEL_QUERIES)],
        )
        for i in range(args.count)
    ]

    with httpx.Client(base_url=args.api_url, timeout=10.0) as client:
        try:
            res = client.post("/api/v1/events/batch", json={"events": events}, headers=headers)
            if res.status_code == 201:
                data = res.json()
                print(f"[+] Successfully ingested {data.get('ingested_count', len(events))} events.")
                print("[+] Triggering Detection Rule RULE-NET-002 (DNS Tunneling Detected).")
            else:
                print(f"[-] Ingestion failed: {res.status_code} - {res.text}")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            sys.exit(1)

    print("=" * 65)


if __name__ == "__main__":
    main()
