"""TCP Port Scan Simulator (Step 7).

Simulates a TCP port reconnaissance sweep across multiple destination ports
from an external scanner IP against a monitored target via SentinelX REST APIs.
Triggers detection rule RULE-NET-001 (MITRE ATT&CK T1046).
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx

DEFAULT_PORTS = [
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    80,  # HTTP
    110,  # POP3
    139,  # NetBIOS
    443,  # HTTPS
    445,  # SMB
    1433,  # MS-SQL
    3306,  # MySQL
    8080,  # HTTP-Alt
]


def generate_connection_event(
    target_host: str,
    target_ip: str,
    scanner_ip: str,
    port: int,
    idx: int,
) -> dict[str, Any]:
    """Builds a SingleIngestRequest payload simulating a TCP port probe."""
    now_utc = datetime.now(UTC).isoformat()
    source_port = 49152 + idx

    return {
        "source_ip": scanner_ip,
        "destination_ip": target_ip,
        "destination_port": port,
        "source_port": source_port,
        "event_type": "connection",
        "target_host": target_host,
        "event_time": now_utc,
        "raw_payload": f"TCP SYN {scanner_ip}:{source_port} -> {target_ip}:{port}",
        "details": {
            "protocol": "tcp",
            "state": "syn_sent",
            "port": port,
        },
    }


def run_simulation(
    api_url: str,
    api_key: str,
    target_host: str,
    target_ip: str,
    scanner_ip: str,
    ports: list[int],
    use_batch: bool,
    delay: float,
    dry_run: bool,
) -> int:
    """Executes the port scan simulation against the target API."""
    base = api_url.rstrip("/")
    endpoint = f"{base}/api/v1/events/batch" if use_batch else f"{base}/api/v1/events/ingest"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    print("=" * 65)
    print(" SentinelX Attack Simulator: TCP Port Scan (T1046)")
    print("=" * 65)
    print(f" Target Host : {target_host} ({target_ip})")
    print(f" Scanner IP  : {scanner_ip}")
    print(f" Ports ({len(ports)}): {', '.join(str(p) for p in ports)} (Threshold: 10)")
    print(f" API Method  : {'Batch (/batch)' if use_batch else 'Stream (/ingest)'}")
    print(f" Ingest URL  : {endpoint}")
    print(f" Mode        : {'DRY RUN' if dry_run else 'ACTIVE EMISSION'}")
    print("-" * 65)

    events = [
        generate_connection_event(
            target_host=target_host,
            target_ip=target_ip,
            scanner_ip=scanner_ip,
            port=port,
            idx=idx,
        )
        for idx, port in enumerate(ports, start=1)
    ]

    if dry_run:
        for idx, ev in enumerate(events, start=1):
            print(
                f"[{idx}/{len(ports)}] [DRY-RUN] SYN probe port {ev['destination_port']:<5} from {scanner_ip}"
            )
        print("-" * 65)
        print(f" Simulation Finished: {len(ports)} probes simulated in DRY RUN mode.")
        print(" [!] Threshold reached (>= 10 distinct ports): Triggers RULE-NET-001.")
        print("=" * 65 + "\n")
        return 0

    with httpx.Client(timeout=10.0) as client:
        try:
            if use_batch:
                batch_payload = {
                    "target_host": target_host,
                    "events": events,
                }
                resp = client.post(endpoint, json=batch_payload, headers=headers)
                if resp.status_code == 201:
                    data = resp.json()
                    print(
                        f" HTTP 201 OK | Batch of {data.get('ingested_count', len(events))} probes ingested successfully."
                    )
                else:
                    print(f" HTTP {resp.status_code} FAIL | {resp.text}")
                    return 1
            else:
                for idx, ev in enumerate(events, start=1):
                    resp = client.post(endpoint, json=ev, headers=headers)
                    if resp.status_code == 201:
                        print(
                            f"[{idx}/{len(ports)}] HTTP 201 OK | Probed Port {ev['destination_port']:<5}"
                        )
                    else:
                        print(f"[{idx}/{len(ports)}] HTTP {resp.status_code} FAIL | {resp.text}")

                    if idx < len(ports) and delay > 0:
                        time.sleep(delay)
        except httpx.ConnectError:
            print(
                f"\n[!] Connection Error: Could not connect to {endpoint}."
                "\n    Ensure the SentinelX backend is running (e.g. uvicorn backend.app.main:app --port 8000)."
            )
            return 1
        except Exception as e:
            print(f" ERROR: {e}")
            return 1

    print("-" * 65)
    print(f" Simulation Finished: {len(ports)} probes transmitted.")
    if len(ports) >= 10:
        print(
            " [!] Threshold reached (>= 10 distinct ports): An alert should be triggered by RULE-NET-001."
        )
    print("=" * 65 + "\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP Port Scan Attack Simulator")
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
        "--scanner-ip",
        default="192.168.1.200",
        help="Scanner source IP address (default: 192.168.1.200)",
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_PORTS,
        help="List of destination ports to probe",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        default=True,
        help="Send all probes in a single batch request (default: True)",
    )
    parser.add_argument(
        "--stream",
        dest="batch",
        action="store_false",
        help="Send probes sequentially one by one",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay between sequential events in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print probes without sending HTTP requests",
    )

    args = parser.parse_args()
    code = run_simulation(
        api_url=args.api_url,
        api_key=args.api_key,
        target_host=args.target_host,
        target_ip=args.target_ip,
        scanner_ip=args.scanner_ip,
        ports=args.ports,
        use_batch=args.batch,
        delay=args.delay,
        dry_run=args.dry_run,
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
