"""SQL Injection Attack Simulator (Step 7).

Simulates web application SQL injection exploits against a monitored target host
via the SentinelX REST Ingest API.
Triggers detection rule RULE-WEB-001 (MITRE ATT&CK T1190).
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx

SQLI_PAYLOADS = [
    {
        "type": "UNION SELECT Data Exfiltration",
        "method": "GET",
        "uri": "/products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users",
        "body": None,
        "status_code": 200,
    },
    {
        "type": "Authentication Bypass (Tautology)",
        "method": "POST",
        "uri": "/api/v1/auth/login",
        "body": "username=admin'%20OR%20'1'='1&password=password",
        "status_code": 200,
    },
    {
        "type": "Destructive Stacked Query",
        "method": "GET",
        "uri": "/search.php?q=test';%20DROP%20TABLE%20users;--",
        "body": None,
        "status_code": 500,
    },
    {
        "type": "Boolean Tautology with SQL Comment",
        "method": "GET",
        "uri": "/items?cat=electronics'%20OR%201=1%20--",
        "body": None,
        "status_code": 200,
    },
]


def generate_sqli_event(
    target_host: str,
    target_ip: str,
    attacker_ip: str,
    payload_info: dict[str, Any],
    idx: int,
) -> dict[str, Any]:
    """Builds a SingleIngestRequest payload simulating an HTTP request with SQL injection."""
    import urllib.parse

    now_utc = datetime.now(UTC).isoformat()
    source_port = 53000 + idx
    method = payload_info["method"]
    raw_uri = payload_info["uri"]
    decoded_uri = urllib.parse.unquote(raw_uri)
    status_code = payload_info["status_code"]

    raw_log = (
        f'{attacker_ip} - - [{datetime.now(UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {raw_uri} HTTP/1.1" {status_code} 2048 "-" "sqlmap/1.8"'
    )

    details = {
        "method": method,
        "uri": decoded_uri,
        "status_code": status_code,
        "user_agent": "sqlmap/1.8",
        "exploit_type": payload_info["type"],
    }
    if payload_info.get("body"):
        details["body"] = payload_info["body"]

    return {
        "source_ip": attacker_ip,
        "destination_ip": target_ip,
        "destination_port": 80,
        "source_port": source_port,
        "event_type": "web_request",
        "target_host": target_host,
        "event_time": now_utc,
        "raw_payload": raw_log,
        "details": details,
    }


def run_simulation(
    api_url: str,
    api_key: str,
    target_host: str,
    target_ip: str,
    attacker_ip: str,
    delay: float,
    dry_run: bool,
) -> int:
    """Executes the SQL injection simulation against the target API."""
    endpoint = f"{api_url.rstrip('/')}/api/v1/events/ingest"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    print("=" * 65)
    print(" SentinelX Attack Simulator: SQL Injection (T1190)")
    print("=" * 65)
    print(f" Target Host : {target_host} ({target_ip})")
    print(f" Attacker IP : {attacker_ip}")
    print(f" Payloads    : {len(SQLI_PAYLOADS)} distinct exploit signatures")
    print(f" Ingest URL  : {endpoint}")
    print(f" Mode        : {'DRY RUN' if dry_run else 'ACTIVE EMISSION'}")
    print("-" * 65)

    success_count = 0
    with httpx.Client(timeout=5.0) as client:
        for idx, payload_info in enumerate(SQLI_PAYLOADS, start=1):
            event = generate_sqli_event(
                target_host=target_host,
                target_ip=target_ip,
                attacker_ip=attacker_ip,
                payload_info=payload_info,
                idx=idx,
            )

            if dry_run:
                print(
                    f"[{idx}/{len(SQLI_PAYLOADS)}] [DRY-RUN] {payload_info['type']:<30} | {payload_info['method']} {payload_info['uri'][:30]}..."
                )
                success_count += 1
            else:
                try:
                    resp = client.post(endpoint, json=event, headers=headers)
                    if resp.status_code == 201:
                        data = resp.json()
                        event_id = data.get("event_ids", ["N/A"])[0]
                        print(
                            f"[{idx}/{len(SQLI_PAYLOADS)}] HTTP 201 OK | {payload_info['type']:<30} | event_id={event_id[:8]}..."
                        )
                        success_count += 1
                    else:
                        print(
                            f"[{idx}/{len(SQLI_PAYLOADS)}] HTTP {resp.status_code} FAIL | {resp.text}"
                        )
                except httpx.ConnectError:
                    print(
                        f"\n[!] Connection Error: Could not connect to {endpoint}."
                        "\n    Ensure the SentinelX backend is running (e.g. uvicorn backend.app.main:app --port 8000)."
                    )
                    return 1
                except Exception as e:
                    print(f"[{idx}/{len(SQLI_PAYLOADS)}] ERROR: {e}")

            if idx < len(SQLI_PAYLOADS) and delay > 0:
                time.sleep(delay)

    print("-" * 65)
    print(f" Simulation Finished: {success_count}/{len(SQLI_PAYLOADS)} exploits transmitted.")
    print(" [!] Threshold reached (>= 1 match): Each signature should trigger RULE-WEB-001.")
    print("=" * 65 + "\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="SQL Injection Attack Simulator")
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
        "--attacker-ip",
        default="192.168.1.150",
        help="Attacker source IP address (default: 192.168.1.150)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Delay between events in seconds (default: 0.2)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print payloads without sending HTTP requests",
    )

    args = parser.parse_args()
    code = run_simulation(
        api_url=args.api_url,
        api_key=args.api_key,
        target_host=args.target_host,
        target_ip=args.target_ip,
        attacker_ip=args.attacker_ip,
        delay=args.delay,
        dry_run=args.dry_run,
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
