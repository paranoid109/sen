"""SSH Brute-Force Attack Simulator (Step 7).

Simulates rapid failed SSH authentication attempts from an external attacker IP
against a target monitored host via the SentinelX REST Ingest API.
Triggers detection rule RULE-AUTH-001 (MITRE ATT&CK T1110.001).
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx

DEFAULT_USERNAMES = [
    "admin",
    "root",
    "deploy",
    "oracle",
    "test",
    "guest",
    "backup",
    "ubuntu",
]


def generate_bruteforce_event(
    target_host: str,
    target_ip: str,
    attacker_ip: str,
    username: str,
    port_idx: int,
) -> dict[str, Any]:
    """Builds a SingleIngestRequest payload simulating an SSH auth failure."""
    now_utc = datetime.now(UTC).isoformat()
    source_port = 50000 + port_idx
    raw_log = (
        f"Oct  7 12:00:{port_idx:02d} {target_host} sshd[{1000 + port_idx}]: "
        f"Failed password for invalid user {username} from {attacker_ip} port {source_port} ssh2"
    )

    return {
        "source_ip": attacker_ip,
        "destination_ip": target_ip,
        "destination_port": 22,
        "source_port": source_port,
        "event_type": "auth_failed",
        "target_host": target_host,
        "event_time": now_utc,
        "raw_payload": raw_log,
        "details": {
            "user": username,
            "service": "sshd",
            "auth_method": "password",
            "attempt": port_idx,
        },
    }


def run_simulation(
    api_url: str,
    api_key: str,
    target_host: str,
    target_ip: str,
    attacker_ip: str,
    attempts: int,
    delay: float,
    dry_run: bool,
) -> int:
    """Executes the brute force simulation against the target API."""
    endpoint = f"{api_url.rstrip('/')}/api/v1/events/ingest"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    print("=" * 65)
    print(" SentinelX Attack Simulator: SSH Brute-Force (T1110.001)")
    print("=" * 65)
    print(f" Target Host : {target_host} ({target_ip})")
    print(f" Attacker IP : {attacker_ip}")
    print(f" Attempts    : {attempts} failed logins (Rule threshold: 5)")
    print(f" Ingest URL  : {endpoint}")
    print(f" Delay       : {delay}s between attempts")
    print(f" Mode        : {'DRY RUN' if dry_run else 'ACTIVE EMISSION'}")
    print("-" * 65)

    success_count = 0
    with httpx.Client(timeout=5.0) as client:
        for idx in range(1, attempts + 1):
            username = DEFAULT_USERNAMES[(idx - 1) % len(DEFAULT_USERNAMES)]
            event_payload = generate_bruteforce_event(
                target_host=target_host,
                target_ip=target_ip,
                attacker_ip=attacker_ip,
                username=username,
                port_idx=idx,
            )

            if dry_run:
                print(
                    f"[{idx}/{attempts}] [DRY-RUN] user={username:<8} src={attacker_ip} -> dst={target_host}:22"
                )
                success_count += 1
            else:
                try:
                    resp = client.post(endpoint, json=event_payload, headers=headers)
                    if resp.status_code == 201:
                        data = resp.json()
                        event_id = data.get("event_ids", ["N/A"])[0]
                        print(
                            f"[{idx}/{attempts}] HTTP 201 OK | user={username:<8} | event_id={event_id[:8]}..."
                        )
                        success_count += 1
                    else:
                        print(f"[{idx}/{attempts}] HTTP {resp.status_code} FAIL | {resp.text}")
                except httpx.ConnectError:
                    print(
                        f"\n[!] Connection Error: Could not connect to {endpoint}."
                        "\n    Ensure the SentinelX backend is running (e.g. uvicorn backend.app.main:app --port 8000)."
                    )
                    return 1
                except Exception as e:
                    print(f"[{idx}/{attempts}] ERROR: {e}")

            if idx < attempts and delay > 0:
                time.sleep(delay)

    print("-" * 65)
    print(f" Simulation Finished: {success_count}/{attempts} events transmitted.")
    if success_count >= 5:
        print(
            " [!] Threshold reached (>= 5 events): An alert should be triggered by RULE-AUTH-001."
        )
    print("=" * 65 + "\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH Brute-Force Attack Simulator")
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
        default="192.168.1.100",
        help="Attacker source IP address (default: 192.168.1.100)",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=6,
        help="Number of failed attempts to simulate (default: 6)",
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
        help="Print events without sending HTTP requests",
    )

    args = parser.parse_args()
    code = run_simulation(
        api_url=args.api_url,
        api_key=args.api_key,
        target_host=args.target_host,
        target_ip=args.target_ip,
        attacker_ip=args.attacker_ip,
        attempts=args.attempts,
        delay=args.delay,
        dry_run=args.dry_run,
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
