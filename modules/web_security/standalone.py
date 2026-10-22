"""Standalone CLI Runner for Web Security Capability Module (X1).

Supports offline log scanning, self-testing, and forwarding to SentinelX Ingest API.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from modules.web_security.analyzer import WebSecurityAnalyzer


def run_self_test() -> int:
    """Executes built-in test suite asserting detection accuracy on known SQLi attacks."""
    analyzer = WebSecurityAnalyzer()
    print("[*] Running WebSecurityAnalyzer self-test suite...")

    test_cases = [
        # (payload, should_detect)
        ("GET /index.html HTTP/1.1", False),
        ("GET /search?q=normal+search+term HTTP/1.1", False),
        ("GET /products?id=1%20UNION%20SELECT%20null,password%20FROM%20users HTTP/1.1", True),
        ("GET /login?user=admin'%20OR%20'1'='1 HTTP/1.1", True),
        ("POST /submit?query=test';%20DROP%20TABLE%20users;-- HTTP/1.1", True),
        ("GET /api/exec?cmd=exec+xp_cmdshell HTTP/1.1", True),
    ]

    detected_count = 0
    expected_detections = 4

    for payload, should_detect in test_cases:
        finding = analyzer.analyze_line(payload)
        is_detected = finding is not None
        status_label = "PASS" if is_detected == should_detect else "FAIL"
        print(f"  [{status_label}] Payload: {payload[:55]}... -> Detected: {is_detected}")
        if is_detected:
            detected_count += 1
            if not should_detect:
                print(f"[-] False positive on: {payload}")
                return 1
        elif should_detect:
            print(f"[-] False negative on: {payload}")
            return 1

    if detected_count == expected_detections:
        print(
            f"[+] Self-test passed: {detected_count}/{expected_detections} attacks successfully detected."
        )
        return 0
    else:
        print(
            f"[-] Self-test failed: expected {expected_detections} detections, got {detected_count}."
        )
        return 1


def main(argv: list[str] | None = None) -> int:
    """Entry point for standalone CLI execution."""
    parser = argparse.ArgumentParser(
        description="SentinelX Web Security Capability Module (Standalone CLI)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run built-in detection verification self-test",
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Path to access log file to analyze",
    )
    parser.add_argument(
        "--target-host",
        type=str,
        default="web-service-01",
        help="Target host name to associate with findings",
    )
    parser.add_argument(
        "--ingest-url",
        type=str,
        help="Optional SentinelX Ingest API endpoint to forward telemetry to",
    )

    args = parser.parse_args(argv)

    if args.test:
        return run_self_test()

    if not args.file:
        parser.print_help()
        return 0

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"[-] Error: File not found: {log_path}", file=sys.stderr)
        return 1

    analyzer = WebSecurityAnalyzer()
    findings = analyzer.analyze_file(log_path, target_host=args.target_host)

    print(f"[*] Analysis complete. Found {len(findings)} security findings:")
    findings_json = [f.model_dump(mode="json") for f in findings]
    print(json.dumps(findings_json, indent=2))

    if args.ingest_url and findings:
        import httpx

        print(f"[*] Forwarding {len(findings)} events to Ingestion API: {args.ingest_url}")
        with httpx.Client(timeout=10.0) as client:
            for f in findings:
                details: dict[str, Any] = f.evidence if isinstance(f.evidence, dict) else {}
                payload = {
                    "source_ip": details.get("source_ip", "127.0.0.1"),
                    "destination_port": 80,
                    "event_type": "web_request",
                    "target_host": args.target_host,
                    "raw_payload": details.get("payload", ""),
                    "details": details,
                }
                resp = client.post(args.ingest_url, json=payload)
                print(f"  -> Ingested finding {f.finding_id}: HTTP {resp.status_code}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
