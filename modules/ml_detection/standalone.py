"""Standalone CLI Runner for ML Anomaly Detection Capability Module (X6).

Supports offline event evaluation, baseline training, self-testing,
and forward-streaming findings to the SentinelX Ingest API (Law 1 & Law 2).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from modules.ml_detection.analyzer import (
    MLAnomalyDetector,
    PureIsolationForest,
    RollingZScoreTracker,
    calculate_shannon_entropy,
)


def run_self_test() -> int:
    """Executes built-in test suite asserting detection on entropy, Z-score, and Isolation Forest."""
    print("[*] Running MLAnomalyDetector (Module X6) self-test suite...")
    failures = 0

    # 1. Test Shannon Entropy
    low_entropy = calculate_shannon_entropy(["admin", "admin", "admin", "admin"])
    high_entropy = calculate_shannon_entropy(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"])
    if low_entropy > 0.1 or high_entropy < 3.0:
        print(f"[-] Shannon entropy test failed: low={low_entropy}, high={high_entropy}")
        failures += 1
    else:
        print(f"  [PASS] Shannon entropy calculation verified ({low_entropy} vs {high_entropy} bits).")

    # 2. Test Rolling Z-Score Tracker
    tracker = RollingZScoreTracker(threshold_z=3.0)
    # Feed 20 baseline points with low variance
    for _ in range(20):
        tracker.update(100.0)
    # Inject a massive volume spike
    z_score, is_anomaly = tracker.update(5000.0)
    if not is_anomaly or z_score < 3.0:
        print(f"[-] Rolling Z-score anomaly detection failed: z={z_score}, anomaly={is_anomaly}")
        failures += 1
    else:
        print(f"  [PASS] Rolling Z-score anomaly detected spike (Z={z_score}).")

    # 3. Test Pure Isolation Forest
    forest = PureIsolationForest(n_trees=25, sub_sample_size=32, seed=42)
    # Baseline cluster around [1.0, 1.0, 1.0]
    baseline_data = [[1.0 + (i % 5) * 0.1, 1.0 + (i % 3) * 0.1, 1.0] for i in range(50)]
    forest.fit(baseline_data)
    normal_score = forest.score([1.05, 1.02, 1.0])
    outlier_score = forest.score([50.0, 99.0, 45.0])
    if outlier_score <= normal_score or outlier_score < 0.55:
        print(f"[-] Isolation Forest score test failed: normal={normal_score}, outlier={outlier_score}")
        failures += 1
    else:
        print(f"  [PASS] Isolation Forest scored outlier successfully ({normal_score} normal vs {outlier_score} outlier).")

    # 4. Integrated Telemetry Evaluation
    detector = MLAnomalyDetector(seed=42)
    detector.train_baseline(baseline_data)
    # Off-hours event with high volume
    off_hours_event = {
        "source_ip": "192.168.1.50",
        "target_host": "srv-prod-db-01",
        "event_time": "2026-10-20T03:15:00Z",
        "details": {"bytes_transferred": 15000000},
        "raw_payload": "SELECT data FROM confidential_vault WHERE id > 0",
    }
    finding = detector.evaluate_telemetry(off_hours_event, features=[50.0, 99.0, 45.0])
    if finding is None or finding.rule_id != "RULE-ML-ANOMALY":
        print("[-] Integrated telemetry evaluation failed to emit FindingContract.")
        failures += 1
    else:
        print(f"  [PASS] Integrated evaluation emitted finding: {finding.rule_id} ({finding.severity})")

    if failures == 0:
        print("[+] Module X6 (ML Anomaly Detection) Self-Test PASSED (4/4 checks clean).\n")
        return 0
    else:
        print(f"[-] Module X6 Self-Test FAILED ({failures} errors).\n")
        return 1


def forward_finding(finding: Any, ingest_url: str, api_key: str | None = None) -> bool:
    """Submits finding to SentinelX REST Ingest API."""
    import httpx

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload = {
        "source_ip": finding.evidence.get("source_ip", "0.0.0.0") if isinstance(finding.evidence, dict) else "0.0.0.0",
        "event_type": "ml_anomaly",
        "target_host": finding.target,
        "event_time": finding.timestamp.isoformat(),
        "raw_payload": finding.description,
        "details": finding.evidence if isinstance(finding.evidence, dict) else {"raw": str(finding.evidence)},
    }

    try:
        resp = httpx.post(f"{ingest_url}/events/ingest", json=payload, headers=headers, timeout=5.0)
        return resp.status_code in (200, 201)
    except Exception as exc:
        print(f"[-] Error forwarding finding to SentinelX: {exc}", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelX ML Anomaly Detection Capability Module (X6)")
    parser.add_argument("--self-test", action="store_true", help="Execute built-in validation test suite")
    parser.add_argument("--file", type=str, help="Path to JSON file containing telemetry events array")
    parser.add_argument("--forward", action="store_true", help="Forward detected findings to SentinelX Ingest API")
    parser.add_argument("--ingest-url", type=str, default="http://localhost:8000/api/v1", help="SentinelX API URL")
    parser.add_argument("--api-key", type=str, default=None, help="Optional X-API-Key header value")

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

    events = data if isinstance(data, list) else data.get("events", [data])
    detector = MLAnomalyDetector()

    findings = []
    for ev in events:
        f = detector.evaluate_telemetry(ev)
        if f:
            findings.append(f)

    print(f"[*] Evaluated {len(events)} telemetry events; detected {len(findings)} anomalies.")

    for f in findings:
        print(json.dumps(f.model_dump(mode="json"), indent=2))
        if args.forward:
            ok = forward_finding(f, args.ingest_url, args.api_key)
            status_text = "FORWARDED" if ok else "FAILED"
            print(f"[*] Ingest API status: {status_text}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
