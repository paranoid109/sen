"""Standalone CLI Runner for Dynamic Risk Engine Capability Module (X9).

Supports offline risk calculation, factor breakdowns, self-testing,
and emitting risk escalation findings to SentinelX (Law 1, Law 2, Law 6).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from modules.risk_engine.analyzer import DynamicRiskEngine


def run_self_test() -> int:
    """Executes built-in test suite asserting mathematical bounds, factor multipliers, and findings."""
    print("[*] Running DynamicRiskEngine (Module X9) self-test suite...")
    failures = 0

    engine = DynamicRiskEngine()

    # 1. Low-Risk Test Case
    low_eval = engine.calculate_risk(
        asset_id="ws-eng-100",
        asset_criticality="low",
        highest_alert_severity="low",
        alert_count=1,
        has_cisa_kev=False,
    )
    # Base: 5.0 * 0.8 = 4.0 -> score 4
    if low_eval.risk_score > 20 or low_eval.risk_tier != "low":
        print(f"[-] Low risk evaluation failed: score={low_eval.risk_score}, tier={low_eval.risk_tier}")
        failures += 1
    else:
        print(f"  [PASS] Low-risk baseline calculated: {low_eval.risk_score}/100 ({low_eval.risk_tier})")

    # 2. Critical Multi-Factor Escalation Test Case
    crit_eval = engine.calculate_risk(
        asset_id="db-prod-01",
        asset_criticality="critical",
        highest_alert_severity="critical",
        alert_count=5,
        has_cisa_kev=True,
        crown_jewel_exposed=True,
    )
    # Base: 35 * 2.0 = 70; Velocity: min(20, 4*3) = 12; Exploit: 25; Blast: 20 -> 70+12+25+20 = 127 -> capped at 100
    if crit_eval.risk_score != 100 or crit_eval.risk_tier != "critical":
        print(f"[-] Critical risk evaluation failed: score={crit_eval.risk_score}, tier={crit_eval.risk_tier}")
        failures += 1
    else:
        print(f"  [PASS] Critical multi-factor risk capped at 100/100 (Score: {crit_eval.risk_score}, Tier: {crit_eval.risk_tier})")

    # 3. High-Risk Intermediate Case with FindingContract
    finding = engine.evaluate_to_finding(
        asset_id="server-prod-01",
        asset_criticality="high",
        highest_alert_severity="high",
        alert_count=3,
        has_cisa_kev=True,
        reachable_nodes=2,
    )
    if finding is None or finding.rule_id != "RULE-RISK-DYNAMIC-ESCALATION":
        print("[-] High-risk finding generation failed.")
        failures += 1
    else:
        print(f"  [PASS] Emitted FindingContract: {finding.rule_id} ({finding.severity})")

    if failures == 0:
        print("[+] Module X9 (Dynamic Risk Engine) Self-Test PASSED (3/3 checks clean).\n")
        return 0
    else:
        print(f"[-] Module X9 Self-Test FAILED ({failures} errors).\n")
        return 1


def forward_finding(finding: Any, ingest_url: str, api_key: str | None = None) -> bool:
    """Submits finding to SentinelX REST Ingest API."""
    import httpx

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload = {
        "source_ip": "192.168.1.10",
        "event_type": "risk_finding",
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
    parser = argparse.ArgumentParser(description="SentinelX Dynamic Risk Engine (X9)")
    parser.add_argument("--self-test", action="store_true", help="Execute built-in validation test suite")
    parser.add_argument("--asset-id", type=str, default="server-prod-01", help="Asset identifier")
    parser.add_argument("--criticality", choices=["critical", "high", "medium", "low"], default="high", help="Asset tier")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="high", help="Highest alert severity")
    parser.add_argument("--alert-count", type=int, default=3, help="Number of correlated alerts")
    parser.add_argument("--cisa-kev", action="store_true", help="Flag if asset has CISA KEV actively exploited flaw")
    parser.add_argument("--cvss", type=float, default=None, help="CVSS score")
    parser.add_argument("--blast-nodes", type=int, default=2, help="Number of reachable graph nodes")
    parser.add_argument("--crown-jewel", action="store_true", help="Flag if attack path exposes Crown Jewel")
    parser.add_argument("--forward", action="store_true", help="Forward detected findings to SentinelX Ingest API")
    parser.add_argument("--ingest-url", type=str, default="http://localhost:8000/api/v1", help="SentinelX API URL")
    parser.add_argument("--api-key", type=str, default=None, help="Optional X-API-Key header value")

    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    engine = DynamicRiskEngine()
    result = engine.calculate_risk(
        asset_id=args.asset_id,
        asset_criticality=args.criticality,
        highest_alert_severity=args.severity,
        alert_count=args.alert_count,
        has_cisa_kev=args.cisa_kev,
        cvss_score=args.cvss,
        reachable_nodes=args.blast_nodes,
        crown_jewel_exposed=args.crown_jewel,
    )

    print(json.dumps({
        "asset_id": result.asset_id,
        "risk_score": result.risk_score,
        "risk_tier": result.risk_tier,
        "factors": result.factors_summary,
        "recommendations": result.recommendations,
    }, indent=2))

    if args.forward and result.risk_tier in ("critical", "high"):
        finding = engine.evaluate_to_finding(
            asset_id=args.asset_id,
            asset_criticality=args.criticality,
            highest_alert_severity=args.severity,
            alert_count=args.alert_count,
            has_cisa_kev=args.cisa_kev,
            cvss_score=args.cvss,
            reachable_nodes=args.blast_nodes,
            crown_jewel_exposed=args.crown_jewel,
        )
        if finding:
            ok = forward_finding(finding, args.ingest_url, args.api_key)
            print(f"[*] Ingest API status: {'FORWARDED' if ok else 'FAILED'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
