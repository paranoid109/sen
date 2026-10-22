"""SentinelX AI SOC Analyst Assistant CLI & Standalone Tool (Module X13).

Provides interactive command-line access to the AI SOC Analyst Assistant for:
- Incident Executive Briefing synthesis
- Alert Triage Advisory & False Positive scoring
- Natural language query to REST API translation
- Autonomous self-test verification
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.ai_assistant.assistant import (  # noqa: E402
    AIAssistant,
    TriageVerdict,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx.ai_assistant.cli")


def run_self_test() -> bool:
    """Executes built-in test suite for AI SOC Assistant capabilities."""
    print("=" * 78)
    print(" SentinelX AI SOC Assistant Engine: Autonomous Self-Test (Module X13)")
    print("=" * 78)

    assistant = AIAssistant()

    # 1. Test Incident Executive Briefing Synthesis
    incident_fixture = {
        "incident_id": "inc-sec-9988",
        "title": "Coordinated Multi-Stage Attack on db-prod-01",
        "risk_score": 95,
        "severity": "critical",
        "target_host": "db-prod-01",
        "description": "SQL injection exploit followed by reverse shell execution and lateral movement",
        "alerts": [
            {
                "rule_id": "RULE-SQLI-001",
                "severity": "critical",
                "source_ip": "198.51.100.4",
                "mitre_attack_id": "T1190",
            },
            {
                "rule_id": "RULE-FORENSICS-001",
                "severity": "critical",
                "source_ip": "127.0.0.1",
                "mitre_attack_id": "T1059.004",
            },
            {
                "rule_id": "RULE-GRAPH-001",
                "severity": "high",
                "source_ip": "192.168.1.10",
                "mitre_attack_id": "T1021",
            },
        ],
    }

    briefing = assistant.synthesize_incident_briefing(incident_fixture)
    print("\n[1/4] Testing Incident Executive Briefing Synthesis...")
    assert "db-prod-01" in briefing.executive_summary
    assert "95/100" in briefing.markdown_content
    assert len(briefing.mitre_mitigations) >= 2
    assert "host_quarantine" in briefing.recommended_playbooks
    print(f"      Result: OK (Generated {len(briefing.markdown_content)} chars briefing)")

    # 2. Test Alert Triage Advisor (True Positive vs False Positive)
    print("\n[2/4] Testing Alert Triage Advisor...")
    alert_tp = {
        "rule_id": "RULE-SQLI-001",
        "source_ip": "198.51.100.4",
        "severity": "critical",
        "occurrence_count": 8,
        "target_host": "server-prod-01",
        "evidence": "GET /api/users?id=1 UNION SELECT username, password_hash FROM users --",
    }
    triage_tp = assistant.advise_alert_triage(alert_tp)
    assert triage_tp.verdict == TriageVerdict.TRUE_POSITIVE
    assert triage_tp.confidence_score >= 0.90
    print(f"      True Positive Case: Verdict={triage_tp.verdict.value} (Confidence={triage_tp.confidence_score*100:.0f}%) -> OK")

    alert_fp = {
        "rule_id": "RULE-PORT-001",
        "source_ip": "10.0.0.50",
        "severity": "low",
        "occurrence_count": 2,
        "target_host": "server-prod-01",
        "evidence": "Healthcheck probe from Datadog agent monitor port 8000",
    }
    triage_fp = assistant.advise_alert_triage(alert_fp)
    assert triage_fp.verdict == TriageVerdict.FALSE_POSITIVE
    print(f"      False Positive Case: Verdict={triage_fp.verdict.value} (Confidence={triage_fp.confidence_score*100:.0f}%) -> OK")

    # 3. Test Natural Language to REST Query Translation
    print("\n[3/4] Testing Natural Language to REST Query Translation...")
    q1 = assistant.translate_query("Show all critical alerts from IP 198.51.100.4 on server-prod-01")
    assert q1.endpoint == "/api/v1/alerts"
    assert q1.params.get("severity") == "critical"
    assert q1.params.get("source_ip") == "198.51.100.4"
    assert q1.params.get("target_host") == "server-prod-01"

    q2 = assistant.translate_query("Find open incidents with risk score above 80")
    assert q2.endpoint == "/api/v1/incidents"
    assert q2.params.get("status") == "OPEN"
    assert q2.params.get("min_risk") == 80
    print(f"      Translated '{q1.natural_query}' -> {q1.endpoint} {q1.params} -> OK")

    # 4. Test MITRE Defense Guidance
    print("\n[4/4] Testing MITRE ATT&CK Defense Guidance Mapping...")
    guidance = briefing.mitre_mitigations
    technique_ids = {g["mitre_id"] for g in guidance}
    assert "T1190" in technique_ids or "T1059.004" in technique_ids
    print(f"      Mapped {len(guidance)} MITRE techniques to defensive controls -> OK")

    print("\n" + "=" * 78)
    print(" ALL SELF-TEST CHECKS PASSED: AI SOC Assistant Module Verified (100%)")
    print("=" * 78)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelX AI SOC Analyst Assistant CLI (X13)")
    parser.add_argument("--incident-file", type=Path, help="Path to incident JSON to generate briefing")
    parser.add_argument("--triage-alert", type=Path, help="Path to alert JSON to advise triage")
    parser.add_argument("--query", type=str, help="Natural language inquiry to translate to REST API")
    parser.add_argument("--self-test", action="store_true", help="Run comprehensive autonomous self-test")

    args = parser.parse_args()
    assistant = AIAssistant()

    if args.self_test:
        success = run_self_test()
        return 0 if success else 1

    if args.query:
        translation = assistant.translate_query(args.query)
        print("\n" + "=" * 78)
        print(f" Natural Query: {translation.natural_query}")
        print(f" REST Endpoint: {translation.method} {translation.endpoint}")
        print(f" Parameters:    {json.dumps(translation.params, indent=2)}")
        print(f" Explanation:   {translation.explanation}")
        print("=" * 78 + "\n")
        return 0

    if args.triage_alert:
        if not args.triage_alert.exists():
            logger.error("Alert file not found: %s", args.triage_alert)
            return 1
        with open(args.triage_alert, encoding="utf-8") as f:
            data = json.load(f)
        assessment = assistant.advise_alert_triage(data)
        print("\n" + "=" * 78)
        print(f" Triage Verdict:   {assessment.verdict.value}")
        print(f" Confidence Score: {assessment.confidence_score * 100:.1f}%")
        print(f" Suggested Action: {assessment.suggested_action}")
        print(" Key Rationale:")
        for r in assessment.reasoning:
            print(f"   * {r}")
        print("=" * 78 + "\n")
        return 0

    if args.incident_file:
        if not args.incident_file.exists():
            logger.error("Incident file not found: %s", args.incident_file)
            return 1
        with open(args.incident_file, encoding="utf-8") as f:
            data = json.load(f)
        briefing = assistant.synthesize_incident_briefing(data)
        print("\n" + briefing.markdown_content + "\n")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
