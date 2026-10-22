"""Unit tests for SentinelX AI SOC Analyst Assistant (Module X13)."""

from __future__ import annotations

from modules.ai_assistant.assistant import (
    AIAssistant,
    TriageVerdict,
)
from modules.ai_assistant.standalone import run_self_test


def test_incident_briefing_synthesis():
    assistant = AIAssistant()
    incident = {
        "incident_id": "inc-test-101",
        "title": "Suspected Data Exfiltration and Privilege Escalation",
        "risk_score": 88,
        "severity": "critical",
        "target_host": "server-prod-01",
        "description": "SQL injection exploit followed by reverse shell and cloud bucket leak",
        "alerts": [
            {
                "rule_id": "RULE-SQLI-001",
                "severity": "critical",
                "source_ip": "198.51.100.4",
                "mitre_attack_id": "T1190",
            },
            {
                "rule_id": "RULE-CLOUD-001",
                "severity": "high",
                "source_ip": "198.51.100.4",
                "mitre_attack_id": "T1530",
            },
        ],
    }

    briefing = assistant.synthesize_incident_briefing(incident)
    assert briefing.incident_id == "inc-test-101"
    assert briefing.risk_score == 88
    assert "server-prod-01" in briefing.executive_summary
    assert "88/100" in briefing.markdown_content
    assert any(m["mitre_id"] == "T1190" for m in briefing.mitre_mitigations)
    assert any(m["mitre_id"] == "T1530" for m in briefing.mitre_mitigations)
    assert "host_quarantine" in briefing.recommended_playbooks


def test_triage_advisor_true_positive():
    assistant = AIAssistant()
    alert = {
        "rule_id": "RULE-SQLI-001",
        "severity": "critical",
        "source_ip": "203.0.113.15",
        "occurrence_count": 6,
        "target_host": "db-prod-01",
        "evidence": "SELECT * FROM users WHERE id = 1 UNION SELECT password_hash FROM admin --",
    }

    triage = assistant.advise_alert_triage(alert)
    assert triage.verdict == TriageVerdict.TRUE_POSITIVE
    assert triage.confidence_score >= 0.90
    assert triage.recommended_status == "INVESTIGATING"
    assert "quarantine" in triage.suggested_action.lower()


def test_triage_advisor_false_positive():
    assistant = AIAssistant()
    alert = {
        "rule_id": "RULE-PORT-001",
        "severity": "low",
        "source_ip": "127.0.0.1",
        "occurrence_count": 1,
        "target_host": "server-prod-01",
        "evidence": "datadog-agent healthcheck ping on /healthz",
    }

    triage = assistant.advise_alert_triage(alert)
    assert triage.verdict == TriageVerdict.FALSE_POSITIVE
    assert triage.recommended_status == "FALSE_POSITIVE"
    assert "false_positive" in triage.suggested_action.lower()


def test_natural_language_query_translation():
    assistant = AIAssistant()

    # Alerts query
    q1 = assistant.translate_query("Show high alerts for db-prod-01")
    assert q1.endpoint == "/api/v1/alerts"
    assert q1.params.get("severity") == "high"
    assert q1.params.get("target_host") == "db-prod-01"

    # Incidents query
    q2 = assistant.translate_query("List open incidents with risk score over 85")
    assert q2.endpoint == "/api/v1/incidents"
    assert q2.params.get("status") == "OPEN"
    assert q2.params.get("min_risk") == 85

    # Audit query
    q3 = assistant.translate_query("Show audit logs for user auditor")
    assert q3.endpoint == "/api/v1/audit"
    assert q3.params.get("username") == "auditor"


def test_ai_assistant_self_test():
    assert run_self_test() is True
