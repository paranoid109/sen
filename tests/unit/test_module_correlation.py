"""Unit Tests for Module X7: Advanced Correlation Engine Capability Module."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from contracts.python.models import IncidentContract, IncidentStatus, SeverityLevel
from modules.correlation.analyzer import AdvancedCorrelationEngine
from modules.correlation.standalone import run_self_test


def test_single_stage_alert_does_not_trigger_incident() -> None:
    """Asserts a single alert in isolation does not trigger a multi-stage incident."""
    engine = AdvancedCorrelationEngine(time_window_hours=4)
    alert = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-NET-001",
        "rule_name": "TCP SYN Port Scan",
        "mitre_attack_id": "T1046",
        "severity": "medium",
        "source_ip": "198.51.100.99",
        "target_host": "srv-prod-db-01",
        "created_at": datetime.now(UTC).isoformat(),
    }
    incident = engine.process_alert(alert)
    assert incident is None


def test_recon_to_initial_access_correlation() -> None:
    """Asserts Reconnaissance followed by Initial Access triggers a 2-stage correlated incident."""
    engine = AdvancedCorrelationEngine(time_window_hours=4)
    target = "srv-prod-app-01"
    now = datetime.now(UTC)

    # 1. Port scan
    alert_1 = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-NET-001",
        "rule_name": "TCP SYN Port Scan",
        "mitre_attack_id": "T1046",
        "severity": "medium",
        "source_ip": "198.51.100.99",
        "target_host": target,
        "first_seen": (now - timedelta(minutes=20)).isoformat(),
    }
    assert engine.process_alert(alert_1) is None

    # 2. SQL Injection
    alert_2 = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-WEB-001",
        "rule_name": "SQL Injection Exploit",
        "mitre_attack_id": "T1190",
        "severity": "high",
        "source_ip": "198.51.100.42",
        "target_host": target,
        "first_seen": now.isoformat(),
    }
    incident = engine.process_alert(alert_2)
    assert incident is not None
    assert isinstance(incident, IncidentContract)
    assert "Reconnaissance -> Initial Access" in incident.title
    assert incident.target_host == target
    assert len(incident.alert_ids) == 2
    assert incident.status == IncidentStatus.OPEN
    assert 40 <= incident.risk_score <= 100


def test_full_four_stage_kill_chain_reconstruction() -> None:
    """Asserts 4-stage kill-chain produces a critical severity IncidentContract with 4 alerts."""
    engine = AdvancedCorrelationEngine(time_window_hours=4)
    target = "srv-prod-vault-01"
    now = datetime.now(UTC)

    alerts = [
        # Stage 1: Reconnaissance
        {
            "alert_id": str(uuid.uuid4()),
            "rule_id": "RULE-NET-001",
            "rule_name": "Port Sweep",
            "mitre_attack_id": "T1046",
            "severity": "medium",
            "target_host": target,
            "first_seen": (now - timedelta(minutes=45)).isoformat(),
        },
        # Stage 2: Initial Access (Brute Force)
        {
            "alert_id": str(uuid.uuid4()),
            "rule_id": "RULE-AUTH-001",
            "rule_name": "SSH Brute-Force Attempt",
            "mitre_attack_id": "T1110.001",
            "severity": "high",
            "target_host": target,
            "first_seen": (now - timedelta(minutes=30)).isoformat(),
        },
        # Stage 3: Execution (FIM Tampering)
        {
            "alert_id": str(uuid.uuid4()),
            "rule_id": "RULE-EDR-001",
            "rule_name": "Critical System File Tampering",
            "mitre_attack_id": "T1565.001",
            "severity": "critical",
            "target_host": target,
            "first_seen": (now - timedelta(minutes=15)).isoformat(),
        },
        # Stage 4: Command and Control (C2 Beacon)
        {
            "alert_id": str(uuid.uuid4()),
            "rule_id": "RULE-TI-001",
            "rule_name": "Threat Intel C2 Communication",
            "mitre_attack_id": "T1071",
            "severity": "critical",
            "target_host": target,
            "first_seen": now.isoformat(),
        },
    ]

    incidents = []
    for a in alerts:
        inc = engine.process_alert(a)
        if inc:
            incidents.append(inc)

    # 3 incidents synthesized (at stage 2, stage 3, stage 4)
    assert len(incidents) == 3
    final_inc = incidents[-1]
    assert final_inc.severity == SeverityLevel.CRITICAL
    assert final_inc.risk_score == 100
    assert len(final_inc.alert_ids) == 4
    assert len(final_inc.timeline) == 4
    assert "Reconnaissance -> Initial Access -> Execution -> Command And Control" in final_inc.title


def test_temporal_window_expiration() -> None:
    """Asserts alerts outside the 4-hour window do not correlate together."""
    engine = AdvancedCorrelationEngine(time_window_hours=4)
    target = "srv-prod-api-01"
    now = datetime.now(UTC)

    # First alert 5 hours ago
    alert_old = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-NET-001",
        "rule_name": "TCP Port Sweep",
        "mitre_attack_id": "T1046",
        "severity": "medium",
        "target_host": target,
        "first_seen": (now - timedelta(hours=5)).isoformat(),
    }
    assert engine.process_alert(alert_old) is None

    # New alert now (5 hours later)
    alert_new = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-WEB-001",
        "rule_name": "SQL Injection",
        "mitre_attack_id": "T1190",
        "severity": "high",
        "target_host": target,
        "first_seen": now.isoformat(),
    }
    # Window expired, so alert_new resets the campaign and does not correlate with alert_old
    incident = engine.process_alert(alert_new)
    assert incident is None


def test_standalone_self_test_execution() -> None:
    """Asserts Module X7 self-test runner exits cleanly with code 0."""
    exit_code = run_self_test()
    assert exit_code == 0
