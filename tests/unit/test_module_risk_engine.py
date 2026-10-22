"""Unit Tests for Module X9: Dynamic Risk Engine."""

from __future__ import annotations

from contracts.python.models import FindingContract, SeverityLevel
from modules.risk_engine.analyzer import DynamicRiskEngine
from modules.risk_engine.standalone import run_self_test


def test_low_risk_baseline() -> None:
    """Asserts low-criticality asset with low alert severity produces low risk score."""
    engine = DynamicRiskEngine()
    result = engine.calculate_risk(
        asset_id="ws-eng-100",
        asset_criticality="low",
        highest_alert_severity="low",
        alert_count=1,
        has_cisa_kev=False,
    )

    # Base: 5.0 * 0.8 = 4.0; Velocity: 0; Exploit: 0; Blast: 0 -> 4
    assert result.risk_score == 4
    assert result.risk_tier == SeverityLevel.LOW
    assert result.base_severity_score == 5.0
    assert result.criticality_multiplier == 0.8
    assert result.threat_velocity_factor == 0.0
    assert result.exploitability_factor == 0.0
    assert result.blast_radius_factor == 0.0


def test_critical_risk_score_capping() -> None:
    """Asserts multi-factor escalation caps at 100 and assigns critical tier."""
    engine = DynamicRiskEngine()
    result = engine.calculate_risk(
        asset_id="db-prod-01",
        asset_criticality="critical",
        highest_alert_severity="critical",
        alert_count=10,
        has_cisa_kev=True,
        crown_jewel_exposed=True,
    )

    # Base: 35.0 * 2.0 = 70.0; Velocity: min(20, 27) = 20.0; Exploit: 25.0; Blast: 20.0
    # Sum: 70 + 20 + 25 + 20 = 135 -> capped at 100
    assert result.risk_score == 100
    assert result.risk_tier == SeverityLevel.CRITICAL
    assert len(result.recommendations) >= 3


def test_threat_velocity_scaling() -> None:
    """Asserts threat velocity scales with alert count and caps at 20.0."""
    engine = DynamicRiskEngine()

    # 1 alert -> velocity 0.0
    r1 = engine.calculate_risk("srv-01", alert_count=1)
    assert r1.threat_velocity_factor == 0.0

    # 4 alerts -> velocity (4-1)*3 = 9.0
    r4 = engine.calculate_risk("srv-01", alert_count=4)
    assert r4.threat_velocity_factor == 9.0

    # 10 alerts -> (10-1)*3 = 27.0 -> capped at 20.0
    r10 = engine.calculate_risk("srv-01", alert_count=10)
    assert r10.threat_velocity_factor == 20.0


def test_exploitability_factors() -> None:
    """Asserts CISA KEV and CVSS thresholds influence exploitability correctly."""
    engine = DynamicRiskEngine()

    # CISA KEV active -> 25.0
    r_kev = engine.calculate_risk("srv-01", has_cisa_kev=True)
    assert r_kev.exploitability_factor == 25.0

    # CVSS >= 9.0 -> 25.0
    r_cvss9 = engine.calculate_risk("srv-01", cvss_score=9.8)
    assert r_cvss9.exploitability_factor == 25.0

    # CVSS >= 7.0 -> 15.0
    r_cvss7 = engine.calculate_risk("srv-01", cvss_score=7.5)
    assert r_cvss7.exploitability_factor == 15.0

    # Low CVSS -> 0.0
    r_cvss5 = engine.calculate_risk("srv-01", cvss_score=5.2)
    assert r_cvss5.exploitability_factor == 0.0


def test_topological_blast_factor() -> None:
    """Asserts crown jewel exposure triggers max blast factor while reachable nodes scale up to 15.0."""
    engine = DynamicRiskEngine()

    # Crown jewel exposed -> max 20.0
    r_cj = engine.calculate_risk("srv-01", crown_jewel_exposed=True, reachable_nodes=1)
    assert r_cj.blast_radius_factor == 20.0

    # 2 reachable nodes -> 2 * 2.5 = 5.0
    r_nodes2 = engine.calculate_risk("srv-01", crown_jewel_exposed=False, reachable_nodes=2)
    assert r_nodes2.blast_radius_factor == 5.0

    # 8 reachable nodes -> 8 * 2.5 = 20.0 -> capped at 15.0
    r_nodes8 = engine.calculate_risk("srv-01", crown_jewel_exposed=False, reachable_nodes=8)
    assert r_nodes8.blast_radius_factor == 15.0


def test_evaluate_to_finding_contracts() -> None:
    """Asserts evaluate_to_finding emits FindingContract for high/critical risks and None for low."""
    engine = DynamicRiskEngine()

    # Low risk -> None
    low_finding = engine.evaluate_to_finding(
        asset_id="ws-eng-100",
        asset_criticality="low",
        highest_alert_severity="low",
        alert_count=1,
    )
    assert low_finding is None

    # Critical risk -> FindingContract with T1190 when CISA KEV present
    crit_finding = engine.evaluate_to_finding(
        asset_id="server-prod-01",
        asset_criticality="critical",
        highest_alert_severity="critical",
        alert_count=5,
        has_cisa_kev=True,
    )
    assert crit_finding is not None
    assert isinstance(crit_finding, FindingContract)
    assert crit_finding.tool_name == "dynamic_risk_engine"
    assert crit_finding.rule_id == "RULE-RISK-DYNAMIC-ESCALATION"
    assert crit_finding.severity == SeverityLevel.CRITICAL
    assert crit_finding.mitre_attack_id == "T1190"

    # High risk without CISA KEV -> FindingContract with T1071
    high_finding = engine.evaluate_to_finding(
        asset_id="server-prod-01",
        asset_criticality="high",
        highest_alert_severity="high",
        alert_count=6,
        has_cisa_kev=False,
        reachable_nodes=4,
    )
    assert high_finding is not None
    assert high_finding.severity == SeverityLevel.HIGH
    assert high_finding.mitre_attack_id == "T1071"


def test_standalone_self_test_execution() -> None:
    """Asserts Module X9 self-test runner exits cleanly with code 0."""
    exit_code = run_self_test()
    assert exit_code == 0
