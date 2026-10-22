"""Unit Tests for Module X6: ML Anomaly Detection & UEBA Capability Module."""

from __future__ import annotations

from contracts.python.models import FindingContract
from modules.ml_detection.analyzer import (
    MLAnomalyDetector,
    PureIsolationForest,
    RollingZScoreTracker,
    calculate_shannon_entropy,
)
from modules.ml_detection.standalone import run_self_test


def test_shannon_entropy_calculation() -> None:
    """Asserts Shannon entropy distinguishes uniform tokens from high-entropy strings."""
    uniform = ["login", "login", "login", "login"]
    high_entropy = [f"token_{i}" for i in range(16)]

    ent_low = calculate_shannon_entropy(uniform)
    ent_high = calculate_shannon_entropy(high_entropy)

    assert ent_low == 0.0
    assert ent_high >= 3.8


def test_rolling_z_score_tracker() -> None:
    """Asserts rolling Welford tracker correctly flags statistical outliers."""
    tracker = RollingZScoreTracker(threshold_z=3.0)

    # Baseline 25 points of 50.0
    for _ in range(25):
        _, is_anomaly = tracker.update(50.0)
        assert not is_anomaly

    # Normal minor variation
    z, is_anomaly = tracker.update(52.0)
    assert not is_anomaly

    # Injected statistical anomaly
    z_spike, is_anomaly_spike = tracker.update(5000.0)
    assert is_anomaly_spike
    assert z_spike >= 3.0


def test_pure_isolation_forest_scoring() -> None:
    """Asserts PureIsolationForest assigns higher anomaly score to outliers."""
    forest = PureIsolationForest(n_trees=30, sub_sample_size=32, seed=123)
    baseline_cluster = [[1.0 + (i % 4) * 0.1, 1.0 + (i % 2) * 0.1, 1.0] for i in range(40)]
    forest.fit(baseline_cluster)

    normal_score = forest.score([1.02, 1.01, 1.0])
    outlier_score = forest.score([80.0, 95.0, 70.0])

    assert outlier_score > normal_score
    assert outlier_score >= 0.60


def test_ueba_off_hours_and_volume_finding() -> None:
    """Asserts MLAnomalyDetector detects off-hours access and volume spikes, emitting FindingContract."""
    detector = MLAnomalyDetector(seed=42)

    event = {
        "source_ip": "10.0.1.77",
        "target_host": "srv-prod-db-01",
        "event_time": "2026-10-20T02:30:00Z",  # Off-hours (02:30 UTC)
        "details": {"bytes_transferred": 20000000},
        "raw_payload": "DUMP TABLE confidential_records",
    }

    finding = detector.evaluate_telemetry(event)
    assert finding is not None
    assert isinstance(finding, FindingContract)
    assert finding.tool_name == "ml_anomaly_detector"
    assert finding.rule_id == "RULE-ML-ANOMALY"
    assert finding.severity in ("high", "critical")
    assert "Off-hours access" in finding.description
    assert finding.mitre_attack_id == "T1078"


def test_benign_business_hours_event() -> None:
    """Asserts normal business-hours event with low volume produces no finding."""
    detector = MLAnomalyDetector(seed=42)

    normal_event = {
        "source_ip": "10.0.1.88",
        "target_host": "srv-prod-app-01",
        "event_time": "2026-10-20T14:30:00Z",  # Business hours (14:30 UTC)
        "details": {"bytes_transferred": 100},
        "raw_payload": "GET /index.html",
    }

    finding = detector.evaluate_telemetry(normal_event)
    assert finding is None


def test_standalone_self_test_execution() -> None:
    """Asserts Module X6 self-test runner exits cleanly with code 0."""
    exit_code = run_self_test()
    assert exit_code == 0
