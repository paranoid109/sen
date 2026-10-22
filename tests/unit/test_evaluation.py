"""Unit and Integration Tests for Evaluation Tooling and Benchmarking (Step 7).

Validates the integrity of the ground-truth labelled evaluation dataset,
mathematical correctness of confusion matrix metrics, offline execution harness,
and event generation logic of attack simulators.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.schemas.events import SingleIngestRequest
from scripts.evaluate import CategoryMetrics, EvaluationHarness
from scripts.simulate_bruteforce import generate_bruteforce_event
from scripts.simulate_portscan import generate_connection_event
from scripts.simulate_sqli import SQLI_PAYLOADS, generate_sqli_event

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
DATASET_PATH = FIXTURES_DIR / "labelled_evaluation_dataset.json"


def test_evaluation_dataset_schema_and_integrity() -> None:
    """Validates the schema, labels, and event integrity of the evaluation dataset."""
    assert DATASET_PATH.exists(), f"Evaluation dataset missing at {DATASET_PATH}"

    with open(DATASET_PATH, encoding="utf-8") as f:
        data = json.load(f)

    metadata = data.get("metadata", {})
    assert "version" in metadata
    assert "scenario_count" in metadata
    assert "total_events" in metadata

    scenarios = data.get("scenarios", [])
    assert len(scenarios) == metadata["scenario_count"]
    assert sum(len(s.get("events", [])) for s in scenarios) == metadata["total_events"]

    source_ips = set()
    for s in scenarios:
        assert "scenario_id" in s
        assert "category" in s
        assert s["label"] in ["benign", "attack"]
        assert "source_ip" in s
        assert (
            s["source_ip"] not in source_ips
        ), f"Duplicate source IP {s['source_ip']} across scenarios"
        source_ips.add(s["source_ip"])

        if s["label"] == "attack":
            assert s["expected_rule_id"] is not None
        else:
            assert s["expected_rule_id"] is None

        events = s.get("events", [])
        assert len(events) > 0
        for ev in events:
            assert ev["source_ip"] == s["source_ip"]
            assert "event_type" in ev
            assert "event_time" in ev

            # Verify SingleIngestRequest model validation
            req = SingleIngestRequest(
                source_ip=ev["source_ip"],
                destination_ip=ev.get("destination_ip"),
                destination_port=ev.get("destination_port"),
                source_port=ev.get("source_port"),
                event_type=ev["event_type"],
                target_host=ev.get("target_host"),
                raw_payload=ev.get("raw_payload"),
                details=ev.get("details", {}),
            )
            assert req.source_ip == ev["source_ip"]


def test_category_metrics_math_and_edge_cases() -> None:
    """Validates Precision, Recall, F1, Specificity, and Latency math."""
    # 1. Pure attack category with perfect detection
    cat_perfect = CategoryMetrics(
        name="attack_perfect",
        rule_id="RULE-TEST-001",
        true_positives=10,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
        latencies_ms=[100.0, 200.0, 300.0],
    )
    assert cat_perfect.precision == 1.0
    assert cat_perfect.recall == 1.0
    assert cat_perfect.f1_score == 1.0
    assert cat_perfect.mean_latency_ms == 200.0

    # 2. Category with false positives and false negatives
    cat_imperfect = CategoryMetrics(
        name="attack_mixed",
        rule_id="RULE-TEST-002",
        true_positives=8,
        false_positives=2,
        false_negatives=2,
    )
    # Precision = 8 / (8 + 2) = 0.80
    assert cat_imperfect.precision == 0.80
    # Recall = 8 / (8 + 2) = 0.80
    assert cat_imperfect.recall == 0.80
    # F1 = 2 * (0.8 * 0.8) / (0.8 + 0.8) = 0.80
    assert pytest.approx(cat_imperfect.f1_score, 0.001) == 0.80

    # 3. Pure benign category (no positives)
    cat_benign = CategoryMetrics(
        name="benign_noise",
        rule_id=None,
        true_positives=0,
        false_positives=0,
        true_negatives=5,
        false_negatives=0,
    )
    assert cat_benign.precision == 1.0
    assert cat_benign.recall == 1.0
    assert cat_benign.f1_score is None
    assert cat_benign.specificity == 1.0

    # 4. Zero division handling
    cat_empty = CategoryMetrics(name="empty", rule_id=None)
    assert cat_empty.precision == 0.0
    assert cat_empty.recall == 0.0
    assert cat_empty.f1_score is None
    assert cat_empty.mean_latency_ms == 0.0


@pytest.mark.asyncio
async def test_offline_evaluation_harness_benchmark() -> None:
    """Executes the full offline evaluation harness and verifies >= 90% benchmark performance."""
    harness = EvaluationHarness(dataset_path=DATASET_PATH)
    categories = await harness.run_offline_evaluation()

    total_tp = sum(c.true_positives for c in categories.values())
    total_fp = sum(c.false_positives for c in categories.values())
    total_tn = sum(c.true_negatives for c in categories.values())
    total_fn = sum(c.false_negatives for c in categories.values())

    denom_p = total_tp + total_fp
    overall_precision = (total_tp / denom_p) if denom_p > 0 else 1.0
    denom_r = total_tp + total_fn
    overall_recall = (total_tp / denom_r) if denom_r > 0 else 1.0
    overall_f1 = (
        (2 * overall_precision * overall_recall / (overall_precision + overall_recall))
        if (overall_precision + overall_recall) > 0
        else 0.0
    )

    # Benchmark assertions (17 attack scenarios across 13 rules + 8 benign baseline scenarios)
    assert total_tp == 17, f"Expected 17 true positives, got {total_tp}"
    assert total_fp == 0, f"Expected 0 false positives, got {total_fp}"
    assert total_tn == 8, f"Expected 8 true negatives, got {total_tn}"
    assert total_fn == 0, f"Expected 0 false negatives, got {total_fn}"
    assert overall_precision == 1.0
    assert overall_recall == 1.0
    assert overall_f1 == 1.0


def test_simulator_event_generators() -> None:
    """Verifies that simulator payload generators produce valid, serializable payloads."""
    from scripts.simulate_dns_tunneling import generate_dns_tunnel_event
    from scripts.simulate_endpoint_tamper import generate_fim_event, generate_lolbas_event

    # 1. SSH Brute Force
    bf_event = generate_bruteforce_event(
        target_host="server-prod-01",
        target_ip="192.168.1.10",
        attacker_ip="192.168.1.100",
        username="admin",
        port_idx=1,
    )
    assert bf_event["event_type"] == "auth_failed"
    assert bf_event["destination_port"] == 22
    assert "admin" in bf_event["raw_payload"]
    SingleIngestRequest(**bf_event)

    # 2. Port Scan
    ps_event = generate_connection_event(
        target_host="server-prod-01",
        target_ip="192.168.1.10",
        scanner_ip="192.168.1.200",
        port=80,
        idx=1,
    )
    assert ps_event["event_type"] == "connection"
    assert ps_event["destination_port"] == 80
    SingleIngestRequest(**ps_event)

    # 3. SQL Injection
    sqli_event = generate_sqli_event(
        target_host="server-prod-01",
        target_ip="192.168.1.10",
        attacker_ip="192.168.1.150",
        payload_info=SQLI_PAYLOADS[0],
        idx=1,
    )
    assert sqli_event["event_type"] == "web_request"
    assert sqli_event["destination_port"] == 80
    assert "UNION SELECT" in sqli_event["details"]["uri"]
    SingleIngestRequest(**sqli_event)

    # 4. DNS Tunneling (Phase 2)
    dns_event = generate_dns_tunnel_event(
        target_host="server-prod-01",
        target_ip="192.168.1.10",
        source_ip="192.168.1.155",
        query="a9f82d1c0042e88b9021a8f9001bca2d3345.data.exfil-dns.org",
    )
    assert dns_event["event_type"] == "network_finding"
    assert dns_event["destination_port"] == 53
    SingleIngestRequest(**dns_event)

    # 5. Endpoint FIM & LOLBAS (Phase 2)
    fim_event = generate_fim_event(
        target_host="server-prod-01",
        source_ip="10.0.1.88",
        tampered_file="/etc/sudoers",
    )
    assert fim_event["event_type"] == "endpoint_finding"
    SingleIngestRequest(**fim_event)

    lolbas_event = generate_lolbas_event(
        target_host="server-prod-01",
        source_ip="10.0.1.88",
        cmd_type="powershell",
    )
    assert lolbas_event["event_type"] == "endpoint_finding"
    SingleIngestRequest(**lolbas_event)


def test_unified_campaign_simulator_event_generation() -> None:
    """Verifies that simulate_campaign.py produces valid SingleIngestRequest models for all scenarios."""
    from scripts.simulate_campaign import SCENARIO_CHOICES, build_events_for_scenario

    for scenario in SCENARIO_CHOICES:
        events = build_events_for_scenario(scenario)
        assert len(events) > 0, f"Scenario {scenario} yielded 0 events"
        for ev in events:
            req = SingleIngestRequest(**ev)
            assert req.source_ip == ev["source_ip"]
            assert req.event_type == ev["event_type"]

