"""Unit Tests for Module X8: Knowledge Graph & Attack Path Analyzer."""

from __future__ import annotations

from contracts.python.models import FindingContract, SeverityLevel
from modules.knowledge_graph.analyzer import (
    KnowledgeGraphAnalyzer,
    SecurityKnowledgeGraph,
)
from modules.knowledge_graph.standalone import run_self_test


def test_default_enterprise_graph_structure() -> None:
    """Asserts default enterprise graph initializes with expected nodes, edges, and crown jewel."""
    g = SecurityKnowledgeGraph.build_default_enterprise_graph()

    assert "server-prod-01" in g.nodes
    assert "db-prod-01" in g.nodes
    assert g.nodes["db-prod-01"].is_crown_jewel is True
    assert g.nodes["server-prod-01"].is_crown_jewel is False

    neighbors = g.get_neighbors("server-prod-01")
    neighbor_ids = [n.id for n, _ in neighbors]
    assert "db-prod-01" in neighbor_ids


def test_shortest_attack_path_dijkstra() -> None:
    """Asserts Dijkstra correctly finds the 2-hop attack path from edge to crown jewel."""
    g = SecurityKnowledgeGraph.build_default_enterprise_graph()
    path = g.find_shortest_attack_path("firewall-edge-01", "db-prod-01")

    assert path is not None
    assert len(path) == 3
    node_sequence = [node.id for node, _ in path]
    assert node_sequence == ["firewall-edge-01", "server-prod-01", "db-prod-01"]


def test_unreachable_node_attack_path() -> None:
    """Asserts unreachable nodes return None without throwing exceptions."""
    g = SecurityKnowledgeGraph.build_default_enterprise_graph()
    g.add_node("isolated-node-99", "Isolated Airgap Host", "asset")

    path = g.find_shortest_attack_path("isolated-node-99", "db-prod-01")
    assert path is None


def test_blast_radius_calculation() -> None:
    """Asserts BFS blast radius calculation discovers downstream reachable entities."""
    g = SecurityKnowledgeGraph.build_default_enterprise_graph()
    blast = g.calculate_blast_radius("server-prod-01", max_hops=2)

    assert blast["root_asset"] == "server-prod-01"
    assert blast["reachable_nodes"] >= 2
    assert blast["crown_jewels_at_risk"] >= 1
    impacted_ids = [e["id"] for e in blast["impacted_entities"]]
    assert "db-prod-01" in impacted_ids


def test_evaluate_compromised_asset_finding() -> None:
    """Asserts analyzer emits a valid FindingContract when evaluating a compromised asset."""
    analyzer = KnowledgeGraphAnalyzer()
    finding = analyzer.evaluate_compromised_asset("server-prod-01", "db-prod-01")

    assert finding is not None
    assert isinstance(finding, FindingContract)
    assert finding.tool_name == "knowledge_graph_analyzer"
    assert finding.rule_id == "RULE-GRAPH-BLAST-RADIUS"
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.evidence["crown_jewels_at_risk"] >= 1
    assert finding.evidence["hop_count"] == 1


def test_standalone_self_test_execution() -> None:
    """Asserts Module X8 self-test runner exits cleanly with code 0."""
    exit_code = run_self_test()
    assert exit_code == 0
