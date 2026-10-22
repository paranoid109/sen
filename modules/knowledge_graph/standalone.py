"""Standalone CLI Runner for Knowledge Graph Capability Module (X8).

Supports offline topology queries, attack path calculation, blast radius analysis,
self-testing, and forwarding topology findings to SentinelX (Law 1, Law 2, Law 6).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from modules.knowledge_graph.analyzer import (
    KnowledgeGraphAnalyzer,
    SecurityKnowledgeGraph,
)


def run_self_test() -> int:
    """Executes built-in test suite asserting graph topology, attack paths, and blast radius."""
    print("[*] Running KnowledgeGraphAnalyzer (Module X8) self-test suite...")
    failures = 0

    graph = SecurityKnowledgeGraph.build_default_enterprise_graph()
    analyzer = KnowledgeGraphAnalyzer(graph=graph)

    # 1. Assert Node and Edge Counts
    node_count = len(graph.nodes)
    if node_count < 8:
        print(f"[-] Node count too low: {node_count} nodes found.")
        failures += 1
    else:
        print(f"  [PASS] Topology nodes initialized ({node_count} nodes: assets, identities, vulns).")

    # 2. Assert Shortest Attack Path to Crown Jewel
    path = graph.find_shortest_attack_path("firewall-edge-01", "db-prod-01")
    if not path or len(path) != 3:
        print(f"[-] Unexpected attack path: {path}")
        failures += 1
    else:
        path_str = " -> ".join([node.id for node, _ in path])
        print(f"  [PASS] Discovered 2-hop attack path to crown jewel: {path_str}")

    # 3. Assert Blast Radius Calculation
    blast = graph.calculate_blast_radius("server-prod-01", max_hops=2)
    if blast["reachable_nodes"] < 2 or blast["crown_jewels_at_risk"] < 1:
        print(f"[-] Blast radius calculation failed: {blast}")
        failures += 1
    else:
        print(f"  [PASS] Blast radius verified ({blast['reachable_nodes']} nodes, {blast['crown_jewels_at_risk']} crown jewel at risk).")

    # 4. Assert FindingContract Generation
    finding = analyzer.evaluate_compromised_asset("server-prod-01", "db-prod-01")
    if finding is None or finding.rule_id != "RULE-GRAPH-BLAST-RADIUS":
        print("[-] Failed to generate FindingContract from graph evaluation.")
        failures += 1
    else:
        print(f"  [PASS] Emitted FindingContract: {finding.rule_id} ({finding.severity})")

    if failures == 0:
        print("[+] Module X8 (Knowledge Graph Engine) Self-Test PASSED (4/4 checks clean).\n")
        return 0
    else:
        print(f"[-] Module X8 Self-Test FAILED ({failures} errors).\n")
        return 1


def forward_finding(finding: Any, ingest_url: str, api_key: str | None = None) -> bool:
    """Submits finding to SentinelX REST Ingest API."""
    import httpx

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload = {
        "source_ip": "192.168.1.1",
        "event_type": "graph_finding",
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
    parser = argparse.ArgumentParser(description="SentinelX Knowledge Graph & Attack Path Analyzer (X8)")
    parser.add_argument("--self-test", action="store_true", help="Execute built-in validation test suite")
    parser.add_argument("--export-json", action="store_true", help="Export topology graph to JSON format")
    parser.add_argument("--blast-radius", type=str, metavar="ASSET_ID", help="Calculate blast radius for asset")
    parser.add_argument("--attack-path", nargs=2, metavar=("SRC", "DST"), help="Compute shortest attack path")
    parser.add_argument("--evaluate", type=str, metavar="ASSET_ID", help="Evaluate asset finding and blast exposure")
    parser.add_argument("--hops", type=int, default=3, help="Max traversal hops (default: 3)")
    parser.add_argument("--forward", action="store_true", help="Forward detected findings to SentinelX Ingest API")
    parser.add_argument("--ingest-url", type=str, default="http://localhost:8000/api/v1", help="SentinelX API URL")
    parser.add_argument("--api-key", type=str, default=None, help="Optional X-API-Key header value")

    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    graph = SecurityKnowledgeGraph.build_default_enterprise_graph()
    analyzer = KnowledgeGraphAnalyzer(graph=graph)

    if args.evaluate:
        finding = analyzer.evaluate_compromised_asset(args.evaluate)
        if finding:
            print(json.dumps(finding.model_dump(mode="json"), indent=2))
            if args.forward:
                ok = forward_finding(finding, args.ingest_url, args.api_key)
                print(f"[*] Ingest API status: {'FORWARDED' if ok else 'FAILED'}")
        else:
            print(f"[*] No critical blast exposure finding emitted for {args.evaluate}")
        return 0

    if args.export_json:
        data = graph.export_topology()
        print(json.dumps(data, indent=2))
        return 0

    if args.blast_radius:
        blast = graph.calculate_blast_radius(args.blast_radius, max_hops=args.hops)
        print(json.dumps(blast, indent=2))
        if args.forward and blast.get("crown_jewels_at_risk", 0) > 0:
            finding = analyzer.evaluate_compromised_asset(args.blast_radius)
            if finding:
                ok = forward_finding(finding, args.ingest_url, args.api_key)
                print(f"[*] Ingest API status: {'FORWARDED' if ok else 'FAILED'}")
        return 0

    if args.attack_path:
        src, dst = args.attack_path
        path = graph.find_shortest_attack_path(src, dst)
        if not path:
            print(f"[-] No traversable path found between '{src}' and '{dst}'", file=sys.stderr)
            return 1
        path_nodes = [{"id": n.id, "label": n.label, "type": n.node_type} for n, _ in path]
        print(json.dumps({"source": src, "target": dst, "hops": len(path) - 1, "path": path_nodes}, indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
