"""Knowledge Graph & Attack Path Analysis Capability Module (X8).

Provides pure-Python in-memory directed multigraph representation of IT infrastructure,
identities, vulnerabilities, and threats, with Dijkstra/BFS shortest attack path
discovery to crown jewels and transitive blast radius calculation (Law 1, Law 2, Law 6).
"""

from __future__ import annotations

import collections
import heapq
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from contracts.python.models import FindingContract, SeverityLevel


@dataclass
class GraphNode:
    """Node in the SentinelX Knowledge Graph."""

    id: str
    label: str
    node_type: str  # "asset", "user", "vulnerability", "threat_actor", "service"
    properties: dict[str, Any] = field(default_factory=dict)
    is_crown_jewel: bool = False


@dataclass
class GraphEdge:
    """Directed edge in the SentinelX Knowledge Graph."""

    source_id: str
    target_id: str
    relation: str  # "CONNECTS_TO", "AUTHENTICATED_TO", "EXPOSES_SERVICE", "HAS_VULNERABILITY", "TARGETS"
    weight: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)


class SecurityKnowledgeGraph:
    """Pure-Python in-memory directed multigraph for cyber threat topology."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        # adjacency: source_id -> list of GraphEdge
        self._adj: dict[str, list[GraphEdge]] = collections.defaultdict(list)
        # reverse adjacency for inbound traversal
        self._rev_adj: dict[str, list[GraphEdge]] = collections.defaultdict(list)

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        properties: dict[str, Any] | None = None,
        is_crown_jewel: bool = False,
    ) -> GraphNode:
        """Adds or updates a node in the graph."""
        node = GraphNode(
            id=node_id,
            label=label,
            node_type=node_type,
            properties=properties or {},
            is_crown_jewel=is_crown_jewel,
        )
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        weight: float = 1.0,
        properties: dict[str, Any] | None = None,
    ) -> GraphEdge:
        """Adds a directed edge between two existing nodes."""
        if source_id not in self.nodes:
            raise KeyError(f"Source node '{source_id}' does not exist in graph")
        if target_id not in self.nodes:
            raise KeyError(f"Target node '{target_id}' does not exist in graph")

        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            weight=weight,
            properties=properties or {},
        )
        self._adj[source_id].append(edge)
        self._rev_adj[target_id].append(edge)
        return edge

    def get_neighbors(self, node_id: str) -> list[tuple[GraphNode, GraphEdge]]:
        """Returns outbound neighbors and connecting edges."""
        results: list[tuple[GraphNode, GraphEdge]] = []
        for edge in self._adj.get(node_id, []):
            if edge.target_id in self.nodes:
                results.append((self.nodes[edge.target_id], edge))
        return results

    def find_shortest_attack_path(
        self, source_id: str, target_id: str
    ) -> list[tuple[GraphNode, GraphEdge | None]] | None:
        """Computes shortest traversable attack path using Dijkstra's algorithm.

        Returns list of (node, edge_used) tuples or None if unreachable.
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        # Min-heap: (accumulated_cost, current_node_id)
        pq: list[tuple[float, str]] = [(0.0, source_id)]
        distances: dict[str, float] = {source_id: 0.0}
        predecessors: dict[str, tuple[str, GraphEdge]] = {}

        while pq:
            cost, u = heapq.heappop(pq)

            if u == target_id:
                break

            if cost > distances.get(u, float("inf")):
                continue

            for neighbor_node, edge in self.get_neighbors(u):
                v = neighbor_node.id
                alt = cost + edge.weight
                if alt < distances.get(v, float("inf")):
                    distances[v] = alt
                    predecessors[v] = (u, edge)
                    heapq.heappush(pq, (alt, v))

        if target_id not in distances:
            return None

        # Reconstruct path
        path: list[tuple[GraphNode, GraphEdge | None]] = []
        curr = target_id
        while curr != source_id:
            prev, edge = predecessors[curr]
            path.append((self.nodes[curr], edge))
            curr = prev
        path.append((self.nodes[source_id], None))
        path.reverse()
        return path

    def calculate_blast_radius(self, asset_id: str, max_hops: int = 3) -> dict[str, Any]:
        """Calculates transitive downstream blast radius (reachable assets and identities) via BFS."""
        if asset_id not in self.nodes:
            return {"reachable_nodes": 0, "crown_jewels_at_risk": 0, "impacted_entities": []}

        visited: set[str] = {asset_id}
        queue: collections.deque[tuple[str, int]] = collections.deque([(asset_id, 0)])

        impacted: list[dict[str, Any]] = []
        crown_jewels = 0

        while queue:
            curr_id, depth = queue.popleft()
            if depth >= max_hops:
                continue

            for neighbor_node, edge in self.get_neighbors(curr_id):
                nid = neighbor_node.id
                if nid not in visited:
                    visited.add(nid)
                    if neighbor_node.is_crown_jewel:
                        crown_jewels += 1
                    impacted.append({
                        "id": nid,
                        "label": neighbor_node.label,
                        "type": neighbor_node.node_type,
                        "depth": depth + 1,
                        "relation": edge.relation,
                        "is_crown_jewel": neighbor_node.is_crown_jewel,
                    })
                    queue.append((nid, depth + 1))

        return {
            "root_asset": asset_id,
            "max_hops": max_hops,
            "reachable_nodes": len(impacted),
            "crown_jewels_at_risk": crown_jewels,
            "impacted_entities": impacted,
        }

    def export_topology(self) -> dict[str, Any]:
        """Exports the graph in a format directly consumable by visualization frontends."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.node_type,
                    "is_crown_jewel": n.is_crown_jewel,
                    "properties": n.properties,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "relation": e.relation,
                    "weight": e.weight,
                    "properties": e.properties,
                }
                for edges in self._adj.values()
                for e in edges
            ],
        }

    @classmethod
    def build_default_enterprise_graph(cls) -> SecurityKnowledgeGraph:
        """Constructs canonical baseline enterprise topology matching SentinelX CMDB."""
        g = cls()

        # Monitored Infrastructure Assets (CMDB)
        g.add_node("firewall-edge-01", "Perimeter Gateway", "asset", {"ip": "192.168.1.1", "tier": "high"})
        g.add_node("server-prod-01", "Production Web/App", "asset", {"ip": "192.168.1.10", "tier": "high"})
        g.add_node("db-prod-01", "Core Production Database", "asset", {"ip": "192.168.1.20", "tier": "critical"}, is_crown_jewel=True)
        g.add_node("ws-eng-100", "Dev Workstation", "asset", {"ip": "192.168.1.100", "tier": "low"})

        # Identities / Users
        g.add_node("user:admin", "Domain Administrator", "user", {"role": "Admin", "privileged": True})
        g.add_node("user:developer", "Dev Engineer", "user", {"role": "Analyst", "privileged": False})

        # Known Vulnerabilities
        g.add_node("vuln:CVE-2023-44487", "HTTP/2 Rapid Reset", "vulnerability", {"cisa_kev": True, "cvss": 9.8})
        g.add_node("vuln:CVE-2021-44228", "Log4Shell RCE", "vulnerability", {"cisa_kev": True, "cvss": 10.0})

        # Known Threat Actor
        g.add_node("actor:APT29", "Cozy Bear (APT29)", "threat_actor", {"origin": "Nation-State", "sophistication": "high"})

        # Network & Topological Connections (Edges)
        g.add_edge("firewall-edge-01", "server-prod-01", "CONNECTS_TO", weight=1.0, properties={"ports": [80, 443]})
        g.add_edge("server-prod-01", "db-prod-01", "CONNECTS_TO", weight=1.5, properties={"ports": [5432]})
        g.add_edge("ws-eng-100", "server-prod-01", "CONNECTS_TO", weight=2.0, properties={"ports": [22]})

        # Identity Authentications
        g.add_edge("user:developer", "ws-eng-100", "AUTHENTICATED_TO", weight=0.5)
        g.add_edge("user:admin", "db-prod-01", "AUTHENTICATED_TO", weight=0.5)

        # Vulnerability Attachments
        g.add_edge("server-prod-01", "vuln:CVE-2023-44487", "HAS_VULNERABILITY", weight=1.0)
        g.add_edge("db-prod-01", "vuln:CVE-2021-44228", "HAS_VULNERABILITY", weight=1.0)

        # Threat Targeting
        g.add_edge("actor:APT29", "firewall-edge-01", "TARGETS", weight=1.0)

        return g


class KnowledgeGraphAnalyzer:
    """Coordinates graph analytics, attack path evaluations, and FindingContract emissions."""

    def __init__(self, graph: SecurityKnowledgeGraph | None = None) -> None:
        self.graph = graph or SecurityKnowledgeGraph.build_default_enterprise_graph()

    def evaluate_compromised_asset(
        self, asset_id: str, crown_jewel_id: str = "db-prod-01"
    ) -> FindingContract | None:
        """Evaluates blast radius and attack path from a compromised asset to a crown jewel."""
        path = self.graph.find_shortest_attack_path(asset_id, crown_jewel_id)
        blast = self.graph.calculate_blast_radius(asset_id, max_hops=3)

        if not path and blast["reachable_nodes"] == 0:
            return None

        hops = len(path) - 1 if path else -1
        path_str = " -> ".join([node.id for node, _ in path]) if path else "Unreachable"

        severity: SeverityLevel
        if blast["crown_jewels_at_risk"] > 0 or (0 <= hops <= 2):
            severity = "critical"
        elif blast["reachable_nodes"] >= 2 or hops == 3:
            severity = "high"
        else:
            severity = "medium"

        evidence = {
            "compromised_asset": asset_id,
            "crown_jewel_target": crown_jewel_id,
            "shortest_attack_path": path_str,
            "hop_count": hops,
            "blast_radius_reachable_nodes": blast["reachable_nodes"],
            "crown_jewels_at_risk": blast["crown_jewels_at_risk"],
            "impacted_entities": blast["impacted_entities"],
        }

        return FindingContract(
            finding_id=uuid.uuid4(),
            tool_name="knowledge_graph_analyzer",
            rule_id="RULE-GRAPH-BLAST-RADIUS",
            severity=severity,
            target=f"{asset_id} -> {crown_jewel_id}",
            description=(
                f"Attack path discovered from {asset_id} to crown jewel {crown_jewel_id} "
                f"({hops} hops; {blast['reachable_nodes']} downstream entities exposed)."
            ),
            evidence=evidence,
            timestamp=datetime.now(UTC),
            mitre_attack_id="T1021",
        )
