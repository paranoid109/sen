# Knowledge Graph Capability Module (X8)

## 1. Overview
The **Knowledge Graph Capability Module (X8)** constructs and maintains a pure-Python in-memory directed multigraph of enterprise infrastructure, identities, access privileges, vulnerabilities, and active threat actors. It provides topological attack path analysis and blast radius simulation without requiring an external graph database server.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Operates as an independent graph modeling service decoupled from `backend/app/` (Core M1–M7) — conforms to **Law 1**.
* Ingests topological relations and emits structured findings conforming to `contracts/findings/finding_contract.json` (**Law 2**).
* Zero external binary or database dependencies — runs purely with standard library collections and algorithms.

## 3. Entity & Relationship Graph Schema
* **Nodes**:
  - `asset`: Monitored hosts, databases, and gateways with criticality tier.
  - `user`: Identity accounts with administrative privileges.
  - `vulnerability`: CVE IDs, CVSS ratings, and CISA KEV active status.
  - `threat_actor`: Adversary groups and threat campaigns (e.g. APT29).
  - `service`: Network listening daemons and ports.
* **Edges**:
  - `CONNECTS_TO`: Network reachability between infrastructure assets.
  - `AUTHENTICATED_TO`: User credentials active on hosts.
  - `HAS_VULNERABILITY`: Exploitable flaws present on assets.
  - `TARGETS`: Threat actors pursuing specific infrastructure assets.

## 4. Analytical Capabilities
* **Shortest Path to Crown Jewel**: Uses Dijkstra's algorithm to calculate the minimum lateral movement hops from an initial entry point to high-value assets (`db-prod-01`).
* **Transitive Blast Radius Calculation**: Evaluates breadth-first search reachability to quantify total exposed downstream assets and identities if a node is compromised.

## 5. CLI Usage & Verification (Law 6)
```bash
# Execute standalone self-test suite (evaluates attack paths, blast radius, and findings)
python -m modules.knowledge_graph.standalone --self-test

# Export full enterprise topology to JSON
python -m modules.knowledge_graph.standalone --export-json

# Compute blast radius for a specific host
python -m modules.knowledge_graph.standalone --blast-radius server-prod-01 --hops 2

# Compute shortest attack path between two entities
python -m modules.knowledge_graph.standalone --attack-path firewall-edge-01 db-prod-01
```
