# SentinelX Development Roadmap & Phased Execution Plan

## 1. Roadmap Architecture Overview

The SentinelX development lifecycle is structured into eight distinct phases, advancing from a verified, self-contained **Modular Monolith (Phase 1 Minor Scope)** to an **Enterprise Distributed Multi-Agent Platform (Phase 8)**.

```text
Phase 1 (Minor)  ──► Phase 2-4 (Sensors & AI) ──► Phase 5-7 (SOAR & Cloud) ──► Phase 8 (Enterprise)
Core M1-M7 & X1       Network, Endpoint, ML         Knowledge Graph, SOAR,        Distributed Brokers,
Modular Monolith      Anomaly, Threat Intel          Cloud Security, Assistant     Multi-Worker Cluster
```

---

## 2. Phase Breakdown & Milestones

### Phase 1: SentinelX SOC Lite (Minor Project) — [STATUS: COMPLETED]
* **Objective**: Deliver a production-grade, end-to-end security operations platform adhering to the complete lifecycle ($\text{Collect} \to \text{Report}$).
* **Delivered Components**:
  * Shared Core Modules **M1–M7**: Identity (M1), CMDB Assets (M2), Ingestion (M3), Sliding-Window Detection (M4), Alert Deduplication (M5), Incident Correlation (M6), Reporting Engine (M7).
  * Web Security Capability Module (**X1**): SQLi analyzer with standalone CLI and integrated ingest modes.
  * Tamper-evident cryptographic SHA-256 audit log (**Law 4**).
  * Dual-database persistence (SQLite 3 / PostgreSQL 16, **Law 3**).
  * Dark-themed React 18 + TypeScript + Tailwind CSS SOC console.
  * Labelled ground-truth evaluation benchmark ($100\%$ Precision/Recall, F1: $1.000$).
  * Docker Compose container orchestration.

### Phase 2: Host & Network Telemetry Expansion — [STATUS: COMPLETED]
* **Objective**: Introduce high-throughput packet and endpoint telemetry streaming.
* **Delivered Capability Modules**:
  * `modules/network_security/` (X2): Pure-Python PCAP parser, Zeek JSON stream reader, Shannon entropy DNS tunneling detection (`T1071.004`), port sweeping (`T1046`), and C2 beaconing jitter variance (`T1071`).
  * `modules/endpoint_security/` (X3): Linux Auditd (`type=EXECVE`) and Windows Sysmon JSON parser, LOLBAS & reverse shell detection (`T1059.001`, `T1059.004`, `T1105`, `T1548.003`), and persistent SHA-256 FIM baseline state tracking (`T1565.001`).
* **Contract Integration**: Strict conformance to `contracts/findings/finding_contract.json` and `contracts/events/event_contract.json`.

### Phase 3: Vulnerability & Threat Intelligence Integration — [STATUS: COMPLETED]
* **Objective**: Enrich incoming telemetry with proactive vulnerability posture and global threat feeds.
* **Delivered Capability Modules**:
  * `modules/threat_intelligence/` (X5): Multi-format IOC feed parser (STIX 2.1 JSON Bundles, MISP JSON exports, CSV blocklists), TTL indicator aging/expiration, and real-time telemetry cross-referencing.
  * `modules/vulnerability_management/` (X4): Trivy scan JSON & CycloneDX SBOM parser, CISA Known Exploited Vulnerabilities (KEV) detection, and CMDB asset criticality risk escalation.
* **Core Detection Expansion**: Declarative YAML rules added for `RULE-TI-001` and `RULE-VULN-001`, fully verified in live PostgreSQL container.

### Phase 4: Machine Learning Anomaly Detection & Behavioral Analytics — [STATUS: COMPLETED]
* **Objective**: Complement declarative YAML rules with unsupervised and semi-supervised anomaly detection.
* **Delivered Capability Modules**:
  * `modules/ml_detection/` (X6): Pure-Python unsupervised outlier detection, rolling Welford Z-score volume tracking, dynamic Shannon entropy calculation, and PureIsolationForest multidimensional scoring.
  * `modules/correlation/` (X7): Complex Event Processing (CEP) and Directed Acyclic Graph (DAG) state tracking, MITRE ATT&CK 4-stage kill-chain reconstruction (Recon -> Initial Access -> Execution -> C2), bounded risk scoring ($[0, 100]$), and temporal sliding windows.
* **Console Enhancement**: Red Team Attack Simulator & Scenario Lab (`SimulationModal.tsx`) integrated into React frontend header for one-click telemetry scenario injection.

### Phase 5: Knowledge Graph & Advanced Risk Scoring Engine — [STATUS: COMPLETED]
* **Objective**: Transition asset and threat relationships into a dynamic graph and provide multi-factor quantitative risk analytics.
* **Delivered Capability Modules**:
  * `modules/knowledge_graph/` (X8): Pure-Python in-memory directed multigraph, Dijkstra shortest attack path computation to Crown Jewels, transitive BFS blast radius calculation, and FindingContract emissions (`RULE-GRAPH-BLAST-RADIUS`, MITRE ATT&CK `T1021`).
  * `modules/risk_engine/` (X9): Multi-factor quantitative risk scoring formula factoring asset criticality multipliers ($0.8\times - 2.0\times$), threat velocity, CISA KEV exploitability, and topological blast exposure, with closed-form $[0, 100]$ bounds and FindingContract emissions (`RULE-RISK-DYNAMIC-ESCALATION`).
* **Console Enhancement**:
  * Interactive SVG Attack Path & Blast Radius Topology Visualizer (`TopologyGraph.tsx`) mounted in the Monitored CMDB Asset view with view toggling, Dijkstra critical path animations, BFS blast radius simulation, and live multi-factor dynamic risk breakdown cards.


### Phase 6: SOAR Automated Containment & Digital Forensics — [STATUS: COMPLETED]
* **Objective**: Execute autonomous and analyst-approved active containment workflows with reversible rollbacks and automated digital forensics evidence acquisition.
* **Delivered Capability Modules**:
  * `modules/soar/` (X10): Active containment playbook engine with multi-platform firewall commands (`iptables`, `nftables`, Windows `netsh advfirewall`), host quarantine with preserved SOC management channels (ports 8000, 22), account suspension (`usermod -L`, `pkill`, token revocation), automatic reversible rollback commands, critical infrastructure whitelist guardrails (`127.0.0.1`, `::1`, `192.168.1.1`, `root`, `sentinelx`), and CLI standalone runner (`--self-test`, `--playbook`, `--forward`).
  * `modules/forensics/` (X11): Automated digital forensics acquisition engine capturing volatile memory (process trees, reverse shells, active sockets), disk artifacts (shell history, `/var/log/auth.log` tail, FIM SHA-256 hashes of critical configs), sealed with deterministic Merkle Root SHA-256 chain of custody, and `FindingContract` emissions (`RULE-FORENSICS-TRIAGE-001`, `T1059.004`).
* **Core Platform & Console Integration**:
  * Incident Service (M6) enhanced with `POST /api/v1/incidents/{incident_id}/timeline` recording containment actions to the chronological audit timeline and tamper-evident SHA-256 audit hash chain (**Law 4**).
  * Interactive SOAR Playbook Modal & Execution Drawer (`SOARPlaybookModal.tsx`) mounted in the React SOC console under "Incident Response & Containment" with pre-flight command inspection, rollback preview, real-time guardrail alerts, and one-click sealed forensics package JSON download.

### Phase 7: Cloud Infrastructure Security & GenAI SOC Assistant — [STATUS: COMPLETED]
* **Objective**: Multi-cloud posture visibility, CIS Benchmark compliance auditing, and interactive natural language triage assistance.
* **Delivered Capability Modules**:
  * `modules/cloud_security/` (X12): Multi-cloud control plane security posture management (CSPM) for AWS CloudTrail, GCP Cloud Audit, and Azure Activity Logs. Evaluates against CIS Multi-Cloud Benchmarks (CIS AWS 3.0, CIS GCP 2.0, CIS Azure 2.0), detects S3 bucket public access (`T1530`), IAM wildcard privilege escalation (`T1098`), root console logins without MFA (`T1078.004`), open security group/NSG ingress (`T1046`), and produces `FindingContract` records. CLI runner supports `--audit-file`, `--cis-benchmark`, `--forward`, and `--self-test`.
  * `modules/ai_assistant/` (X13): Interactive GenAI SOC Analyst Copilot engine. Synthesizes multi-alert incident timelines into structured executive debriefs, provides alert triage advisory with confidence scoring and rationale, translates natural language inquiries into SentinelX REST API query parameters, and maps MITRE ATT&CK techniques to CIS Controls v8 and MITRE D3FEND defensive countermeasures. CLI runner supports `--incident-file`, `--triage-alert`, `--query`, and `--self-test`.
* **Core Platform & Console Integration**:
  * Added declarative YAML detection rule `backend/app/rules/cloud_misconfiguration.yaml` (`RULE-CLOUD-001`).
  * Updated ground-truth evaluation benchmark to 25 scenarios, achieving $100\%$ precision, $100\%$ recall, and $F_1 = 1.000$ across all 13 detection rules.
  * Dedicated Cloud Security Posture Management console (`CloudSecurity.tsx`, `/cloud`) with multi-cloud KPI score cards, CIS benchmark controls breakdown, and expandable remediation guidance.
  * Interactive AI SOC Copilot Drawer & Modal (`AICopilotModal.tsx`) integrated into global header navigation and incident response views for 1-click executive debrief synthesis and natural language filtering.


### Phase 8: Enterprise Scale & Distributed Architecture
* **Objective**: Decompose modular monolith into distributed microservices where load requires.
* **Architectural Transformations**:
  * In-process dispatcher transitioned to Apache Kafka or RabbitMQ clusters.
  * Single-worker `asyncio.Lock` audit logging transitioned to PostgreSQL distributed advisory locking or a dedicated sequencer microservice.
  * Distributed caching via Redis and horizontal worker scaling.
