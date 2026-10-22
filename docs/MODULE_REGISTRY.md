# SentinelX Authoritative Module Registry

This document serves as the single source of truth for all 20 architectural modules within the SentinelX cybersecurity platform.

---

## 1. Core Platform Modules (M1–M7) — Minor Scope

The Core Platform modules reside in `backend/app/` and form the foundation of SentinelX.

| ID | Module Name | Scope | Directory | Primary Responsibilities | Consumes | Emits |
|:---|:---|:---:|:---|:---|:---|:---|
| **M1** | Identity & Access Management | Phase 1 | `backend/app/services/auth_service.py` | Bcrypt password hashing, PyJWT issuance, login rate limiting via indexed audit log queries, and ingestion API key hashing/lifecycle. | Login requests, UserCreate payloads | JWT tokens, User models, ApiKey hashes |
| **M2** | CMDB Asset Management | Phase 1 | `backend/app/services/asset_service.py` | Monitored asset inventory, criticality tiers (critical, high, medium, low), and 3-tier target resolution (ID $\to$ hostname $\to$ IP). | Asset attributes, CMDB registrations | Asset ORM rows, criticality context |
| **M3** | Security Event Ingestion | Phase 1 | `backend/app/services/ingestion_service.py` | Syslog, Combined Web log, and JSON connection parsers; API key asset binding precedence enforcement; post-commit event dispatching. | Raw telemetry streams, Ingest REST API | `Event` ORM rows, `EventContract` |
| **M4** | Sliding-Window Detection | Phase 1 | `backend/app/services/detection_service.py` | Declarative YAML rule engine evaluating sliding temporal windows via Python timedelta bindings; distinct field and regex pattern matching. | `EventContract` stream | Triggered Alert definitions |
| **M5** | Alert Management & Triage | Phase 1 | `backend/app/services/alert_service.py` | Deterministic SHA-256 deduplication windows, `with_for_update()` locking, evidence list capping (100 items), and triage state machine. | Detection triggers | `Alert` ORM rows, `AlertContract`, Audit mutations |
| **M6** | Incident & Correlation Management | Phase 1 | `backend/app/services/incident_service.py` | 15-minute asset correlation window, closed-form bounded risk scoring ($[0, 100]$), timeline recording, auto-closure, notification dispatch. | `Alert` instances | `Incident` ORM rows, `IncidentContract`, `ActionContract` |
| **M7** | Reporting & Operational Engine | Phase 1 | `backend/app/services/report_service.py` | Operational telemetry aggregation (active alerts, open incidents, assets, MTTD latency) and formatted Markdown executive security debriefs. | Database state queries | Dashboard metrics, Executive debriefs |

---

## 2. Pluggable Capability Modules (X1–X13) — Major Scope

Capability modules reside in `modules/` and remain strictly decoupled from the Shared Core Platform (**Law 1**).

| ID | Module Name | Phase | Directory | Primary Capabilities | Input Contract | Output Contract |
|:---|:---|:---:|:---|:---|:---|:---|
| **X1** | Web Security Analyzer | Phase 1 | `modules/web_security/` | Web access log scanning, SQL injection exploit detection (CWE-89, T1190), standalone CLI mode and REST forwarding. | Raw web access logs, HTTP URIs | `FindingContract`, `EventContract` |
| **X2** | Network Security Analyzer | Phase 2 | `modules/network_security/` | Deep packet inspection (DPI), flow protocol analysis, TCP/UDP port sweep detection, DNS tunneling inspection. | PCAP files, NetFlow, Zeek/Suricata logs | `FindingContract`, `EventContract` |
| **X3** | Endpoint Security Monitor | Phase 2 | `modules/endpoint_security/` | Host-based monitoring, process creation tracking, file integrity monitoring (FIM), privilege escalation detection. | Auditd, Sysmon, osquery event streams | `FindingContract`, `EventContract` |
| **X4** | Vulnerability Management | Phase 3 | `modules/vulnerability_management/` | Asset exposure mapping, CVE database matching, CVSS scoring, patch prioritization. | Vulnerability scan exports (Nessus, OpenVAS) | `FindingContract` |
| **X5** | Threat Intelligence Feeds | Phase 3 | `modules/threat_intelligence/` | STIX/TAXII threat feed consumption, IOC parsing, malicious IP/domain/hash reputation enrichment. | External threat feeds (AlienVault, MISP) | IOC enrichment lookups, `FindingContract` |
| **X6** | ML Anomaly Detection | Phase 4 | `modules/ml_detection/` | Unsupervised behavioral baseline analytics, Isolation Forests, statistical outlier scoring across event streams. | Aggregated event histories | `FindingContract` |
| **X7** | Advanced Correlation Engine | Phase 4 | `modules/correlation/` | Multi-stage attack kill-chain reconstruction, cross-asset lateral movement tracking, temporal graph sequencing. | `AlertContract` stream | `IncidentContract` (Multi-stage kill-chain clusters) |
| **X8** | Knowledge Graph Engine | Phase 5 | `modules/knowledge_graph/` | In-memory directed multigraph, Dijkstra shortest attack path discovery to Crown Jewels, transitive BFS blast-radius calculation. | Asset inventory, finding relations | `FindingContract` (`RULE-GRAPH-BLAST-RADIUS`, `T1021`), Graph JSON topologies |
| **X9** | Dynamic Risk Engine | Phase 5 | `modules/risk_engine/` | Multi-factor quantitative risk scoring incorporating asset criticality multipliers, threat velocity, CISA KEV, and topological blast exposure. | Asset CMDB tiers, alerts, CISA KEV, graph reachability | `FindingContract` (`RULE-RISK-DYNAMIC-ESCALATION`, `T1190`), Dynamic risk breakdown $[0, 100]$ |
| **X10** | SOAR Playbook Engine | Phase 6 | `modules/soar/` | Automated containment execution (firewall IP blocks, endpoint quarantine, account disablement) with approval gates and reversible rollbacks. | `ActionContract` (types: `block_ip`, `isolate_host`, `disable_user`) | `ActionContract` (status: `COMPLETED` / `FAILED`), `ContainmentDirective` |
| **X11** | Digital Forensics Triage | Phase 6 | `modules/forensics/` | Automated volatile artifact triage, memory capture orchestration, disk artifact preservation for high-severity incidents. | Triggered `IncidentContract` / target host | `FindingContract` (`RULE-FORENSICS-TRIAGE-001`, `T1059.004`), `ForensicTriagePackage` with Merkle Root SHA-256 seal |
| **X12** | Cloud Security Posture (CSPM) | Phase 7 | `modules/cloud_security/` | Multi-cloud control plane auditing (AWS IAM, S3, Azure NSGs, GCP IAM), CIS benchmark evaluation. | Cloud audit logs (CloudTrail, Stackdriver) | `FindingContract` |
| **X13** | GenAI SOC Analyst Assistant | Phase 7 | `modules/ai_assistant/` | Natural language incident briefing, query synthesis, contextual investigative recommendations. | Incident context, alert evidence | Analyst executive briefs, response guidance |
