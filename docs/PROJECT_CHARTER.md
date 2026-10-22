# SentinelX Project Charter

## 1. Executive Summary & Vision

**SentinelX** is an autonomous, modular cybersecurity detection and incident response platform engineered around the complete security operations lifecycle:
$$\text{Collect} \longrightarrow \text{Detect} \longrightarrow \text{Correlate} \longrightarrow \text{Investigate} \longrightarrow \text{Prioritize} \longrightarrow \text{Respond} \longrightarrow \text{Report}$$

The platform addresses three fundamental deficiencies in traditional enterprise SIEM/SOAR platforms:
1. **Severe Alert Fatigue**: Raw security sensors emit millions of disjoint events daily. SentinelX introduces deterministic sliding-window detection, SHA-256 deduplication windows, and $N:1$ target-asset incident correlation.
2. **Brittle Cross-Module Coupling**: Monolithic security tools suffer from schema drift and tight coupling. SentinelX enforces **Strict Dependency Inversion (Law 1)** and **Immutable Contract Primacy (Law 2)** using dual-synced JSON Schemas (Draft-07), Pydantic v2 twins, and TypeScript interfaces.
3. **Audit Log Tampering & Repudiation**: Traditional relational logs are vulnerable to in-place manipulation by compromised accounts. SentinelX establishes a cryptographically chained, SHA-256 tamper-evident audit trail (**Law 4**) with verifiable sequence continuity.

---

## 2. Scope & Phase Boundaries

### Phase 1: SentinelX SOC Lite (Minor Scope) — Implemented
* **Architecture**: Single-process modular monolith (`--workers 1`, Law 5).
* **Core Modules (M1–M7)**:
  * **M1**: Identity, Access & Ingestion API Key Management (Bcrypt, PyJWT, Rate Limiting).
  * **M2**: CMDB Monitored Asset Inventory (Criticality Ratings, 3-Tier IP/Host Resolution).
  * **M3**: Multi-Source Telemetry Ingestion (Syslog, Combined Web Logs, JSON Telemetry, Asset Precedence).
  * **M4**: Sliding-Window Detection Engine (Declarative YAML rules with MITRE ATT&CK IDs: T1110, T1046, T1190).
  * **M5**: Alert Deduplication & Triage Queue (Deterministic SHA-256 deduplication, triage state machine).
  * **M6**: Incident Correlation & Closed-Form Risk Scoring (15-minute correlation window, $[0, 100]$ risk formula, auto-closure).
  * **M7**: Operational Reporting & KPI Engine (MTTD, severity distribution, executive Markdown debrief).
* **Cross-Cutting**:
  * Dual-Database Persistence: SQLite 3 for local dev/testing; PostgreSQL 16 for production (Law 3).
  * Tamper-Evident SHA-256 Hash Chained Audit Trail (Law 4).
  * React 18 + TypeScript + Tailwind CSS SOC Dashboard.

### Phase 2–8: Enterprise Scale & Autonomous Intelligence (Major Scope) — Pluggable
* Capability Modules **X1–X13** (Network, Endpoint, Vulnerability, Threat Intel, ML Anomaly, Complex Correlation, Risk Engine, Knowledge Graph, Digital Forensics, SOAR Playbooks, Cloud Security, AI Assistant).
* Distributed stream processing (Kafka/RabbitMQ) and multi-node advisory locking.

---

## 3. Core Academic & Research Questions

1. **Detection Accuracy & Latency**: Can a declarative YAML sliding-window engine achieve $>95\%$ Precision and Recall on benchmark attack vectors (Brute Force, Reconnaissance, Injection) with sub-second detection latency?
   * *Empirical Finding*: Achieved $100\%$ Precision, $100\%$ Recall, $1.000$ F1, and $\sim 212\text{ ms}$ latency on the labelled evaluation dataset.
2. **Incident Prioritization Determinism**: How does closed-form asset-weighted risk scoring compare to arbitrary heuristic rankings in reducing analyst cognitive load?
3. **Cryptographic Non-Repudiation**: What is the performance overhead of serialized SHA-256 hash chaining on database mutation throughput in single-node SOC architectures?

---

## 4. Platform Roles & Governance Matrix

| Role | Access Scope | Intended Persona |
|:---|:---|:---|
| **Admin** | Full platform control: user management, CMDB asset mutation, API key generation/revocation, audit verification. | SOC Director / Platform Engineer |
| **Analyst** | Read-write access to security telemetry: alert triage, incident investigation, notes, timeline analysis. | SOC Triage Analyst (L1/L2) |
| **Auditor** | Read-only access across all operational data, with dedicated access to cryptographic audit log inspection and verification. | Compliance Auditor / Oversight |
