# SentinelX System Architecture Specification

## 1. Architectural Philosophy & Governing Laws

SentinelX is designed as a **Modular Monolith** for Phase 1 (Minor Scope) with strict contract-based plugin boundaries designed to transition seamlessly to distributed microservices in Phase 8 (Major Scope).

The codebase is governed by the Six Core Architectural Laws codified in `AGENTS.md`:
1. **Law 1: Strict Dependency Inversion & Module Boundaries**: Shared core platform (`backend/app/`, M1–M7) must **never** import from capability modules (`modules/`). Capability modules interact exclusively via immutable data contracts or REST APIs.
2. **Law 2: Immutable Contract Primacy**: Cross-module data transfers adhere to Draft-07 JSON Schemas (`contracts/`), Pydantic v2 twins (`contracts/python/models.py`), and TypeScript interfaces (`frontend/src/types/index.ts`).
3. **Law 3: Dual-Database Engine Compatibility**: Every query and model operates interchangeably on SQLite 3 (`aiosqlite`) and PostgreSQL 16 (`asyncpg`). Timestamps are normalized via custom `UTCDateTime` TypeDecorators. Time bounds are calculated in Python via `timedelta` bindings.
4. **Law 4: Tamper-Evident Hash Chaining**: All security mutations are written to a cryptographic SHA-256 hash chain with strict `asyncio.Lock` serialization.
5. **Law 5: Single-Worker Architecture (Minor Scope)**: Minor scope runs with `--workers 1` without multi-worker distributed lock managers or external broker clusters.
6. **Law 6: Standalone-First Verification**: Every capability and service is verified via unit tests, SQLite test harnesses, and offline benchmarks prior to containerized integration.

---

## 2. High-Level System Architecture

```mermaid
flowchart TD
    %% Presentation Tier
    UI["<b>SentinelX Unified Frontend (React 18 + TS + Vite)</b><br/>Dashboard (M7) | Alerts (M5) | Incidents (M6) | Assets (M2) | Audit (M1)"]
    GW["<b>FastAPI Perimeter Gateway</b><br/>JWT Authentication, RBAC Guard, Request Size Limiter"]
    UI -->|"HTTPS / REST API"| GW

    %% Core Platform
    subgraph CorePlatform ["Shared Core Platform (backend/app/)"]
        M1["<b>M1: Identity & Access</b><br/>Bcrypt, JWT, API Keys, Rate Limiter"]
        M2["<b>M2: CMDB Asset Inventory</b><br/>Criticality Tiers & Target Resolution"]
        Audit["<b>Platform Audit Service (Law 4)</b><br/>SHA-256 Tamper-Evident Hash Chain"]
        M7["<b>M7: Reporting & Metrics</b><br/>MTTD, Severity Breakdown, Executive Debrief"]
    end
    GW -.->|"Auth & Policy"| M1
    GW -.->|"Audit Trail"| Audit
    GW --> CorePlatform

    %% Ingestion & Event Dispatcher
    subgraph IngestionSubsystem ["Ingestion & Event Bus"]
        M3["<b>M3: Security Event Ingestion</b><br/>Syslog, Web Logs, JSON, Asset Precedence"]
        Dispatcher{{"<b>In-Process Event Dispatcher</b><br/>Strong Task Anchoring, drain() Sync Hook"}}
    end
    GW --> M3
    M3 -->|"EventContract"| Dispatcher

    %% Detection, Alerting & Correlation
    subgraph PipelineSubsystem ["Detection, Alert Triage & Incident Engine"]
        M4["<b>M4: Sliding-Window Detection</b><br/>YAML Rules + MITRE IDs (T1110, T1046, T1190)"]
        M5["<b>M5: Alert Management</b><br/>SHA-256 Dedup Window, Triage Lifecycle"]
        M6["<b>M6: Incident Correlation</b><br/>15m Asset Correlation, [0, 100] Risk Score"]
    end
    Dispatcher -->|"Normalized Event Stream"| M4
    M4 -->|"Trigger Alert"| M5
    M2 -.->|"Asset Criticality Multiplier"| M6
    M5 -->|"Correlate Alert"| M6
    M5 -.->|"Triage Mutations"| Audit
    M6 -.->|"Status & Timeline"| Audit

    %% Egress & Extensions
    Notif["<b>Notification Sink (M6/M7)</b><br/>Post-Commit Webhook & Console Alert"]
    M6 -->|"Incident Created"| Notif

    subgraph PluggableCapabilities ["Pluggable Major Capabilities (modules/)"]
        X1["X1: Web Security Analyzer (SQLi CLI)"]
        X_other["X2-X13: Network, ML, Threat Intel, SOAR"]
    end
    X1 -->|"POST /events/ingest"| GW
    X_other -.->|"Contract Interface"| GW

    %% Persistence
    subgraph Storage ["Dual Persistence Layer"]
        ORM["<b>SQLAlchemy 2.0 Async ORM</b><br/>UTCDateTime TypeDecorator, Partial Unique Indexes"]
        DB[("<b>Database</b><br/>PostgreSQL 16 (Prod) | SQLite 3 (Dev/Test)")]
    end
    CorePlatform --> ORM
    M5 --> ORM
    M6 --> ORM
    Audit --> ORM
    ORM --> DB
```

---

## 3. Data Flow & Transaction Boundaries

1. **Ingest Phase**: Client submits telemetry via `POST /api/v1/events/ingest`. If authenticated with an `ApiKey` bound to an `asset_id`, the bound asset strictly overrides payload claims. The event is persisted to the `events` table and committed.
2. **Post-Commit Dispatch**: After transaction commit, the event is serialized into an immutable `EventContract` and published to `EventDispatcher.dispatch()`. Subscribers execute in asynchronous background tasks tracked in a strong reference set.
3. **Sliding-Window Rule Evaluation**: `DetectionService` calculates temporal boundaries in Python (`window_start = event.event_time - timedelta(seconds=rule.window_seconds)`) and executes standard parameter-bound queries across the sliding window.
4. **Deterministic Alert Deduplication**: If a rule threshold is met, `AlertService` hashes `sha256(rule_id:asset:source_ip)`. If an active alert (`NEW` or `INVESTIGATING`) exists, its counter and evidence IDs (capped at 100) are updated with `with_for_update()`. Otherwise, a new alert is created.
5. **Asset-Centric Correlation & Closed-Form Risk Scoring**: `IncidentService` searches for open incidents on the same target asset updated within the last 15 minutes (900 seconds). Correlated incidents recalculate their closed-form risk score:
   $$\text{RawScore} = \left(\max_{a \in \text{alerts}} \text{BaseScore}(a.\text{severity})\right) \times \text{AssetMultiplier} + (|\text{alerts}| - 1) \times 15 + \min\left(20, \sum_{a \in \text{alerts}} (a.\text{occurrence\_count} - 1) \times 2\right)$$
   $$\text{RiskScore} = \min(100, \max(0, \text{round}(\text{RawScore})))$$
6. **Tamper-Evident Audit Logging**: State transitions across authentication, assets, alerts, and incidents are recorded sequentially through `AuditService.log_action()` protected by `asyncio.Lock()`.
