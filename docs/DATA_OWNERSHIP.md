# SentinelX Data Ownership & Lifecycle Boundaries

This document defines the strict data ownership boundaries, mutability semantics, and lifecycle rules across all entities in the SentinelX platform.

---

## 1. Relational Table Ownership Matrix

In compliance with **Architectural Law 1 (Strict Dependency Inversion)** and **Law 4 (Tamper-Evident Hash Chaining)**, each database table is exclusively owned by a single domain service in the Shared Core Platform (`backend/app/services/`).

| Table Name | Owning Service | Direct Write Access | Read Access | Mutability Policy |
|:---|:---|:---|:---|:---|
| `users` | `AuthService` (M1) | `AuthService` | `AuthService`, `get_current_user` | Mutable (password updates, role adjustments, activation status). |
| `api_keys` | `AuthService` (M1) | `AuthService` | `AuthService`, `IngestionService` | Mutable (last used timestamps, revocation/deletion). Key secrets are hashed once. |
| `assets` | `AssetService` (M2) | `AssetService` | All Core Services | Mutable (hostname, IP, criticality tier, description). Mutations audited via Law 4. |
| `events` | `IngestionService` (M3) | `IngestionService` | `DetectionService`, `ReportService` | **Append-Only / Immutable**. Events are never updated or deleted once committed. |
| `alerts` | `AlertService` (M5) | `AlertService` | `IncidentService`, `ReportService`, Alerts API | Controlled Mutability. Active alerts (`NEW`/`INVESTIGATING`) increment occurrence count. Once closed, immutable. |
| `incidents` | `IncidentService` (M6) | `IncidentService` | `ReportService`, Incidents API | Mutable (status transitions, risk score recalculations). Mutations audited via Law 4. |
| `incident_alerts` | `IncidentService` (M6) | `IncidentService` | `IncidentService`, Incidents API | **Append-Only Join Table**. Associative links between incidents and correlated alerts. |
| `incident_timeline`| `IncidentService` (M6) | `IncidentService` | `IncidentService`, Incidents API | **Append-Only Chronological Log**. Records timeline entries (creation, correlation, updates). |
| `audit_logs` | `AuditService` (Law 4) | `AuditService` | `AuditService`, Audit API | **Append-Only Cryptographic Chain**. Serialized via `asyncio.Lock()`. Never mutated or deleted. |

---

## 2. Mutability & Retention Invariants

1. **Write-Once Telemetry (Events)**:
   * The `events` table serves as the immutable ground-truth telemetry log.
   * Telemetry events are persisted with UTC timestamps (`event_time`, `ingest_time`).
   * No application component is permitted to issue `UPDATE` or `DELETE` statements on the `events` table during normal operations.

2. **Controlled Deduplication Window (Alerts)**:
   * An incoming detection trigger computes `dedup_key = sha256(rule:asset:source_ip)`.
   * If an alert with this key is currently in status `NEW` or `INVESTIGATING`, it receives in-place updates: `occurrence_count` is incremented, `last_seen` is updated, and unique `evidence` IDs are merged (capped at 100).
   * Once an alert transitions to `RESOLVED` or `FALSE_POSITIVE`, it becomes immutable. Subsequent attacks generate a fresh alert.

3. **Tamper-Evident Hash Chain (Audit Logs)**:
   * Records are sequenced sequentially ($1, 2, 3, \dots, N$).
   * Every record embeds $H_{i-1}$ (`prev_hash`) and computes $H_i = \text{SHA256}(H_{i-1} \parallel \dots)$.
   * Any direct SQL modification or row deletion breaks the chain, causing `GET /api/v1/audit/verify` to report `is_valid: false`.

---

## 3. Capability Module Data Boundaries

* **No Direct Core Database Access**: Capability modules (`modules/*`) have zero write access to the central database tables.
* **Pluggable Persistence**: Capability modules may maintain their own local scratch stores, SQLite databases, or feature caches inside their respective module directories.
* **Contractual Egress**: Capability modules communicate results strictly by emitting JSON contract payloads (`FindingContract`, `EventContract`) via file export or HTTP POST to `/api/v1/events/ingest`.
