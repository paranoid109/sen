# SentinelX Platform Contracts Specification

This document defines the five immutable JSON contract schemas governing all data exchange between the Shared Core Platform (M1-M7) and pluggable capability extensions (X1-X13).

---

## 1. The Five Core Contracts

```
[ Log Sources / External Agents ]
             │
             ▼ (Ingest API / Ingest Schemas)
  ┌──────────────────────┐
  │   1. EventContract   │ ──► Published by Ingestion (M3) via In-Process Dispatcher
  └──────────────────────┘
             │
             ▼
  ┌──────────────────────┐
  │   2. FindingContract │ ──► Emitted by Standalone Capability Tools (e.g. Web Scanner)
  └──────────────────────┘
             │
             ▼
  ┌──────────────────────┐
  │   3. AlertContract   │ ──► Emitted by Detection Engine (M4) / Curated by Alerts (M5)
  └──────────────────────┘
             │
             ▼
  ┌──────────────────────┐
  │  4. IncidentContract │ ──► Correlated N:1 by Incidents & Correlation (M6)
  └──────────────────────┘
             │
             ▼
  ┌──────────────────────┐
  │   5. ActionContract  │ ──► Consumed by Notification Sinks / Future SOAR (X10)
  └──────────────────────┘
```

---

## 2. Mathematical Definitions & Formulas

### 2.1 Closed-Form Incident Risk Score Formula
The Incident risk score is deterministically computed from the properties of its correlated active alerts:
$$\text{RawScore} = \left(\max_{a \in \text{alerts}} \text{BaseScore}(a.\text{severity})\right) \times \text{AssetMultiplier} + (|\text{alerts}| - 1) \times 15 + \min\left(20, \sum_{a \in \text{alerts}} (a.\text{occurrence\_count} - 1) \times 2\right)$$
$$\text{RiskScore} = \min(100, \max(0, \text{round}(\text{RawScore})))$$

#### Complete Numeric Maps:
* **Alert BaseScore**:
  * `critical`: $40$
  * `high`: $25$
  * `medium`: $15$
  * `low`: $5$
* **Asset Multiplier**:
  * `critical`: $2.0$
  * `high`: $1.5$
  * `medium`: $1.2$
  * `low`: $1.0$ (unassigned or untracked assets default to $1.0$)
* **Multi-Alert Escalation Penalty**: $(|\text{alerts}| - 1) \times 15$
* **Recurrence Cap**: $\min\left(20, \sum (a.\text{occurrence\_count} - 1) \times 2\right)$ (capped strictly at $20$ points)

### 2.2 Alert Deduplication Key Specification
To prevent alert fatigue and duplicate ticket creation, alerts are deduplicated using a deterministic SHA-256 hash:
$$\text{dedup\_key} = \text{SHA256}\left(\text{rule\_id} \parallel \text{":"} \parallel (\text{target\_asset\_id} \lor \text{target\_host} \lor \text{"unassigned"}) \parallel \text{":"} \parallel (\text{source\_ip} \lor \text{"unknown"})\right)$$

* **Active Alert Condition**: An alert is active for deduplication while `status IN ('NEW', 'INVESTIGATING')`.
* **Deduplication Action**: When a new detection matches an active alert's `dedup_key`, the engine increments `occurrence_count`, updates `last_seen`, appends the new `event_id` to `evidence` (capped at 100), and triggers immediate incident risk score recalculation.

### 2.3 Detection Latency Metric
The end-to-end detection latency is calculated in seconds:
$$\text{Latency} = \max(0.0, (\text{alert.created\_at} - \text{triggering\_event.ingest\_time}).\text{total\_seconds}())$$

---

## 3. Incident Correlation Rules

1. **Target Asset Correlation Window**: $15\text{ minutes}$ ($900\text{ seconds}$). An incoming alert is aggregated into an existing open incident if the incident has the same `target_asset_id` and its last activity occurred within $15\text{ minutes}$.
2. **False-Positive Handling**: If an alert is updated to `status = 'FALSE_POSITIVE'`, it is excluded from the incident risk calculation and the incident risk score is recalculated immediately.
3. **Incident Auto-Closure**: If all alerts correlated with an incident reach status `RESOLVED` or `FALSE_POSITIVE`, the incident automatically transitions to `status = 'RESOLVED'`.
