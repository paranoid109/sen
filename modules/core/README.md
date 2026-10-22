# Shared Core Platform Specification (`backend/app/`)

## 1. Overview & Architectural Role

The **Shared Core Platform** comprises Modules **M1 through M7** located in `backend/app/`:
* **M1**: Identity, Access, and API Key Management (`services/auth_service.py`)
* **M2**: CMDB Asset Management & Target Resolution (`services/asset_service.py`)
* **M3**: Multi-Source Telemetry Ingestion (`services/ingestion_service.py`)
* **M4**: Sliding-Window Detection Rule Engine (`services/detection_service.py`)
* **M5**: Alert Deduplication & Triage Queue (`services/alert_service.py`)
* **M6**: Incident Correlation & Closed-Form Risk Scoring (`services/incident_service.py`)
* **M7**: Operational Reporting & Executive Debriefs (`services/report_service.py`)
* **Cross-Cutting**: Tamper-Evident SHA-256 Audit Trail (`services/audit_service.py`)

---

## 2. Dependency Inversion Boundary (Architectural Law 1)

In strict accordance with **Law 1**:
> **The Shared Core Platform (`backend/app/`) MUST NEVER import from capability modules (`modules/`).**

```text
               Shared Core Platform (backend/app/)
                                │
                  [Strict Dependency Boundary]
                                │
                                ▼
         Pluggable Capability Modules (modules/X1 - X13)
```

### Communication Protocol
* Capability modules may import public immutable contract models (`contracts/python/models.py`).
* Capability modules may submit normalized security telemetry via the public HTTP Ingest API (`POST /api/v1/events/ingest` or `/batch`).
* Capability modules may operate in complete standalone isolation (e.g. offline CLI tool execution) without requiring the Shared Core Platform to run.
