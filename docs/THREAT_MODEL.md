# SentinelX Platform Threat Model (STRIDE Methodology)

This document presents a comprehensive STRIDE threat modeling analysis of the SentinelX platform across its data ingestion, detection, triage, and audit subsystems.

---

## 1. System Trust Boundaries & Data Flow

```text
Untrusted Network (Attackers, Ingestion Agents, Web Browsers)
                     │
═════════════════════╪══════════════════════════════════════════════════ [TRUST BOUNDARY 1: Perimeter]
                     ▼
         FastAPI Perimeter Gateway
         • RequestSizeLimitMiddleware (1 MB)
         • JWT Bearer & Ingestion API Key Authenticator
         • Role-Based Access Control (Admin / Analyst / Auditor)
                     │
═════════════════════╪══════════════════════════════════════════════════ [TRUST BOUNDARY 2: Core Platform]
                     ▼
         In-Process Event Dispatcher & Domain Services (M1–M7)
         • Ingestion Service (API Key Asset Binding Precedence)
         • Detection Service (Declarative YAML Rule Engine)
         • Alert & Incident Services (Bounded Risk Formulas)
                     │
═════════════════════╪══════════════════════════════════════════════════ [TRUST BOUNDARY 3: Persistence]
                     ▼
         Persistence & Cryptographic Audit
         • SQLAlchemy 2.0 ORM with UTCDateTime
         • AuditService (SHA-256 Hash Chained Trail with asyncio.Lock)
         • PostgreSQL 16 (Prod) / SQLite 3 (Dev/Test)
```

---

## 2. STRIDE Analysis & Implemented Countermeasures

### 2.1 Spoofing (Identity Deception)
* **Threat S1: Telemetry Asset Spoofing**: A compromised or rogue agent submits telemetry claiming to be a high-value domain controller (`server-dc-01`) to trigger false alarms or misdirect investigations.
  * **Countermeasure**: **API Key Asset Binding Precedence Rule** (`docs/SECURITY_MODEL.md`). If an `ApiKey` has an assigned `asset_id`, any body-level `asset_id` or `target_host` claim is discarded in favor of the authenticated key's bound asset.
* **Threat S2: JWT Token Forgery**: An adversary crafts arbitrary JWT tokens with `"role": "Admin"`.
  * **Countermeasure**: Signed with HMAC-SHA256 using a strong `JWT_SECRET`. Production mode fails closed upon startup if default or short (<32 character) secrets are detected (`backend/app/core/config.py`).

### 2.2 Tampering (Data Modification)
* **Threat T1: Mass Assignment & Parameter Injection**: An attacker injects unauthorized fields (e.g. `{"risk_score": 0}` or `{"status": "RESOLVED"}`) in ingestion payloads.
  * **Countermeasure**: All data models configure `model_config = ConfigDict(extra="forbid")` paired with JSON Schema `additionalProperties: false` (Law 2), rejecting unvetted attributes immediately.
* **Threat T2: Audit Log Record Modification**: A rogue administrator modifies historic audit entries to conceal malicious actions.
  * **Countermeasure**: **Tamper-Evident SHA-256 Hash Chaining** (Law 4). Each entry embeds $H_{i-1}$ and computes $H_i = \text{SHA256}(H_{i-1} \parallel \dots)$. Any in-place modification invalidates all subsequent entries and is flagged by `GET /api/v1/audit/verify`.

### 2.3 Repudiation (Denial of Action)
* **Threat R1: Analyst Denies Triage Action**: An analyst suppresses an alert or marks an incident false positive and later claims they did not take the action.
  * **Countermeasure**: `AlertService.triage_alert()` and `IncidentService.update_incident()` require authenticated JWT credentials and automatically record actor identity, old state, new state, and notes to the tamper-evident audit log.

### 2.4 Information Disclosure (Data Leakage)
* **Threat I1: XSS Token Persistence in Web Browsers**: Injected malicious scripts read persistent JWT credentials from `localStorage`.
  * **Countermeasure**: JWT tokens are stored strictly in `sessionStorage` (mitigating multi-tab leakage and persistence across browser closes). The React frontend escapes dynamic text, and Nginx serves strict Content Security Policy (`CSP`) headers.
* **Threat I2: Credential Exposure in Database**: Database leaks expose user passwords and ingestion API keys in plaintext.
  * **Countermeasure**: Passwords are saved as one-way Bcrypt hashes. API keys are generated with random 256-bit entropy, and only their SHA-256 hashes (`key_hash`) are stored.

### 2.5 Denial of Service (Resource Exhaustion)
* **Threat D1: HTTP Request Body Flooding**: Transmitting gigantic payloads to crash the ASGI server via out-of-memory errors.
  * **Countermeasure**: `RequestSizeLimitMiddleware` intercepts requests and terminates bodies exceeding 1 MB with `HTTP 413 Payload Too Large`.
* **Threat D2: Authentication Flood & Audit Table Exhaustion**: An adversary fires millions of bad logins to exhaust database storage via audit logs.
  * **Countermeasure**: Dual-threshold rate limiting in `AuthService`. When failed attempts exceed 5 per 15-minute window for a client IP or username, the gateway returns `HTTP 429 Too Many Requests` without writing to the audit table.
* **Threat D3: Memory Exhaustion via Alert Evidence Arrays**: An attacker triggers an alert with millions of event IDs to bloat memory.
  * **Countermeasure**: Evidence ID lists are strictly capped at 100 items in both the Pydantic model (`max_length=100`) and `AlertService`.

### 2.6 Elevation of Privilege (Unauthorized Capability)
* **Threat E1: Auditor Initiates Incident Triage**: A read-only Auditor calls `PATCH /api/v1/alerts/{id}/triage` to alter platform state.
  * **Countermeasure**: Endpoints are protected by `require_role(["Admin", "Analyst"])` dependency factories, rejecting unauthorized roles with `HTTP 403 Forbidden`.
