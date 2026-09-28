# SentinelX Platform Security Model & RBAC

This document outlines the security architecture, Role-Based Access Control (RBAC) permissions matrix, API key scoping model, and web security defenses enforced across SentinelX.

---

## 1. Role-Based Access Control (RBAC) Matrix

SentinelX defines three explicit security roles:
1. **Admin**: Full platform control, user administration, API key generation, asset inventory management, and incident triage.
2. **Analyst**: Active security operations, alert triage, incident investigation, notes appending, and report generation.
3. **Auditor**: Read-only compliance auditor with access to historical logs, reports, and cryptographic audit trail verification.

| Route / Capability | Method | Admin | Analyst | Auditor | Unauthenticated |
|:---|:---:|:---:|:---:|:---:|:---:|
| `POST /api/v1/auth/login` | POST | Allow | Allow | Allow | Allow |
| `GET /api/v1/auth/me` | GET | Allow | Allow | Allow | Deny (401) |
| `POST /api/v1/auth/register` | POST | Allow (or Admin only) | Deny (403) | Deny (403) | Deny (403) |
| `POST /api/v1/auth/api-keys` | POST | Allow | Deny (403) | Deny (403) | Deny (401) |
| `GET /api/v1/auth/api-keys` | GET | Allow | Deny (403) | Deny (403) | Deny (401) |
| `DELETE /api/v1/auth/api-keys/{id}` | DELETE | Allow | Deny (403) | Deny (403) | Deny (401) |
| `GET /api/v1/assets` | GET | Allow | Allow | Allow | Deny (401) |
| `POST /api/v1/assets` | POST | Allow | Deny (403) | Deny (403) | Deny (401) |
| `PUT /api/v1/assets/{id}` | PUT | Allow | Deny (403) | Deny (403) | Deny (401) |
| `DELETE /api/v1/assets/{id}` | DELETE | Allow | Deny (403) | Deny (403) | Deny (401) |
| `POST /api/v1/events/ingest` | POST | Allow (Key/JWT) | Allow (Key/JWT) | Deny (403) | Key Only |
| `POST /api/v1/events/batch` | POST | Allow (Key/JWT) | Allow (Key/JWT) | Deny (403) | Key Only |
| `GET /api/v1/alerts` | GET | Allow | Allow | Allow | Deny (401) |
| `PATCH /api/v1/alerts/{id}/triage`| PATCH | Allow | Allow | Deny (403) | Deny (401) |
| `GET /api/v1/incidents` | GET | Allow | Allow | Allow | Deny (401) |
| `GET /api/v1/incidents/{id}` | GET | Allow | Allow | Allow | Deny (401) |
| `PATCH /api/v1/incidents/{id}` | PATCH | Allow | Allow | Deny (403) | Deny (401) |
| `GET /api/v1/reports/metrics` | GET | Allow | Allow | Allow | Deny (401) |
| `GET /api/v1/reports/executive` | GET | Allow | Allow | Allow | Deny (401) |
| `GET /api/v1/audit` | GET | Allow | Deny (403) | Allow | Deny (401) |
| `GET /api/v1/audit/verify` | GET | Allow | Allow | Allow | Deny (401) |

---

## 2. Ingestion API Key Scoping & Precedence

1. **Storage**: Ingestion API keys are stored as cryptographic SHA-256 hashes in the `ApiKey` database table. Raw keys are never stored.
2. **Asset Binding Precedence**:
   * If an `ApiKey` has a non-null `asset_id`, that key is permanently bound to that monitored asset (e.g. an agent installed on `web-prod-01`).
   * **Security Rule**: Any `asset_id` or `target_host` provided in the HTTP request body by an asset-bound key is **strictly ignored**. The event's `target_asset_id` is forced to the key's bound asset.
   * Only an unbound global key (`asset_id IS NULL`, e.g. a centralized syslog collector key) is permitted to specify `asset_id` or `target_host` in the request body.

---

## 3. Web & Session Security Rationale

* **Token Storage (`sessionStorage`)**:
  * Storing JWT tokens in browser `sessionStorage` completely prevents Cross-Site Request Forgery (CSRF) without requiring double-submit cookie mechanics between the frontend (port 5173) and backend API (port 8000).
  * Tokens are destroyed automatically when the browser tab is closed.
* **XSS Defense**:
  * React's JSX automatically escapes all dynamic content, preventing script injection.
  * `dangerouslySetInnerHTML` is prohibited.
  * Production Nginx headers enforce `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';`.
