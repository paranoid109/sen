# Web Security Capability Module (X1)

## Overview
The Web Security Capability Module is a decoupled, pluggable security inspection component designed to detect web application exploits, with primary focus on SQL Injection attacks (CWE-89, MITRE ATT&CK `T1190`).

In compliance with **Architectural Law 1 (Strict Dependency Inversion)**, this module is decoupled from the Shared Core Platform:
* It **never** imports internal backend services (`backend.app.services`).
* It interacts exclusively with data contracts (`contracts.python.models`) or through the public Ingest REST API (`POST /api/v1/events/ingest`).

## Dual Operational Modes (Decision S8)

### 1. Standalone Mode (Offline Analysis)
In standalone mode, the tool runs independently via CLI or scheduled audit jobs without requiring a running SentinelX backend:
* Reads access logs or URI payloads directly from disk or standard input.
* Parses detection patterns from `backend/app/rules/sql_injection.yaml` as the single canonical source of truth.
* Emits strongly typed `FindingContract` JSON objects conforming to `contracts/findings/finding_contract.json`.

```powershell
# Run built-in self-test verification
python -m modules.web_security.standalone --test

# Scan a web server access log file
python -m modules.web_security.standalone --file /var/log/nginx/access.log
```

### 2. Integrated Mode (Telemetry Forwarding)
When integrated with a live SentinelX deployment:
* Extracts raw HTTP telemetry from web logs.
* Forwards normalized events to the core ingest API:
  `POST /api/v1/events/ingest` (or `/api/v1/events/batch`).
* The central platform (M3 $\to$ M4 $\to$ M5 $\to$ M6) evaluates sliding windows, deduplicates alerts, and aggregates incidents without duplicate alerting.

```powershell
# Forward scanned web events to SentinelX backend
python -m modules.web_security.standalone --file /var/log/nginx/access.log --ingest-url http://localhost:8000/api/v1/events/ingest
```

## Contract Conformance
Outputs generated in standalone mode conform to `FindingContract`:
* `finding_id`: UUID string
* `tool_name`: `"web_security"`
* `severity`: `"high"` (or according to pattern)
* `confidence`: `"high"`
* `title`: `"SQL Injection Exploit Pattern Detected"`
* `cwe_id`: `"CWE-89"`
* `mitre_attack_id`: `"T1190"`
* `target`: Target host or URI
* `details`: Matching pattern, raw payload, source IP
