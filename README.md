# 🛡️ SentinelX: Modular Cybersecurity Platform

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.13-3776AB.svg?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141.1-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react)](https://react.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC.svg?logo=tailwind-css)](https://tailwindcss.com)

SentinelX is an enterprise cybersecurity operations platform engineered around the complete security lifecycle:
$$\text{Collect} \longrightarrow \text{Detect} \longrightarrow \text{Correlate} \longrightarrow \text{Investigate} \longrightarrow \text{Prioritize} \longrightarrow \text{Respond} \longrightarrow \text{Report}$$

---

## 1. Architectural Overview

SentinelX is constructed as a **modular monolith** with clear architectural boundaries. Phase 1 (Minor Project) implements the complete Security Operations Center (SOC) baseline:

* **M1: Identity & Access Management**: JWT authentication, bcrypt password hashing, role-based access control (`Admin`, `Analyst`, `Auditor`), and login brute-force rate limiting.
* **M2: Asset Management**: CMDB inventory of monitored infrastructure, IP/hostname mapping, and asset criticality ratings (`critical`, `high`, `medium`, `low`).
* **M3: Security Event Ingestion**: High-throughput REST Ingestion API (`POST /api/v1/events/ingest`), Linux `auth.log` parser, connection attempts parser, and web access log normalizer.
* **M4: Detection Engine**: Declarative YAML detection rules with MITRE ATT&CK mapping (`T1110` Brute Force, `T1046` Port Scan, `T1190` SQL Injection) evaluating index-backed sliding windows.
* **M5: Alert Management & Triage**: Alert deduplication via partial unique index, evidence array aggregation, and state machine (`NEW` $\to$ `INVESTIGATING` $\to$ `RESOLVED` / `FALSE_POSITIVE`).
* **M6: Incident & Correlation Management**: $N:1$ target-asset alert correlation within 15-minute windows, event timeline reconstruction, and closed-form bounded risk scoring ($0–100$).
* **M7: Reporting & Metrics Engine**: Live SOC KPI metrics and automated Markdown/HTML executive debrief reports.
* **Platform Audit Service**: Cryptographically verifiable, SHA-256 hash-chained tamper-evident audit trail (`GET /api/v1/audit/verify`).
* **Unified Frontend**: React 18 + TypeScript + Tailwind CSS dark-mode analyst dashboard.

---

## 2. Quickstart Guide (Local Development)

### Prerequisites
* **Python 3.13+** (AMD64 / x86_64)
* **Node.js v20+** and npm v10+

### Installation & Setup

1. **Clone repository and configure environment**:
   ```bash
   git clone https://github.com/your-org/sentinelx.git
   cd sentinelx
   cp .env.example .env
   ```

2. **Set up Python Virtual Environment**:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r backend/requirements.txt -r backend/requirements-dev.txt
   ```

4. **Seed Database (SQLite local dev)**:
   ```bash
   python scripts/seed_db.py
   ```

5. **Run FastAPI Backend**:
   ```bash
   uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```

6. **Start React Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open `http://localhost:5173` in your browser. Default Admin credentials: `admin` / `Admin@SentinelX2026!`.

---

## 3. Running with Docker Compose (Production Setup)

```bash
docker compose up -d --build
```
* **Frontend**: `http://localhost:5173`
* **Backend API & Swagger Docs**: `http://localhost:8000/docs`
* **Health Check**: `http://localhost:8000/health`

---

## 4. Verification & Testing

```bash
# 1. Run all unit tests (11 test files on SQLite)
pytest tests/unit/ -v

# 2. Run the end-to-end integration pipeline test
pytest tests/integration/test_soc_pipeline.py -v

# 3. Test standalone capability module runner
python -m modules.web_security.standalone --test

# 4. Run offline academic evaluation benchmark
python scripts/evaluate.py

# 5. Security audit dependencies (0 vulnerabilities)
pip-audit

# 6. Lint code
ruff check .
```

---

## 5. License

Apache License 2.0. See [LICENSE](LICENSE) for details.
