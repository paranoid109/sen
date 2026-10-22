# Digital Forensics Triage Capability Module (X11)

## 1. Overview
The **Digital Forensics Triage Capability Module** coordinates automated evidence acquisition, volatile memory triage, disk artifact preservation, and legal chain-of-custody verification during high-severity incidents.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Operates as a completely pluggable capability module without core platform imports.
* Triggered in response to high-severity incidents or analyst execution requests.
* Produces `contracts/python/models.py` `FindingContract` telemetry and cryptographic evidence manifests.
* Computes deterministic Merkle Root SHA-256 signatures ensuring verifiable, tamper-evident chains of custody (**Law 4**).

## 3. Triage Capabilities
* **Volatile Memory Preservation**:
  - Live process hierarchy acquisition (PID, PPID, executable path, command lines, resident memory RSS).
  - Reverse shell and malicious command syntax heuristic detection (`/bin/bash -i`, `nc -e`, Python socket payloads).
  - Active network socket mapping with suspicious port detection (`4444`, `1337`, `31337`).
* **Disk Artifact Acquisition**:
  - Shell execution history analysis (`.bash_history`, `.zsh_history`, PowerShell history).
  - Security authentication log extraction (`/var/log/auth.log`, failed SSH logins, unauthorized `sudo` executions).
  - File Integrity Monitoring (FIM) SHA-256 fingerprinting across critical system configurations (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`).
* **Forensic Evidence Packaging & Chain of Custody**:
  - Structured JSON evidence bundle with artifact manifest.
  - Deterministic Merkle Root SHA-256 hash calculated over all individual artifact checksums.
  - Verifiable evidence seal suitable for legal and regulatory compliance.

## 4. Standalone CLI Usage
```bash
# Run verification self-test suite
python modules/forensics/standalone.py --self-test

# Acquire full forensics bundle for an endpoint
python modules/forensics/standalone.py --target srv-prod-01 --collect all

# Export sealed forensic package to JSON
python modules/forensics/standalone.py --target srv-prod-01 --export-json evidence_srv_prod_01.json

# Forward forensic finding directly to SentinelX Ingest REST API
python modules/forensics/standalone.py --target srv-prod-01 --forward --ingest-url http://localhost:8000/api/v1/events/ingest
```

## 5. Contract Conformance
Produces `contracts/findings/finding_contract.json`:
* `tool_name`: `"DigitalForensicsCollector"`
* `rule_id`: `"RULE-FORENSICS-TRIAGE-001"`
* `mitre_attack_id`: `"T1059.004"` (Command and Scripting Interpreter: Unix Shell)
* `severity`: `"critical"` / `"high"` / `"medium"`
