# Advanced Multi-Stage Correlation Engine Capability Module (X7)

## 1. Overview
The **Advanced Multi-Stage Correlation Engine (X7)** models end-to-end cyber attack kill-chains across multi-hour sliding time windows. By correlating alerts from diverse sensors (network, host, web, threat intel) into a unified Directed Acyclic Graph (DAG), it discovers complex campaigns that bypass single-rule sliding windows.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Strictly decoupled from `backend/app/` (Core M1–M7) — conforms to **Law 1**.
* Ingests `AlertContract` streams and emits correlated meta-incidents conforming to `contracts/incidents/incident_contract.json` (**Law 2**).
* Evaluates complex stateful event processing (CEP) and temporal graph linkages.

## 3. MITRE ATT&CK Kill-Chain Mapping
The engine maps incoming security alerts into four canonical kill-chain stages:
1. **Reconnaissance** (`T1046`, `T1595` / `RULE-NET-001` Port Scanning)
2. **Initial Access & Credential Access** (`T1110` Brute Force, `T1190` SQL Injection / KEV Exploits)
3. **Execution & Defense Evasion** (`T1059` LOLBAS execution, `T1565` File Integrity Tampering)
4. **Command & Control / Exfiltration** (`T1071` C2 communication, `T1071.004` High-entropy DNS Tunneling)

## 4. Multi-Stage Attack Chain Correlation
* **Recon-to-Breach**: Links early discovery port sweeps (`T1046`) to subsequent exploitation (`T1190` or `T1110`).
* **Compromise-to-Persistence**: Links web/auth breaches to subsequent FIM tampering (`T1565.001`) or LOLBAS execution (`T1059.001`).
* **Full Kill-Chain Intrusion**: Tracks full multi-stage progression from reconnaissance all the way to C2 beaconing and exfiltration.
* **Bounded Closed-Form Risk Scoring**: Calculates dynamic risk score ($[0, 100]$) weighted by stage progression, alert severity, and constituent alert volume.

## 5. CLI Usage & Verification (Law 6)
```bash
# Execute standalone self-test suite (evaluates 4-stage kill-chain progression)
python -m modules.correlation.standalone --self-test

# Correlate alert stream from JSON file with 4-hour temporal window
python -m modules.correlation.standalone --file /path/to/alerts.json --window-hours 4
```
