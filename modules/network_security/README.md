# Network Security Capability Module (X2)

## 1. Overview
The Network Security Capability Module is a pluggable telemetry collector and analyzer for network perimeter and internal segment traffic. It inspects connection flows, identifies anomalous port sweeps (MITRE ATT&CK `T1046`), and detects protocol tunneling anomalies.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Contains zero imports from `backend.app.services`.
* Can execute standalone against PCAP dumps or Zeek/Suricata log streams.
* Emits strongly typed `FindingContract` or forwards normalized telemetry to `POST /api/v1/events/ingest`.

## 3. Supported Threat Vectors
* **TCP SYN/Connect Port Sweeps**: Identifies scanning activity across multiple destination ports.
* **DNS Data Exfiltration**: Identifies unusually long subdomain queries or entropy bursts.
* **Unauthorized Ingress Connections**: Flags incoming connections to unadvertised services on monitored assets.

## 4. Contract Conformance
Findings conform to `contracts/findings/finding_contract.json`:
* `tool_name`: `"network_security"`
* `cwe_id`: `"CWE-200"`
* `mitre_attack_id`: `"T1046"`
