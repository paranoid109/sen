# Cloud Security Posture Management (CSPM) Module (X12)

## 1. Overview
The Cloud Security Posture Management Module continuously monitors multi-cloud environments (AWS, GCP, Azure) for misconfigurations, overly permissive IAM roles, unencrypted storage, and public exposure.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Operates as an independent cloud audit worker or ingest adapter for CSPM frameworks (Prowler, Steampipe, CloudSploit).
* Audits against CIS Cloud Benchmarks, NIST CSF, and PCI-DSS.
* Emits standardized `FindingContract` structures.

## 3. Monitored Cloud Vectors
* **Storage Exposure**: Publicly readable AWS S3 buckets or GCP Cloud Storage buckets.
* **IAM Over-Privilege**: Wildcard `*:*` permissions, inactive access keys, or missing MFA on root/privileged roles.
* **Network Perimeter Drift**: Overly permissive security groups (`0.0.0.0/0` on port 22/3389).

## 4. Contract Conformance
Findings conform to `contracts/findings/finding_contract.json`:
* `tool_name`: `"cloud_security_cspm"`
* `cwe_id`: `"CWE-732"` / `"CWE-284"`
