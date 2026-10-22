# Threat Intelligence Capability Module (X5)

## 1. Overview
The Threat Intelligence Capability Module ingests, normalizes, and correlates external Indicators of Compromise (IOCs) from public, commercial, and open-source intelligence feeds (AlienVault OTX, MISP, AbuseIPDB).

## 2. Decoupled Architecture (Law 1 & Law 2)
* Subscribes to STIX 2.1 / TAXII feeds and updates local IOC indices.
* Provides high-performance reputation lookup interfaces for IP addresses, domains, and file hashes.
* Decorates incoming events and findings without coupling to the core database.

## 3. Core Capabilities
* **IOC Ingestion & Deduplication**: Parses and hashes IP, domain, URL, and SHA-256 file IOCs with confidence scores and threat actor attributions.
* **Triage Enrichment**: Cross-checks `Alert.source_ip` against known malicious infrastructure.
* **Feed Expiration & Aging**: Prunes decayed or stale indicators based on configurable half-life parameters.

## 4. Contract Conformance
Findings and enrichments conform to `contracts/findings/finding_contract.json`:
* `tool_name`: `"threat_intelligence"`
* `mitre_attack_id`: Associated adversary techniques
