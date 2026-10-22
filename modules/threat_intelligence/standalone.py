"""Standalone CLI Runner for Threat Intelligence Capability Module (X5).

Provides STIX 2.1, MISP, and CSV indicator ingestion, IOC lookup,
built-in self-testing, and forwarding security findings to SentinelX Ingest API.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from contracts.python.models import SeverityLevel
from modules.threat_intelligence.analyzer import ThreatIndicator, ThreatIntelligenceEngine


def run_self_test() -> int:
    """Executes built-in test suite asserting feed parsing, matching, and TTL expiration."""
    print("[*] Running ThreatIntelligenceEngine self-test suite...")
    engine = ThreatIntelligenceEngine()
    failures = 0

    # 1. CSV Blocklist ingestion
    csv_lines = [
        "# Malicious C2 infrastructure",
        "198.51.100.99,90,APT29,T1071",
        "bad-domain-beacon.ru,85,FancyBear,T1071.004",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85,95,Lazarus,T1565.001",
    ]
    count_csv = engine.ingest_csv_blocklist(csv_lines, source="Abuse_Feed")
    if count_csv != 3:
        print(f"[-] CSV ingestion mismatch: expected 3, got {count_csv}")
        failures += 1
    else:
        print(f"  [PASS] CSV Blocklist: Ingested {count_csv} indicators.")

    # 2. STIX 2.1 JSON bundle parsing
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000001",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--11111111-1111-1111-1111-111111111111",
                "pattern": "[ipv4-addr:value = '203.0.113.50']",
                "pattern_type": "stix",
                "confidence": 90,
                "description": "Adversary Actor: VoltTyphoon C2 node",
                "labels": ["malicious-activity", "c2"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1071"}
                ],
            }
        ],
    }
    count_stix = engine.ingest_stix_bundle(stix_bundle, source="CISA_Alert")
    if count_stix != 1:
        print(f"[-] STIX ingestion mismatch: expected 1, got {count_stix}")
        failures += 1
    else:
        print(f"  [PASS] STIX 2.1: Ingested {count_stix} indicator.")

    # 3. MISP JSON parsing
    misp_data = {
        "Event": {
            "threat_level_id": "1",
            "info": "FIN7 Campaign",
            "Attribute": [
                {
                    "type": "domain",
                    "value": "fin7-drop-payload.com",
                    "category": "Payload delivery",
                }
            ],
        }
    }
    count_misp = engine.ingest_misp_json(misp_data, source="MISP_Community")
    if count_misp != 1:
        print(f"[-] MISP ingestion mismatch: expected 1, got {count_misp}")
        failures += 1
    else:
        print(f"  [PASS] MISP JSON: Ingested {count_misp} indicator.")

    # 4. Lookup and Enrichment
    ioc_match = engine.lookup_ioc("198.51.100.99")
    if not ioc_match or ioc_match.threat_actor != "APT29":
        print("[-] Lookup failed for '198.51.100.99'")
        failures += 1
    else:
        print(f"  [PASS] IOC Lookup match: {ioc_match.value} -> {ioc_match.threat_actor} ({ioc_match.confidence}%)")

    # Event enrichment
    mock_event = {
        "source_ip": "198.51.100.99",
        "target_host": "server-prod-01",
        "event_type": "network_flow",
    }
    finding = engine.enrich_event(mock_event)
    if not finding or finding.mitre_attack_id != "T1071":
        print("[-] Event enrichment failed to emit FindingContract.")
        failures += 1
    else:
        print(f"  [PASS] Telemetry Enrichment: {finding.rule_id} -> {finding.description}")

    # 5. TTL Indicator Expiration
    expired_ind = ThreatIndicator(
        value="expired-c2-node.com",
        indicator_type="domain",
        severity=SeverityLevel.HIGH,
        confidence=80,
        valid_until=datetime.now(UTC) - timedelta(hours=1),
    )
    engine.add_indicator(expired_ind)
    if engine.lookup_ioc("expired-c2-node.com") is not None:
        print("[-] Expired indicator was returned by lookup_ioc()")
        failures += 1
    else:
        print("  [PASS] TTL Aging: Expired indicator successfully ignored.")

    pruned = engine.prune_expired()
    if pruned != 1:
        print(f"[-] Expected 1 pruned expired indicator, got {pruned}")
        failures += 1
    else:
        print(f"  [PASS] Pruning: Purged {pruned} expired indicator from memory.")

    if failures == 0:
        print("[+] ThreatIntelligenceEngine self-test passed: 5/5 test cases verified.")
        return 0
    else:
        print(f"[-] Self-test failed with {failures} failure(s).")
        return 1


def forward_finding_to_ingest(
    finding_dict: dict[str, Any],
    ingest_url: str,
    api_key: str,
) -> bool:
    """Forwards an enriched Threat Intelligence Finding to SentinelX Ingest API."""
    import httpx

    evidence_obj = finding_dict.get("evidence")
    source_ip = "0.0.0.0"
    if isinstance(evidence_obj, dict):
        source_ip = evidence_obj.get("event_source_ip") or evidence_obj.get("matched_ioc", "0.0.0.0")

    event_payload = {
        "event_type": "threat_intel_match",
        "source_ip": source_ip,
        "target_host": str(finding_dict.get("target") or "unknown-target"),
        "event_time": finding_dict.get("timestamp") or datetime.now(UTC).isoformat(),
        "details": {
            "finding_id": str(finding_dict.get("finding_id")),
            "tool_name": finding_dict.get("tool_name"),
            "rule_id": finding_dict.get("rule_id"),
            "severity": finding_dict.get("severity"),
            "description": finding_dict.get("description"),
            "mitre_attack_id": finding_dict.get("mitre_attack_id"),
            "evidence": evidence_obj,
        },
    }

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    try:
        res = httpx.post(ingest_url, json=event_payload, headers=headers, timeout=5.0)
        return res.status_code == 201
    except Exception as e:
        print(f"[-] Failed to forward finding to {ingest_url}: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelX Threat Intelligence Capability Module (X5)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Execute built-in self-test suite and exit",
    )
    parser.add_argument(
        "--lookup",
        type=str,
        help="Query reputation for an IP address, domain, or SHA-256 hash",
    )
    parser.add_argument(
        "--csv-file",
        type=Path,
        help="Path to CSV / plain list blocklist file",
    )
    parser.add_argument(
        "--stix-file",
        type=Path,
        help="Path to STIX 2.1 JSON bundle file",
    )
    parser.add_argument(
        "--misp-file",
        type=Path,
        help="Path to MISP JSON export file",
    )
    parser.add_argument(
        "--load",
        type=Path,
        help="Load IOC database snapshot from JSON file",
    )
    parser.add_argument(
        "--save",
        type=Path,
        help="Save current IOC database snapshot to JSON file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )

    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    engine = ThreatIntelligenceEngine()

    if args.load:
        if not args.load.exists():
            print(f"[-] Error: Snapshot file not found: {args.load}", file=sys.stderr)
            sys.exit(1)
        count = engine.import_snapshot(args.load)
        print(f"[+] Loaded {count} indicators from snapshot {args.load}.")

    if args.csv_file:
        if not args.csv_file.exists():
            print(f"[-] Error: CSV file not found: {args.csv_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.csv_file, encoding="utf-8") as f:
            count = engine.ingest_csv_blocklist(f.readlines(), source=args.csv_file.name)
        print(f"[+] Ingested {count} indicators from {args.csv_file}.")

    if args.stix_file:
        if not args.stix_file.exists():
            print(f"[-] Error: STIX file not found: {args.stix_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.stix_file, encoding="utf-8") as f:
            data = json.load(f)
            count = engine.ingest_stix_bundle(data, source=args.stix_file.name)
        print(f"[+] Ingested {count} indicators from {args.stix_file}.")

    if args.misp_file:
        if not args.misp_file.exists():
            print(f"[-] Error: MISP file not found: {args.misp_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.misp_file, encoding="utf-8") as f:
            data = json.load(f)
            count = engine.ingest_misp_json(data, source=args.misp_file.name)
        print(f"[+] Ingested {count} indicators from {args.misp_file}.")

    if args.save:
        engine.export_snapshot(args.save)
        print(f"[+] Exported {engine.total_indicators} indicators to {args.save}.")

    if args.lookup:
        match = engine.lookup_ioc(args.lookup)
        if args.json:
            if match:
                res = {
                    "found": True,
                    "value": match.value,
                    "type": match.indicator_type,
                    "severity": match.severity.value,
                    "confidence": match.confidence,
                    "threat_actor": match.threat_actor,
                    "campaign": match.campaign,
                    "mitre_attack_id": match.mitre_attack_id,
                    "source": match.source,
                }
            else:
                res = {"found": False, "query": args.lookup}
            print(json.dumps(res, indent=2))
        else:
            print("========================================================")
            print(" SentinelX Threat Intelligence - IOC Lookup")
            print("========================================================")
            if match:
                print(f"[!] MATCH FOUND: {match.value} [{match.indicator_type}]")
                print(f"    Severity     : {match.severity.value.upper()}")
                print(f"    Confidence   : {match.confidence}%")
                print(f"    Threat Actor : {match.threat_actor or 'Unknown'}")
                print(f"    Campaign     : {match.campaign or 'N/A'}")
                print(f"    MITRE ATT&CK : {match.mitre_attack_id or 'N/A'}")
                print(f"    Feed Source  : {match.source}")
            else:
                print(f"[-] No matching malicious indicator found for: '{args.lookup}'")
        sys.exit(0)

    if not args.lookup and not args.load and not args.csv_file and not args.stix_file and not args.misp_file:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
