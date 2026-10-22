"""Unit tests for Threat Intelligence Capability Module (X5).

Tests STIX 2.1, MISP, and CSV feed ingestion, TTL aging, IOC lookups,
FindingContract compliance, and snapshot persistence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from contracts.python.models import FindingContract, SeverityLevel
from modules.threat_intelligence.analyzer import ThreatIndicator, ThreatIntelligenceEngine


def test_csv_blocklist_ingestion() -> None:
    """Verifies parsing of CSV format IOC feeds and type inference."""
    engine = ThreatIntelligenceEngine()
    lines = [
        "# Comment header",
        "198.51.100.44,85,APT28,T1071",
        "evil-c2-tunnel.biz,90,Lazarus,T1071.004",
        "4b8a1c902e88ad98a2f7c00192e4a9f82d1c0042e88b9021a8f9001bca2d3345,95,Fin7,T1565.001",
    ]
    count = engine.ingest_csv_blocklist(lines, source="TestFeed")
    assert count == 3
    assert engine.total_indicators == 3

    # IP check
    ip_ind = engine.lookup_ioc("198.51.100.44")
    assert ip_ind is not None
    assert ip_ind.indicator_type == "ipv4"
    assert ip_ind.confidence == 85
    assert ip_ind.threat_actor == "APT28"

    # Domain check
    dom_ind = engine.lookup_ioc("evil-c2-tunnel.biz")
    assert dom_ind is not None
    assert dom_ind.indicator_type == "domain"

    # Hash check
    hash_ind = engine.lookup_ioc("4b8a1c902e88ad98a2f7c00192e4a9f82d1c0042e88b9021a8f9001bca2d3345")
    assert hash_ind is not None
    assert hash_ind.indicator_type == "sha256"


def test_stix_bundle_parsing() -> None:
    """Verifies STIX 2.1 JSON bundle parsing and MITRE ATT&CK reference mapping."""
    engine = ThreatIntelligenceEngine()
    stix_data = {
        "type": "bundle",
        "id": "bundle--test-01",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--test-01",
                "pattern": "[ipv4-addr:value = '192.0.2.100']",
                "confidence": 95,
                "description": "Actor: Sandworm Team C2",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1071"}
                ],
            },
            {
                "type": "indicator",
                "id": "indicator--test-02",
                "pattern": "[domain-name:value = 'sandworm-exfil.com']",
                "confidence": 80,
                "description": "Exfiltration domain",
            },
        ],
    }

    count = engine.ingest_stix_bundle(stix_data, source="US-CERT")
    assert count == 2

    ind1 = engine.lookup_ioc("192.0.2.100")
    assert ind1 is not None
    assert ind1.threat_actor == "Sandworm"
    assert ind1.severity == SeverityLevel.CRITICAL
    assert ind1.mitre_attack_id == "T1071"

    ind2 = engine.lookup_ioc("sandworm-exfil.com")
    assert ind2 is not None
    assert ind2.severity == SeverityLevel.HIGH


def test_misp_export_parsing() -> None:
    """Verifies MISP JSON attribute parsing and threat level mapping."""
    engine = ThreatIntelligenceEngine()
    misp_json = {
        "Event": {
            "threat_level_id": "1",
            "info": "Cobalt Strike Infrastructure",
            "Attribute": [
                {
                    "type": "ip-dst",
                    "value": "198.51.100.77",
                    "category": "Network activity",
                },
                {
                    "type": "sha256",
                    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "category": "Payload delivery",
                },
            ],
        }
    }

    count = engine.ingest_misp_json(misp_json, source="MISP_Hub")
    assert count == 2

    ind = engine.lookup_ioc("198.51.100.77")
    assert ind is not None
    assert ind.severity == SeverityLevel.CRITICAL
    assert ind.source == "MISP_Hub"


def test_ttl_indicator_expiration() -> None:
    """Verifies indicators with valid_until deadlines expire and are pruned."""
    engine = ThreatIntelligenceEngine()
    now = datetime.now(UTC)

    # Active indicator
    active = ThreatIndicator(
        value="active-c2.com",
        indicator_type="domain",
        severity=SeverityLevel.HIGH,
        confidence=80,
        valid_until=now + timedelta(hours=2),
    )
    # Expired indicator
    expired = ThreatIndicator(
        value="expired-c2.com",
        indicator_type="domain",
        severity=SeverityLevel.HIGH,
        confidence=80,
        valid_until=now - timedelta(hours=1),
    )

    engine.add_indicator(active)
    engine.add_indicator(expired)

    assert engine.lookup_ioc("active-c2.com", current_time=now) is not None
    assert engine.lookup_ioc("expired-c2.com", current_time=now) is None

    # Prune expired
    pruned = engine.prune_expired(current_time=now)
    assert pruned == 1
    assert engine.total_indicators == 1


def test_telemetry_event_enrichment() -> None:
    """Verifies event cross-referencing and FindingContract generation."""
    engine = ThreatIntelligenceEngine()
    engine.add_indicator(
        ThreatIndicator(
            value="198.51.100.5",
            indicator_type="ipv4",
            severity=SeverityLevel.CRITICAL,
            confidence=95,
            threat_actor="APT29",
            mitre_attack_id="T1071",
            source="ThreatFeed",
        )
    )

    # Event matching source_ip
    ev = {
        "source_ip": "198.51.100.5",
        "target_host": "bastion-host",
        "event_type": "ssh_login",
    }
    finding = engine.enrich_event(ev)

    assert finding is not None
    assert isinstance(finding, FindingContract)
    assert isinstance(finding.finding_id, UUID)
    assert finding.rule_id == "RULE-TI-MATCH-001"
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.mitre_attack_id == "T1071"
    assert finding.target == "198.51.100.5"
    assert isinstance(finding.evidence, dict)
    assert finding.evidence["threat_actor"] == "APT29"

    # Event without match
    clean_ev = {"source_ip": "10.0.0.1", "target_host": "safe-server"}
    assert engine.enrich_event(clean_ev) is None


def test_snapshot_export_import(tmp_path: Path) -> None:
    """Verifies persistence roundtrip of the IOC database."""
    engine = ThreatIntelligenceEngine()
    engine.add_indicator(
        ThreatIndicator(
            value="203.0.113.88",
            indicator_type="ipv4",
            severity=SeverityLevel.HIGH,
            confidence=85,
            threat_actor="Turla",
            source="SnapshotTest",
        )
    )

    snap_file = tmp_path / "ioc_snapshot.json"
    engine.export_snapshot(snap_file)
    assert snap_file.exists()

    new_engine = ThreatIntelligenceEngine()
    loaded = new_engine.import_snapshot(snap_file)
    assert loaded == 1
    assert new_engine.lookup_ioc("203.0.113.88") is not None
    assert new_engine.lookup_ioc("203.0.113.88").threat_actor == "Turla"
