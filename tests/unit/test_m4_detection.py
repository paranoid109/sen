"""Unit Tests for Detection Service & YAML Rule Engine (M4).

Verifies Step 5 Exit Criteria:
- Loading all 3 detection rules (SSH Brute Force, Port Scan, SQL Injection).
- Dialect-agnostic temporal sliding windows with Python timedelta bounds.
- Distinct field aggregation for Port Scan (RULE-NET-001).
- Regex pattern matching for SQL Injection (RULE-WEB-001).
- Alert triggering, deduplication, and evidence attachment via pipeline dispatcher.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.dispatcher import dispatcher
from backend.app.models.alert import Alert
from backend.app.schemas.events import SingleIngestRequest
from backend.app.services.detection_service import DetectionService
from backend.app.services.ingestion_service import ingestion_service

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def detection_service() -> DetectionService:
    """Provides a fresh DetectionService instance with rules loaded."""
    return DetectionService()


def test_rules_loaded(detection_service: DetectionService):
    """Verifies all 3 canonical detection rules are loaded."""
    rule_ids = {r.id for r in detection_service.rules}
    assert "RULE-AUTH-001" in rule_ids, "RULE-AUTH-001 (SSH Brute Force) not loaded"
    assert "RULE-NET-001" in rule_ids, "RULE-NET-001 (Port Scan) not loaded"
    assert "RULE-WEB-001" in rule_ids, "RULE-WEB-001 (SQL Injection) not loaded"


@pytest.mark.asyncio
async def test_ssh_brute_force_rule(db_session: AsyncSession):
    """Rule 1: 5 failed logins within 60s triggers RULE-AUTH-001; 4 does not."""
    base_time = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)
    source_ip = "192.168.1.101"

    # 1. Ingest 4 failed logins (below threshold of 5)
    for i in range(4):
        req = SingleIngestRequest(
            source_ip=source_ip,
            event_type="auth_failed",
            destination_port=22,
            target_host="bastion-01",
            event_time=base_time + timedelta(seconds=i * 2),
        )
        await ingestion_service.ingest_single(db_session, req)

    await dispatcher.drain(timeout=3.0)

    # Verify no alert triggered yet
    stmt = select(Alert).where(Alert.source_ip == source_ip)
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) == 0, "Alert should not trigger with only 4 failed logins"

    # 2. 5th failed login hits threshold
    req5 = SingleIngestRequest(
        source_ip=source_ip,
        event_type="auth_failed",
        destination_port=22,
        target_host="bastion-01",
        event_time=base_time + timedelta(seconds=8),
    )
    await ingestion_service.ingest_single(db_session, req5)
    await dispatcher.drain(timeout=3.0)

    res5 = await db_session.execute(stmt)
    alerts5 = list(res5.scalars().all())
    assert len(alerts5) == 1, "Alert should trigger on 5th failed login"
    alert = alerts5[0]
    assert alert.rule_id == "RULE-AUTH-001"
    assert alert.severity == "high"
    assert alert.mitre_attack_id == "T1110"
    assert alert.occurrence_count == 1
    assert len(alert.evidence) == 5

    # 3. 6th failed login deduplicates into the active alert
    req6 = SingleIngestRequest(
        source_ip=source_ip,
        event_type="auth_failed",
        destination_port=22,
        target_host="bastion-01",
        event_time=base_time + timedelta(seconds=10),
    )
    await ingestion_service.ingest_single(db_session, req6)
    await dispatcher.drain(timeout=3.0)

    db_session.expire_all()
    res6 = await db_session.execute(stmt)
    alerts6 = list(res6.scalars().all())
    assert len(alerts6) == 1, "Should still be exactly 1 alert (deduplicated)"
    assert alerts6[0].id == alert.id
    assert alerts6[0].occurrence_count == 2


@pytest.mark.asyncio
async def test_port_scan_distinct_port_aggregation(db_session: AsyncSession):
    """Rule 2: 10 connections to same port does NOT trigger port scan; 10 distinct ports DOES."""
    base_time = datetime(2026, 10, 7, 13, 0, 0, tzinfo=UTC)
    source_ip = "192.168.1.102"

    # 1. 10 connections to the SAME port (port 80) -> not a port scan
    for i in range(10):
        req = SingleIngestRequest(
            source_ip=source_ip,
            destination_port=80,
            event_type="connection",
            target_host="web-01",
            event_time=base_time + timedelta(seconds=i),
        )
        await ingestion_service.ingest_single(db_session, req)

    await dispatcher.drain(timeout=3.0)

    stmt = select(Alert).where(Alert.source_ip == source_ip)
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) == 0, "Repeated connections to same port must not trigger port scan"

    # 2. 10 connections to 10 DISTINCT ports -> triggers RULE-NET-001
    scan_ip = "192.168.1.103"
    distinct_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]
    for idx, port in enumerate(distinct_ports):
        req = SingleIngestRequest(
            source_ip=scan_ip,
            destination_port=port,
            event_type="connection",
            target_host="web-01",
            event_time=base_time + timedelta(seconds=idx * 2),
        )
        await ingestion_service.ingest_single(db_session, req)

    await dispatcher.drain(timeout=3.0)

    scan_stmt = select(Alert).where(Alert.source_ip == scan_ip)
    scan_res = await db_session.execute(scan_stmt)
    scan_alerts = list(scan_res.scalars().all())
    assert len(scan_alerts) == 1, "Port scan should trigger on 10th distinct port"
    alert = scan_alerts[0]
    assert alert.rule_id == "RULE-NET-001"
    assert alert.severity == "medium"
    assert alert.mitre_attack_id == "T1046"
    assert len(alert.evidence) >= 10


@pytest.mark.asyncio
async def test_sql_injection_pattern_matching(db_session: AsyncSession):
    """Rule 3: Benign web requests do not trigger; SQL injection payload triggers RULE-WEB-001."""
    base_time = datetime(2026, 10, 7, 14, 0, 0, tzinfo=UTC)
    source_ip = "192.168.1.104"

    # 1. Benign web request
    benign_req = SingleIngestRequest(
        source_ip=source_ip,
        destination_port=80,
        event_type="web_request",
        target_host="storefront-01",
        event_time=base_time,
        raw_payload="GET /index.html HTTP/1.1",
        details={"uri": "/index.html", "method": "GET"},
    )
    await ingestion_service.ingest_single(db_session, benign_req)
    await dispatcher.drain(timeout=3.0)

    stmt = select(Alert).where(Alert.source_ip == source_ip)
    res_benign = await db_session.execute(stmt)
    assert len(list(res_benign.scalars().all())) == 0, "Benign web request should not trigger alert"

    # 2. SQL injection attack payload: UNION SELECT
    sqli_req = SingleIngestRequest(
        source_ip=source_ip,
        destination_port=80,
        event_type="web_request",
        target_host="storefront-01",
        event_time=base_time + timedelta(seconds=5),
        raw_payload="GET /items?cat=1 UNION SELECT null,password FROM users HTTP/1.1",
        details={"uri": "/items?cat=1 UNION SELECT null,password FROM users", "method": "GET"},
    )
    await ingestion_service.ingest_single(db_session, sqli_req)
    await dispatcher.drain(timeout=3.0)

    res_sqli = await db_session.execute(stmt)
    sqli_alerts = list(res_sqli.scalars().all())
    assert len(sqli_alerts) == 1, "SQL injection attack should trigger alert"
    alert = sqli_alerts[0]
    assert alert.rule_id == "RULE-WEB-001"
    assert alert.severity == "high"
    assert alert.mitre_attack_id == "T1190"


@pytest.mark.asyncio
async def test_portscan_fixture_integration(db_session: AsyncSession):
    """Verifies detection using the tests/fixtures/portscan_connections.json fixture."""
    fixture_path = FIXTURES_DIR / "portscan_connections.json"
    assert fixture_path.exists()

    with open(fixture_path, encoding="utf-8") as f:
        records = json.load(f)

    for item in records:
        req = ingestion_service.parse_connection_json(item)
        assert req is not None
        await ingestion_service.ingest_single(db_session, req)

    await dispatcher.drain(timeout=5.0)

    stmt = select(Alert).where(Alert.source_ip == "192.168.1.200")
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-NET-001"
    assert alerts[0].mitre_attack_id == "T1046"


@pytest.mark.asyncio
async def test_web_sqli_fixture_integration(db_session: AsyncSession):
    """Verifies detection using the tests/fixtures/web_sqli.log fixture."""
    fixture_path = FIXTURES_DIR / "web_sqli.log"
    assert fixture_path.exists()

    with open(fixture_path, encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    for line in lines:
        req = ingestion_service.parse_web_log_line(line, target_host="web-app-01")
        if not req:
            continue
        await ingestion_service.ingest_single(db_session, req)

    await dispatcher.drain(timeout=5.0)

    stmt = select(Alert).where(Alert.source_ip == "192.168.1.150")
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) >= 1
    assert any(a.rule_id == "RULE-WEB-001" for a in alerts)


@pytest.mark.asyncio
async def test_dns_tunneling_detection_rule(db_session: AsyncSession):
    """Verifies RULE-NET-002 triggers upon ingesting a network_finding DNS tunneling event."""
    req = SingleIngestRequest(
        source_ip="192.168.1.199",
        event_type="network_finding",
        target_host="dns-gateway-01",
        raw_payload="DNS Tunneling detected: a9f82d1c.tunnel.evilcorp.com",
        details={
            "rule_id": "RULE-NET-DNS-001",
            "mitre_attack_id": "T1071.004",
            "query": "a9f82d1c.tunnel.evilcorp.com",
        },
        event_time=datetime.now(UTC),
    )
    await ingestion_service.ingest_single(db_session, req)
    await dispatcher.drain(timeout=3.0)

    stmt = select(Alert).where(Alert.source_ip == "192.168.1.199")
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-NET-002"
    assert alerts[0].mitre_attack_id == "T1071.004"


@pytest.mark.asyncio
async def test_endpoint_tampering_detection_rule(db_session: AsyncSession):
    """Verifies RULE-EDR-001 triggers upon ingesting an endpoint_finding FIM tampering event."""
    req = SingleIngestRequest(
        source_ip="10.0.2.55",
        event_type="endpoint_finding",
        target_host="srv-finance-01",
        raw_payload="File Integrity Tampering Detected: /etc/sudoers modified",
        details={
            "rule_id": "RULE-EDR-FIM-001",
            "mitre_attack_id": "T1565.001",
            "path": "/etc/sudoers",
        },
        event_time=datetime.now(UTC),
    )
    await ingestion_service.ingest_single(db_session, req)
    await dispatcher.drain(timeout=3.0)

    stmt = select(Alert).where(Alert.source_ip == "10.0.2.55")
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-EDR-001"
    assert alerts[0].mitre_attack_id == "T1565.001"


@pytest.mark.asyncio
async def test_threat_intel_match_rule(db_session: AsyncSession):
    """Verifies RULE-TI-001 triggers upon ingesting a threat_intel_match event."""
    req = SingleIngestRequest(
        source_ip="198.51.100.99",
        event_type="threat_intel_match",
        target_host="firewall-external",
        raw_payload="Threat Intel Match: 198.51.100.99 (APT29 C2)",
        details={"threat_actor": "APT29", "confidence": 90},
        event_time=datetime.now(UTC),
    )
    await ingestion_service.ingest_single(db_session, req)
    await dispatcher.drain(timeout=3.0)

    stmt = select(Alert).where(Alert.source_ip == "198.51.100.99")
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-TI-001"
    assert alerts[0].mitre_attack_id == "T1071"


@pytest.mark.asyncio
async def test_vulnerability_finding_rule(db_session: AsyncSession):
    """Verifies RULE-VULN-001 triggers upon ingesting a critical vulnerability finding."""
    req = SingleIngestRequest(
        source_ip="127.0.0.1",
        event_type="vulnerability_finding",
        target_host="server-prod-01",
        raw_payload="Vulnerability CVE-2021-44228 in log4j-core:2.14.0 [CISA-KEV]",
        details={"cve_id": "CVE-2021-44228", "cisa_kev": True, "cvss": 10.0},
        event_time=datetime.now(UTC),
    )
    await ingestion_service.ingest_single(db_session, req)
    await dispatcher.drain(timeout=3.0)

    stmt = select(Alert).where(Alert.source_ip == "127.0.0.1")
    res = await db_session.execute(stmt)
    alerts = list(res.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-VULN-001"
    assert alerts[0].mitre_attack_id == "T1190"


