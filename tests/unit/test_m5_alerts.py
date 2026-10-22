"""Unit tests for Alert Management and Deduplication Service (M5)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.audit import AuditLog
from backend.app.services.alert_service import alert_service


def test_dedup_key_deterministic():
    k1 = alert_service.compute_dedup_key("RULE-1", "asset-1", "host-1", "1.2.3.4")
    k2 = alert_service.compute_dedup_key("RULE-1", "asset-1", "host-1", "1.2.3.4")
    assert k1 == k2
    assert len(k1) == 64

    # Target host used if asset_id is None
    k3 = alert_service.compute_dedup_key("RULE-1", None, "host-1", "1.2.3.4")
    assert k3 == alert_service.compute_dedup_key("RULE-1", None, "host-1", "1.2.3.4")


@pytest.mark.asyncio
async def test_alert_creation_and_deduplication(db_session: AsyncSession):
    now1 = datetime.now(UTC)
    now2 = datetime.now(UTC)

    # 1. First occurrence
    a1, is_created1 = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-AUTH-001",
        rule_name="SSH Brute Force",
        severity="high",
        source_ip="192.168.1.100",
        target_host="server-1",
        first_seen=now1,
        last_seen=now1,
        evidence=["ev-1", "ev-2"],
    )

    assert is_created1 is True
    assert a1.occurrence_count == 1
    assert a1.evidence == ["ev-1", "ev-2"]

    # 2. Second occurrence (deduplicates into active alert)
    a2, is_created2 = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-AUTH-001",
        rule_name="SSH Brute Force",
        severity="high",
        source_ip="192.168.1.100",
        target_host="server-1",
        first_seen=now1,
        last_seen=now2,
        evidence=["ev-3"],
    )

    assert is_created2 is False
    assert a2.id == a1.id
    assert a2.occurrence_count == 2
    assert a2.last_seen == now2
    assert a2.evidence == ["ev-1", "ev-2", "ev-3"]


@pytest.mark.asyncio
async def test_alert_triage_lifecycle_and_audit(db_session: AsyncSession):
    now = datetime.now(UTC)
    alert, _ = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-AUTH-001",
        rule_name="SSH Brute Force",
        severity="high",
        source_ip="10.0.0.1",
        target_host="server-1",
        first_seen=now,
        last_seen=now,
        evidence=["ev-1"],
    )
    assert alert.status == "NEW"

    # Triage to INVESTIGATING
    updated = await alert_service.triage_alert(
        db_session,
        alert.id,
        new_status="INVESTIGATING",
        notes="Reviewing authentication logs",
        user_id="analyst-1",
    )
    assert updated is not None
    assert updated.status == "INVESTIGATING"

    # Check that mutation was audited (Law 4)
    stmt = select(AuditLog).where(
        AuditLog.resource_id == alert.id, AuditLog.action == "ALERT_TRIAGE"
    )
    res = await db_session.execute(stmt)
    audit_entry = res.scalars().first()
    assert audit_entry is not None
    assert audit_entry.details["new_status"] == "INVESTIGATING"


@pytest.mark.asyncio
async def test_resolved_alert_allows_fresh_alert(db_session: AsyncSession):
    now1 = datetime.now(UTC)
    now2 = datetime.now(UTC)

    # 1. Create first alert
    a1, _ = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-1",
        rule_name="Rule 1",
        severity="high",
        source_ip="10.0.0.5",
        target_host="srv-1",
        first_seen=now1,
        last_seen=now1,
        evidence=["e1"],
    )

    # 2. Resolve alert
    await alert_service.triage_alert(db_session, a1.id, new_status="RESOLVED")

    # 3. New detection matching same dedup_key must create a new active alert
    a2, is_created = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-1",
        rule_name="Rule 1",
        severity="high",
        source_ip="10.0.0.5",
        target_host="srv-1",
        first_seen=now2,
        last_seen=now2,
        evidence=["e2"],
    )

    assert is_created is True
    assert a2.id != a1.id
    assert a2.status == "NEW"
    assert a2.occurrence_count == 1


@pytest.mark.asyncio
async def test_list_alerts_search_and_asset_filter(db_session: AsyncSession):
    from backend.app.models.asset import Asset
    asset = Asset(
        id="asset-uuid-123",
        hostname="db-server-prod",
        ip_address="192.168.1.50",
        asset_type="database",
        criticality="critical",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(asset)
    await db_session.commit()

    now = datetime.now(UTC)
    a1, _ = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-AUTH-001",
        rule_name="SSH Brute Force",
        severity="high",
        source_ip="192.168.1.50",
        target_asset_id=asset.id,
        target_host="db-server-prod",
        first_seen=now,
        last_seen=now,
        evidence=["attempt-1"],
    )
    a2, _ = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-WEB-001",
        rule_name="SQL Injection Exploitation",
        severity="critical",
        source_ip="10.0.0.99",
        target_host="web-edge-01",
        first_seen=now,
        last_seen=now,
        evidence=["UNION SELECT"],
    )

    # Search by IP
    by_ip = await alert_service.list_alerts(db_session, search="192.168.1.50")
    assert len(by_ip) == 1
    assert by_ip[0].id == a1.id

    # Search by Rule Name keyword
    by_rule = await alert_service.list_alerts(db_session, search="Injection")
    assert len(by_rule) == 1
    assert by_rule[0].id == a2.id

    # Filter by Asset UUID
    by_asset = await alert_service.list_alerts(db_session, target_asset_id="asset-uuid-123")
    assert len(by_asset) == 1
    assert by_asset[0].id == a1.id


@pytest.mark.asyncio
async def test_get_alert_events_hydration(db_session: AsyncSession):
    """Verifies AlertService.get_alert_events hydrates supporting Event records in chronological order."""
    from backend.app.models.event import Event

    now = datetime.now(UTC)
    ev1 = Event(
        id="ev-hyd-1",
        source_ip="192.168.1.90",
        event_type="auth_failed",
        target_host="server-1",
        event_time=now,
        ingest_time=now,
        raw_payload="Failed password for root from 192.168.1.90",
        details={"user": "root"},
    )
    db_session.add(ev1)
    await db_session.commit()

    alert, _ = await alert_service.create_or_update_alert(
        db_session,
        rule_id="RULE-AUTH-001",
        rule_name="SSH Brute Force",
        severity="high",
        source_ip="192.168.1.90",
        target_host="server-1",
        first_seen=now,
        last_seen=now,
        evidence=["ev-hyd-1"],
    )

    events = await alert_service.get_alert_events(db_session, alert.id)
    assert events is not None
    assert len(events) == 1
    assert events[0].id == "ev-hyd-1"
    assert events[0].raw_payload == "Failed password for root from 192.168.1.90"
    assert await alert_service.get_alert_events(db_session, "nonexistent-alert") is None

