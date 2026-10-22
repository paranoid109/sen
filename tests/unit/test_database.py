"""Unit tests for Dual-Database Engine Compatibility & UTCDateTime (ADR 0002)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.alert import Alert
from backend.app.models.asset import Asset
from backend.app.models.event import Event
from backend.app.services.asset_service import asset_service


@pytest.mark.asyncio
async def test_utcdatetime_enforces_timezone_awareness(db_session: AsyncSession):
    now_utc = datetime.now(UTC)
    event = Event(
        source_ip="10.0.0.1",
        event_type="auth_failed",
        event_time=now_utc,
        details={},
    )
    db_session.add(event)
    await db_session.commit()
    await db_session.refresh(event)

    assert event.event_time.tzinfo is not None
    assert event.event_time.tzinfo == UTC
    assert event.ingest_time.tzinfo == UTC


@pytest.mark.asyncio
async def test_alert_partial_unique_index(db_session: AsyncSession):
    now_utc = datetime.now(UTC)
    dedup = "a" * 64

    # First active alert with dedup_key
    a1 = Alert(
        rule_id="RULE-1",
        rule_name="Test Rule",
        severity="high",
        status="NEW",
        source_ip="192.168.1.1",
        dedup_key=dedup,
        first_seen=now_utc,
        last_seen=now_utc,
        evidence=[],
    )
    db_session.add(a1)
    await db_session.commit()

    # Second alert with same dedup_key but status=RESOLVED must succeed
    a2 = Alert(
        rule_id="RULE-1",
        rule_name="Test Rule",
        severity="high",
        status="RESOLVED",
        source_ip="192.168.1.1",
        dedup_key=dedup,
        first_seen=now_utc,
        last_seen=now_utc,
        evidence=[],
    )
    db_session.add(a2)
    await db_session.commit()

    # Third alert with same dedup_key and active status (INVESTIGATING) must raise IntegrityError
    a3 = Alert(
        rule_id="RULE-1",
        rule_name="Test Rule",
        severity="high",
        status="INVESTIGATING",
        source_ip="192.168.1.1",
        dedup_key=dedup,
        first_seen=now_utc,
        last_seen=now_utc,
        evidence=[],
    )
    db_session.add(a3)
    with pytest.raises(IntegrityError):
        await db_session.commit()


@pytest.mark.asyncio
async def test_asset_target_resolution(db_session: AsyncSession):
    asset = Asset(
        hostname="gw-prod-01",
        ip_address="10.0.1.5",
        asset_type="gateway",
        criticality="critical",
    )
    db_session.add(asset)
    await db_session.commit()
    await db_session.refresh(asset)

    # Resolution by exact asset_id
    res1 = await asset_service.resolve_target_asset(db_session, asset_id=asset.id)
    assert res1 is not None
    assert res1.id == asset.id

    # Resolution by hostname
    res2 = await asset_service.resolve_target_asset(db_session, target_host="gw-prod-01")
    assert res2 is not None
    assert res2.id == asset.id

    # Resolution by IP
    res3 = await asset_service.resolve_target_asset(db_session, destination_ip="10.0.1.5")
    assert res3 is not None
    assert res3.id == asset.id

    # Unmatched resolution returns None
    res_none = await asset_service.resolve_target_asset(db_session, destination_ip="10.99.99.99")
    assert res_none is None
