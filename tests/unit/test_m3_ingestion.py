"""Unit tests for Telemetry Ingestion Service (M3)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.api_key import ApiKey
from backend.app.models.asset import Asset
from backend.app.models.event import Event
from backend.app.schemas.events import BatchIngestRequest, SingleIngestRequest
from backend.app.services.ingestion_service import ingestion_service


def test_parse_auth_log_valid_line():
    raw_line = (
        "Oct  7 12:00:01 server-prod-01 sshd[1234]: "
        "Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    )
    parsed = ingestion_service.parse_auth_log_line(raw_line, default_year=2026)

    assert parsed is not None
    assert parsed.source_ip == "192.168.1.100"
    assert parsed.source_port == 54321
    assert parsed.destination_port == 22
    assert parsed.event_type == "auth_failed"
    assert parsed.target_host == "server-prod-01"
    assert parsed.details["user"] == "admin"
    assert parsed.details["service"] == "sshd"
    assert parsed.event_time == datetime(2026, 10, 7, 12, 0, 1, tzinfo=UTC)


def test_parse_auth_log_invalid_line():
    raw_line = "Oct  7 12:00:01 server-prod-01 CRON[1234]: (root) CMD (run-parts /etc/cron.hourly)"
    parsed = ingestion_service.parse_auth_log_line(raw_line)
    assert parsed is None


@pytest.mark.asyncio
async def test_ingest_single_persists_event(db_session: AsyncSession):
    req = SingleIngestRequest(
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        destination_port=22,
        event_type="auth_failed",
        target_host="bastion-01",
        details={"user": "root"},
    )

    event = await ingestion_service.ingest_single(db_session, req)
    assert event.id is not None
    assert event.source_ip == "192.168.1.50"
    assert event.event_type == "auth_failed"

    # Query from DB
    stmt = select(Event).where(Event.id == event.id)
    res = await db_session.execute(stmt)
    db_event = res.scalars().one()
    assert db_event.target_host == "bastion-01"


@pytest.mark.asyncio
async def test_api_key_asset_precedence(db_session: AsyncSession):
    # Pre-create CMDB asset
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="secure-vault",
        ip_address="10.0.0.99",
        criticality="critical",
    )
    db_session.add(asset)
    await db_session.commit()

    # Pre-create API Key bound to this asset
    api_key = ApiKey(
        id=str(uuid.uuid4()),
        key_hash="hash_123",
        name="Vault Agent Key",
        prefix="sen_test",
        scope="ingest",
        asset_id=asset.id,
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.commit()

    # Request attempts to claim a spoofed target_host and asset_id
    req = SingleIngestRequest(
        source_ip="10.1.1.5",
        event_type="auth_failed",
        target_host="spoofed-target-host",
        asset_id=str(uuid.uuid4()),  # Spoofed asset ID
    )

    event = await ingestion_service.ingest_single(db_session, req, api_key=api_key)

    # Law 1 Precedence: forced to api_key.asset_id
    assert event.target_asset_id == asset.id
    assert event.target_asset_id != req.asset_id


@pytest.mark.asyncio
async def test_ingest_batch_with_fallbacks(db_session: AsyncSession):
    asset = Asset(
        id="asset-batch-fallback",
        hostname="batch-fallback-host",
        ip_address="10.2.2.2",
        criticality="medium",
    )
    db_session.add(asset)
    await db_session.commit()

    events = [
        SingleIngestRequest(source_ip="1.1.1.1", event_type="test1"),
        SingleIngestRequest(source_ip="2.2.2.2", event_type="test2", target_host="explicit-host"),
    ]
    batch = BatchIngestRequest(
        events=events,
        target_host="batch-fallback-host",
        asset_id="asset-batch-fallback",
    )

    persisted = await ingestion_service.ingest_batch(db_session, batch)
    assert len(persisted) == 2

    # Item 1 used fallback
    assert persisted[0].target_host == "batch-fallback-host"
    assert persisted[0].target_asset_id == "asset-batch-fallback"

    # Item 2 preserved explicit target_host
    assert persisted[1].target_host == "explicit-host"
    assert persisted[1].target_asset_id == "asset-batch-fallback"
