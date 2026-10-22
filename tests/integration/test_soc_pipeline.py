"""End-to-End Vertical Slice SOC Pipeline Integration Test.

Satisfies Step 4 Exit Criteria:
Ingest auth.log lines -> Dispatch -> Detect (YAML Rule Engine) -> Alert (Dedup) -> Incident (Correlation & Risk Score).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.dispatcher import dispatcher
from backend.app.core.security import create_access_token, hash_password
from backend.app.models.alert import Alert
from backend.app.models.asset import Asset
from backend.app.models.event import Event
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.services.ingestion_service import ingestion_service

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.mark.asyncio
async def test_vertical_slice_auth_bruteforce_to_incident(
    client: AsyncClient,
    db_session: AsyncSession,
):
    """Full vertical slice: Ingest 6 auth.log lines, detect brute force, dedup alert, and correlate incident."""
    # 1. Register monitored infrastructure asset in CMDB
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="server-prod-01",
        ip_address="192.168.1.10",
        asset_type="server",
        criticality="high",
        description="Production Web & Application Server",
    )
    db_session.add(asset)
    await db_session.commit()

    # 2. Read raw auth.log lines from test fixture
    log_path = FIXTURES_DIR / "auth_bruteforce.log"
    assert log_path.exists(), f"Fixture file not found: {log_path}"
    with open(log_path, encoding="utf-8") as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    assert len(raw_lines) == 6, "Expected 6 log entries in auth_bruteforce.log"

    # 3. Ingest each log entry through the public Ingestion API
    for line in raw_lines:
        parsed = ingestion_service.parse_auth_log_line(line, default_year=2026)
        assert parsed is not None, f"Failed to parse line: {line}"

        payload = {
            "source_ip": parsed.source_ip,
            "destination_ip": parsed.destination_ip,
            "destination_port": parsed.destination_port,
            "source_port": parsed.source_port,
            "event_type": parsed.event_type,
            "target_host": parsed.target_host,
            "event_time": parsed.event_time.isoformat() if parsed.event_time else None,
            "raw_payload": parsed.raw_payload,
            "details": parsed.details,
        }

        resp = await client.post("/api/v1/events/ingest", json=payload)
        assert resp.status_code == 201, f"Ingest failed: {resp.text}"
        data = resp.json()
        assert data["status"] == "success"
        assert data["ingested_count"] == 1

    # 4. Drain all asynchronous subscribers to guarantee pipeline completion
    await dispatcher.drain(timeout=5.0)

    # 5. Verify Ingestion & Persistence (M3)
    ev_stmt = select(Event)
    ev_res = await db_session.execute(ev_stmt)
    events = list(ev_res.scalars().all())
    assert len(events) == 6, "All 6 events should be persisted in DB"
    for ev in events:
        assert ev.target_host == "server-prod-01"
        assert ev.target_asset_id == asset.id
        assert ev.event_type == "auth_failed"
        assert ev.source_ip == "192.168.1.100"

    # 6. Verify Alert Detection & Deduplication (M4 / M5)
    al_stmt = select(Alert)
    al_res = await db_session.execute(al_stmt)
    alerts = list(al_res.scalars().all())
    assert len(alerts) == 1, "Exactly 1 deduplicated alert should exist"

    alert = alerts[0]
    assert alert.rule_id == "RULE-AUTH-001"
    assert alert.severity == "high"
    assert alert.mitre_attack_id == "T1110"
    assert alert.status == "NEW"
    assert alert.target_asset_id == asset.id
    assert alert.target_host == "server-prod-01"
    assert alert.source_ip == "192.168.1.100"
    # 5 events triggered threshold, 6th event deduplicated into it
    assert alert.occurrence_count == 2
    assert len(alert.evidence) >= 5

    # 7. Verify Incident Correlation & Closed-Form Risk Score (M6)
    inc_stmt = select(Incident)
    inc_res = await db_session.execute(inc_stmt)
    incidents = list(inc_res.scalars().all())
    assert len(incidents) == 1, "Exactly 1 incident should be correlated for the target asset"

    incident = incidents[0]
    assert incident.status == "OPEN"
    assert incident.severity == "high"
    assert incident.target_asset_id == asset.id
    assert incident.target_host == "server-prod-01"
    # Closed-form formula:
    # MaxBase(high)=25 * AssetMultiplier(high)=1.5 = 37.5
    # Recurrence bonus: (2 - 1) * 2 = 2
    # RawScore = 37.5 + 2 = 39.5 -> round to 40
    assert incident.risk_score == 40

    # 8. Verify REST API retrieval with authenticated SOC Analyst token
    analyst = User(
        id=str(uuid.uuid4()),
        username="soc_analyst",
        email="analyst@sentinelx.local",
        hashed_password=hash_password("analyst_pass123"),
        role="Analyst",
        is_active=True,
    )
    db_session.add(analyst)
    await db_session.commit()
    auth_token = create_access_token(
        {"sub": analyst.id, "role": analyst.role, "username": analyst.username}
    )
    auth_headers = {"Authorization": f"Bearer {auth_token}"}

    # GET /api/v1/alerts
    alerts_api_resp = await client.get("/api/v1/alerts", headers=auth_headers)
    assert alerts_api_resp.status_code == 200
    alerts_data = alerts_api_resp.json()
    assert len(alerts_data) == 1
    assert alerts_data[0]["id"] == alert.id
    assert alerts_data[0]["occurrence_count"] == 2

    # GET /api/v1/incidents
    inc_api_resp = await client.get("/api/v1/incidents", headers=auth_headers)
    assert inc_api_resp.status_code == 200
    inc_data = inc_api_resp.json()
    assert len(inc_data) == 1
    assert inc_data[0]["id"] == incident.id
    assert inc_data[0]["risk_score"] == 40
    assert inc_data[0]["alert_count"] == 1

    # GET /api/v1/incidents/{id}
    detail_api_resp = await client.get(f"/api/v1/incidents/{incident.id}", headers=auth_headers)
    assert detail_api_resp.status_code == 200
    detail_data = detail_api_resp.json()
    assert detail_data["id"] == incident.id
    assert len(detail_data["alerts"]) == 1
    assert len(detail_data["timeline"]) >= 1

    # 9. Verify Triage & Incident Auto-Resolution
    triage_resp = await client.patch(
        f"/api/v1/alerts/{alert.id}/triage",
        json={"status": "RESOLVED", "notes": "Attacker IP blocked at edge firewall"},
        headers=auth_headers,
    )
    assert triage_resp.status_code == 200
    assert triage_resp.json()["status"] == "RESOLVED"

    # Incident should auto-resolve because all linked alerts are now RESOLVED
    detail_after_triage = await client.get(f"/api/v1/incidents/{incident.id}", headers=auth_headers)
    assert detail_after_triage.status_code == 200
    updated_inc = detail_after_triage.json()
    assert updated_inc["status"] == "RESOLVED"

    # Verify auto-resolved timeline event
    timeline_events = [t["event_type"] for t in updated_inc["timeline"]]
    assert "incident_auto_resolved" in timeline_events
