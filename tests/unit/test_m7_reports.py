"""Unit tests for Reporting Engine and KPI Metrics (M7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.security import create_access_token, hash_password
from backend.app.models.alert import Alert
from backend.app.models.asset import Asset
from backend.app.models.event import Event
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.services.report_service import report_service


@pytest.mark.asyncio
async def test_dashboard_metrics_empty_database(db_session: AsyncSession):
    """Validates baseline metric calculations on a clean database."""
    metrics = await report_service.get_dashboard_metrics(db_session)
    assert metrics.total_events == 0
    assert metrics.active_alerts == 0
    assert metrics.open_incidents == 0
    assert metrics.monitored_assets == 0
    assert metrics.severity_breakdown == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert metrics.mttd_seconds is None


@pytest.mark.asyncio
async def test_dashboard_metrics_with_telemetry_and_mttd(db_session: AsyncSession):
    """Validates KPI aggregation, severity breakdown, and MTTD latency formula."""
    now = datetime.now(UTC)

    # 1. Monitored Assets (2 assets)
    a1 = Asset(id=str(uuid.uuid4()), hostname="srv-1", ip_address="10.0.0.1", criticality="high")
    a2 = Asset(id=str(uuid.uuid4()), hostname="srv-2", ip_address="10.0.0.2", criticality="low")
    db_session.add_all([a1, a2])

    # 2. Events (3 events)
    e1 = Event(id=str(uuid.uuid4()), event_type="auth_failed", source_ip="1.1.1.1", event_time=now)
    e2 = Event(id=str(uuid.uuid4()), event_type="auth_failed", source_ip="1.1.1.1", event_time=now)
    e3 = Event(id=str(uuid.uuid4()), event_type="port_scan", source_ip="1.1.1.1", event_time=now)
    db_session.add_all([e1, e2, e3])

    # 3. Alerts:
    # Alert 1: Active NEW, critical, latency = 20s
    al1 = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-1",
        rule_name="Rule 1",
        severity="critical",
        status="NEW",
        source_ip="192.168.1.100",
        first_seen=now - timedelta(seconds=20),
        last_seen=now,
        created_at=now,
        dedup_key="key1",
    )
    # Alert 2: Active INVESTIGATING, high, latency = 40s
    al2 = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-2",
        rule_name="Rule 2",
        severity="high",
        status="INVESTIGATING",
        source_ip="192.168.1.100",
        first_seen=now - timedelta(seconds=40),
        last_seen=now,
        created_at=now,
        dedup_key="key2",
    )
    # Alert 3: RESOLVED (not counted in active_alerts), medium, latency = 60s
    al3 = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-3",
        rule_name="Rule 3",
        severity="medium",
        status="RESOLVED",
        source_ip="192.168.1.100",
        first_seen=now - timedelta(seconds=60),
        last_seen=now,
        created_at=now,
        dedup_key="key3",
    )
    db_session.add_all([al1, al2, al3])

    # 4. Incidents: 1 OPEN, 1 RESOLVED
    inc1 = Incident(
        id=str(uuid.uuid4()),
        title="Incident 1",
        severity="critical",
        status="OPEN",
        risk_score=75,
    )
    inc2 = Incident(
        id=str(uuid.uuid4()),
        title="Incident 2",
        severity="low",
        status="RESOLVED",
        risk_score=10,
    )
    db_session.add_all([inc1, inc2])
    await db_session.commit()

    # Query metrics
    metrics = await report_service.get_dashboard_metrics(db_session)
    assert metrics.total_events == 3
    assert metrics.active_alerts == 2  # al1 (NEW) and al2 (INVESTIGATING)
    assert metrics.open_incidents == 1  # inc1 (OPEN)
    assert metrics.monitored_assets == 2

    # Severity distribution
    assert metrics.severity_breakdown["critical"] == 1
    assert metrics.severity_breakdown["high"] == 1
    assert metrics.severity_breakdown["medium"] == 1
    assert metrics.severity_breakdown["low"] == 0

    # MTTD = average of (20, 40, 60) = 40.0s
    assert metrics.mttd_seconds == 40.0


@pytest.mark.asyncio
async def test_executive_report_generation(db_session: AsyncSession):
    """Validates executive report generation and markdown contents."""
    report = await report_service.generate_executive_report(db_session)
    assert report.generated_at is not None
    assert "# SentinelX Executive Security Summary Debrief" in report.report_markdown
    assert "Threat Severity Breakdown" in report.report_markdown
    assert "Autonomous & Supervised Containment Actions" in report.report_markdown
    assert "Operational Recommendations" in report.report_markdown
    assert report.kpi_metrics.total_events == 0

    # Add an incident and containment action to verify count update
    from backend.app.models.incident import IncidentTimeline
    inc = Incident(
        id=str(uuid.uuid4()),
        title="Incident Under Containment",
        severity="high",
        status="INVESTIGATING",
        risk_score=70,
    )
    db_session.add(inc)
    await db_session.flush()

    tl_entry = IncidentTimeline(
        id=str(uuid.uuid4()),
        incident_id=inc.id,
        timestamp=datetime.now(UTC),
        event_type="soar_containment_executed",
        description="Blocked attacker IP 203.0.113.55",
        source="SOAR_Playbook",
    )
    db_session.add(tl_entry)
    await db_session.commit()

    updated_report = await report_service.generate_executive_report(db_session)
    assert "- **Active SOAR Directives Executed:** 1" in updated_report.report_markdown


@pytest.mark.asyncio
async def test_reports_rest_api_endpoints(client: AsyncClient, db_session: AsyncSession):
    """Validates REST endpoints for metrics, kpi alias, and executive report."""
    analyst = User(
        id=str(uuid.uuid4()),
        username="report_analyst",
        email="analyst@sentinelx.local",
        hashed_password=hash_password("Pass123!"),
        role="Analyst",
        is_active=True,
    )
    db_session.add(analyst)
    await db_session.commit()

    token = create_access_token(
        {"sub": analyst.id, "role": analyst.role, "username": analyst.username}
    )
    headers = {"Authorization": f"Bearer {token}"}

    # 1. GET /api/v1/reports/metrics
    m_resp = await client.get("/api/v1/reports/metrics", headers=headers)
    assert m_resp.status_code == 200
    m_data = m_resp.json()
    assert "total_events" in m_data
    assert "active_alerts" in m_data

    # 2. GET /api/v1/reports/kpi (alias)
    k_resp = await client.get("/api/v1/reports/kpi", headers=headers)
    assert k_resp.status_code == 200
    assert k_resp.json() == m_data

    # 3. GET /api/v1/reports/executive
    e_resp = await client.get("/api/v1/reports/executive", headers=headers)
    assert e_resp.status_code == 200
    e_data = e_resp.json()
    assert "report_markdown" in e_data
    assert "kpi_metrics" in e_data
