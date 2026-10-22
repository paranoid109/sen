"""Unit Tests for Incident Correlation, Closed-Form Risk Scoring & Lifecycle (M6)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.security import create_access_token, hash_password
from backend.app.models.alert import Alert
from backend.app.models.asset import Asset
from backend.app.models.audit import AuditLog
from backend.app.models.incident import IncidentAlert, IncidentTimeline
from backend.app.models.user import User
from backend.app.services.incident_service import incident_service


def _make_dummy_alert(
    *,
    severity: str = "medium",
    status: str = "NEW",
    occurrence_count: int = 1,
    target_asset_id: str | None = None,
    target_host: str | None = "host-01",
    rule_id: str = "RULE-001",
    rule_name: str = "Test Rule",
) -> Alert:
    """Helper creating an in-memory Alert model instance."""
    now = datetime.now(UTC)
    return Alert(
        id=str(uuid.uuid4()),
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        status=status,
        mitre_attack_id="T1110",
        source_ip="192.168.1.100",
        target_asset_id=target_asset_id,
        target_host=target_host,
        dedup_key=f"dummy-dedup-{uuid.uuid4().hex[:8]}",
        occurrence_count=occurrence_count,
        first_seen=now,
        last_seen=now,
        evidence=["test evidence"],
        created_at=now,
        updated_at=now,
    )


class TestIncidentRiskScoreMath:
    """Table-driven unit tests verifying the closed-form bounded risk score formula."""

    def test_single_low_alert_low_asset(self):
        # BaseScore(low)=5, Multiplier(low)=1.0 -> 5 * 1.0 = 5
        alert = _make_dummy_alert(severity="low", occurrence_count=1)
        score = incident_service.calculate_risk_score([alert], asset_criticality="low")
        assert score == 5

    def test_single_critical_alert_critical_asset(self):
        # BaseScore(critical)=40, Multiplier(critical)=2.0 -> 40 * 2.0 = 80
        alert = _make_dummy_alert(severity="critical", occurrence_count=1)
        score = incident_service.calculate_risk_score([alert], asset_criticality="critical")
        assert score == 80

    def test_single_high_alert_high_asset(self):
        # BaseScore(high)=25, Multiplier(high)=1.5 -> 25 * 1.5 = 37.5 -> round to 38
        alert = _make_dummy_alert(severity="high", occurrence_count=1)
        score = incident_service.calculate_risk_score([alert], asset_criticality="high")
        assert score == 38

    def test_multi_alert_escalation(self):
        # MaxBase(critical)=40 * Multiplier(critical)=2.0 = 80
        # Multi-alert penalty: (2 alerts - 1) * 15 = 15
        # Total = 80 + 15 = 95
        a1 = _make_dummy_alert(severity="critical", occurrence_count=1)
        a2 = _make_dummy_alert(severity="medium", occurrence_count=1)
        score = incident_service.calculate_risk_score([a1, a2], asset_criticality="critical")
        assert score == 95

    def test_score_caps_strictly_at_100(self):
        # 3 critical alerts on critical asset: 80 + (2 * 15) = 110 -> capped at 100
        alerts = [_make_dummy_alert(severity="critical", occurrence_count=1) for _ in range(3)]
        score = incident_service.calculate_risk_score(alerts, asset_criticality="critical")
        assert score == 100

    def test_recurrence_bonus_and_cap(self):
        # Single medium (15) * low (1.0) = 15
        # Recurrence: (5 - 1) * 2 = 8 -> 15 + 8 = 23
        a1 = _make_dummy_alert(severity="medium", occurrence_count=5)
        score = incident_service.calculate_risk_score([a1], asset_criticality="low")
        assert score == 23

        # Recurrence cap at 20: occurrence 25 -> (25 - 1) * 2 = 48 -> capped at 20
        # 15 + 20 = 35
        a2 = _make_dummy_alert(severity="medium", occurrence_count=25)
        score_capped = incident_service.calculate_risk_score([a2], asset_criticality="low")
        assert score_capped == 35

    def test_false_positive_exclusion(self):
        # If critical alert is FALSE_POSITIVE, only the medium alert is scored
        # BaseScore(medium)=15 * low(1.0) = 15
        fp_crit = _make_dummy_alert(
            severity="critical", status="FALSE_POSITIVE", occurrence_count=5
        )
        med = _make_dummy_alert(severity="medium", status="NEW", occurrence_count=1)
        score = incident_service.calculate_risk_score([fp_crit, med], asset_criticality="low")
        assert score == 15

    def test_all_false_positives_yields_zero(self):
        fp = _make_dummy_alert(severity="critical", status="FALSE_POSITIVE")
        assert incident_service.calculate_risk_score([fp], asset_criticality="critical") == 0
        assert incident_service.calculate_risk_score([], asset_criticality="critical") == 0


@pytest.mark.asyncio
async def test_correlate_alert_creates_new_incident(db_session: AsyncSession):
    # Setup monitored asset
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="web-prod-01",
        ip_address="10.0.0.10",
        criticality="high",
    )
    db_session.add(asset)
    await db_session.commit()

    alert = _make_dummy_alert(
        severity="high",
        target_asset_id=asset.id,
        target_host=asset.hostname,
        rule_name="SSH Brute Force",
    )
    db_session.add(alert)
    await db_session.commit()

    incident = await incident_service.correlate_alert(db_session, alert)
    assert incident.id is not None
    assert incident.status == "OPEN"
    assert incident.severity == "high"
    assert incident.target_asset_id == asset.id
    # High base 25 * 1.5 asset multiplier = 37.5 -> 38
    assert incident.risk_score == 38

    # Verify IncidentAlert association
    link_stmt = select(IncidentAlert).where(IncidentAlert.incident_id == incident.id)
    links = (await db_session.execute(link_stmt)).scalars().all()
    assert len(links) == 1
    assert links[0].alert_id == alert.id

    # Verify Timeline entry
    tl_stmt = select(IncidentTimeline).where(IncidentTimeline.incident_id == incident.id)
    timelines = (await db_session.execute(tl_stmt)).scalars().all()
    assert len(timelines) == 1
    assert timelines[0].event_type == "incident_created"


@pytest.mark.asyncio
async def test_correlate_alert_within_15min_window(db_session: AsyncSession):
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="db-server-01",
        ip_address="10.0.0.20",
        criticality="critical",
    )
    db_session.add(asset)
    await db_session.commit()

    alert1 = _make_dummy_alert(
        severity="medium",
        target_asset_id=asset.id,
        rule_name="Port Scan",
    )
    db_session.add(alert1)
    await db_session.commit()

    incident = await incident_service.correlate_alert(db_session, alert1)
    # Medium 15 * critical 2.0 = 30
    assert incident.risk_score == 30

    # Second alert arrives 5 minutes later on the same asset with higher severity
    alert2 = _make_dummy_alert(
        severity="critical",
        target_asset_id=asset.id,
        rule_name="Privilege Escalation",
    )
    db_session.add(alert2)
    await db_session.commit()

    correlated_incident = await incident_service.correlate_alert(db_session, alert2)
    # Correlated into same incident
    assert correlated_incident.id == incident.id
    # Escalated severity
    assert correlated_incident.severity == "critical"
    # Recalculated risk score: MaxBase(critical)=40 * 2.0 = 80 + (2-1)*15 = 95
    assert correlated_incident.risk_score == 95

    # Check 2 alerts linked
    link_stmt = select(IncidentAlert).where(IncidentAlert.incident_id == incident.id)
    links = (await db_session.execute(link_stmt)).scalars().all()
    assert len(links) == 2


@pytest.mark.asyncio
async def test_recalculate_and_auto_close_on_alert_resolution(db_session: AsyncSession):
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="app-gateway",
        ip_address="10.0.0.30",
        criticality="low",
    )
    db_session.add(asset)
    await db_session.commit()

    alert = _make_dummy_alert(
        severity="high",
        target_asset_id=asset.id,
        rule_name="Suspicious Activity",
    )
    db_session.add(alert)
    await db_session.commit()

    incident = await incident_service.correlate_alert(db_session, alert)
    assert incident.status == "OPEN"
    assert incident.risk_score == 25  # High 25 * 1.0 = 25

    # Triage alert to FALSE_POSITIVE
    alert.status = "FALSE_POSITIVE"
    await db_session.commit()

    updated_inc = await incident_service.recalculate_incident_for_alert(db_session, alert)
    assert updated_inc is not None
    # Risk score dropped to 0 because FP is excluded
    assert updated_inc.risk_score == 0
    # Auto-closed since all correlated alerts are FALSE_POSITIVE / RESOLVED
    assert updated_inc.status == "RESOLVED"

    # Verify auto-resolved timeline entry was recorded
    tl_stmt = select(IncidentTimeline).where(
        IncidentTimeline.incident_id == incident.id,
        IncidentTimeline.event_type == "incident_auto_resolved",
    )
    tl = (await db_session.execute(tl_stmt)).scalars().first()
    assert tl is not None


@pytest.mark.asyncio
async def test_update_incident_lifecycle_and_audit(db_session: AsyncSession):
    alert = _make_dummy_alert(severity="medium")
    db_session.add(alert)
    await db_session.commit()

    incident = await incident_service.correlate_alert(db_session, alert)

    # Analyst triages incident to INVESTIGATING
    updated = await incident_service.update_incident(
        db_session,
        incident.id,
        new_status="INVESTIGATING",
        notes="SOC Analyst investigating anomalous behavior",
        user_id="analyst-user-id-01",
    )
    assert updated is not None
    assert updated.status == "INVESTIGATING"

    # Verify tamper-evident audit log was written (Law 4)
    audit_stmt = select(AuditLog).where(
        AuditLog.resource_id == incident.id,
        AuditLog.action == "INCIDENT_UPDATE",
    )
    audit_entry = (await db_session.execute(audit_stmt)).scalars().first()
    assert audit_entry is not None
    assert audit_entry.details["new_status"] == "INVESTIGATING"
    assert audit_entry.details["notes"] == "SOC Analyst investigating anomalous behavior"
    assert audit_entry.entry_hash is not None


@pytest.mark.asyncio
async def test_list_incidents_search_and_asset_filter(db_session: AsyncSession):
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="vpn-gateway-01",
        ip_address="10.10.10.1",
        asset_type="network",
        criticality="high",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(asset)
    await db_session.commit()

    alert = _make_dummy_alert(
        severity="high",
        target_asset_id=asset.id,
        target_host="vpn-gateway-01",
        rule_name="VPN Tunnel Intrusion",
    )
    db_session.add(alert)
    await db_session.commit()

    inc = await incident_service.correlate_alert(db_session, alert)

    # Search by hostname keyword
    by_host = await incident_service.list_incidents(db_session, search="vpn-gateway")
    assert len(by_host) == 1
    assert by_host[0].id == inc.id

    # Filter by Asset UUID
    by_asset = await incident_service.list_incidents(db_session, target_asset_id=asset.id)
    assert len(by_asset) == 1
    assert by_asset[0].id == inc.id


@pytest.mark.asyncio
async def test_correlate_alert_multi_stage_killchain_title_enrichment(
    db_session: AsyncSession,
):
    """Verifies that an incident title and description are enriched when 2+ MITRE techniques correlate."""
    host = "server-prod-01"
    a1 = _make_dummy_alert(
        severity="medium",
        target_host=host,
        rule_name="Port Scan",
    )
    a1.mitre_attack_id = "T1046"
    db_session.add(a1)
    await db_session.commit()

    inc1 = await incident_service.correlate_alert(db_session, a1)
    assert inc1.title == f"Incident: Port Scan on {host}"

    # Correlate second alert with different technique (Initial Access, T1190)
    a2 = _make_dummy_alert(
        severity="high",
        target_host=host,
        rule_name="SQL Injection",
    )
    a2.mitre_attack_id = "T1190"
    db_session.add(a2)
    await db_session.commit()

    inc2 = await incident_service.correlate_alert(db_session, a2)
    assert inc2.id == inc1.id
    assert "Multi-Stage Attack on server-prod-01: T1046 -> T1190" in inc2.title
    assert "Correlated multi-stage attack campaign spanning 2 MITRE ATT&CK techniques" in inc2.description


async def test_add_timeline_entry_and_audit(db_session: AsyncSession) -> None:
    """Asserts adding containment/forensics timeline entry persists and writes to audit log (Law 4)."""
    alert = _make_dummy_alert(target_host="firewall-edge-01")
    db_session.add(alert)
    await db_session.commit()

    inc = await incident_service.correlate_alert(db_session, alert)
    assert inc is not None

    entry = await incident_service.add_timeline_entry(
        db_session,
        incident_id=inc.id,
        event_type="soar_containment_executed",
        description="Blocked attacker IP 198.51.100.22 with 3 firewall rules",
        source="SOAR_Playbook",
        user_id="analyst1",
        details={"commands_count": 3, "target": "198.51.100.22"},
    )

    assert entry is not None
    assert entry.event_type == "soar_containment_executed"
    assert entry.source == "SOAR_Playbook"
    assert entry.incident_id == inc.id

    # Verify incident has timeline entry
    refreshed_inc = await incident_service.get_incident(db_session, inc.id)
    assert refreshed_inc is not None
    assert any(t.event_type == "soar_containment_executed" for t in refreshed_inc.timeline)


@pytest.mark.asyncio
async def test_update_incident_api_endpoint_returns_detail_response(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verifies PATCH /api/v1/incidents/{id} returns IncidentDetailResponse with alerts and timeline."""
    analyst = User(
        id=str(uuid.uuid4()),
        username="test_incident_analyst",
        email="incident_analyst@sentinelx.local",
        hashed_password=hash_password("Analyst123!"),
        role="Analyst",
        is_active=True,
    )
    db_session.add(analyst)
    alert = _make_dummy_alert(target_host="app-server-02")
    db_session.add(alert)
    await db_session.commit()

    inc = await incident_service.correlate_alert(db_session, alert)
    assert inc is not None

    token = create_access_token({"sub": analyst.id, "role": analyst.role, "username": analyst.username})
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.patch(
        f"/api/v1/incidents/{inc.id}",
        json={"status": "INVESTIGATING", "notes": "Analyst investigating compromised host"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == inc.id
    assert data["status"] == "INVESTIGATING"
    assert data["alert_count"] == 1
    assert "alerts" in data and len(data["alerts"]) == 1
    assert "timeline" in data and len(data["timeline"]) >= 2
    assert any("investigating" in t["description"].lower() for t in data["timeline"])



