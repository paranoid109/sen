"""Unit tests for Role-Based Access Control (RBAC) Permissions Matrix."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.security import create_access_token, hash_password
from backend.app.models.alert import Alert
from backend.app.models.api_key import ApiKey
from backend.app.models.asset import Asset
from backend.app.models.incident import Incident
from backend.app.models.user import User


@pytest.fixture
async def rbac_test_setup(db_session: AsyncSession):
    """Provisions Admin, Analyst, and Auditor users along with test domain entities."""
    now = datetime.now(UTC)

    # 1. Users
    admin = User(
        id=str(uuid.uuid4()),
        username="admin_user",
        email="admin@sentinelx.local",
        hashed_password=hash_password("AdminPass123!"),
        role="Admin",
        is_active=True,
    )
    analyst = User(
        id=str(uuid.uuid4()),
        username="analyst_user",
        email="analyst@sentinelx.local",
        hashed_password=hash_password("AnalystPass123!"),
        role="Analyst",
        is_active=True,
    )
    auditor = User(
        id=str(uuid.uuid4()),
        username="auditor_user",
        email="auditor@sentinelx.local",
        hashed_password=hash_password("AuditorPass123!"),
        role="Auditor",
        is_active=True,
    )

    # 2. Test Asset
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="target-vm-01",
        ip_address="10.50.0.1",
        asset_type="server",
        criticality="high",
    )
    db_session.add_all([admin, analyst, auditor, asset])
    await db_session.flush()

    # 3. Test Alert
    alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-AUTH-001",
        rule_name="Brute Force",
        severity="high",
        status="NEW",
        source_ip="192.168.1.5",
        target_asset_id=asset.id,
        target_host=asset.hostname,
        dedup_key="rbac_alert_key",
        occurrence_count=1,
        first_seen=now,
        last_seen=now,
        evidence=["ev1"],
    )

    # 4. Test Incident
    incident = Incident(
        id=str(uuid.uuid4()),
        title="Brute Force Attack on Target VM",
        description="SSH probe",
        severity="high",
        status="OPEN",
        risk_score=40,
        target_asset_id=asset.id,
        target_host=asset.hostname,
    )

    # 5. Test API Key
    api_key = ApiKey(
        id=str(uuid.uuid4()),
        key_hash="rbac_fake_hash_1234567890abcdef",
        name="Test Sensor Key",
        prefix="sen_test1234",
        scope="ingest",
        is_active=True,
    )
    db_session.add_all([alert, incident, api_key])
    await db_session.commit()

    admin_token = create_access_token(
        {"sub": admin.id, "role": admin.role, "username": admin.username}
    )
    analyst_token = create_access_token(
        {"sub": analyst.id, "role": analyst.role, "username": analyst.username}
    )
    auditor_token = create_access_token(
        {"sub": auditor.id, "role": auditor.role, "username": auditor.username}
    )

    return {
        "admin_headers": {"Authorization": f"Bearer {admin_token}"},
        "analyst_headers": {"Authorization": f"Bearer {analyst_token}"},
        "auditor_headers": {"Authorization": f"Bearer {auditor_token}"},
        "asset": asset,
        "alert": alert,
        "incident": incident,
        "api_key": api_key,
    }


@pytest.mark.asyncio
async def test_unauthenticated_requests_rejected(client: AsyncClient, rbac_test_setup: dict):
    """Verifies unauthenticated requests are denied 401 across protected routes."""
    setup = rbac_test_setup
    asset_id = setup["asset"].id
    alert_id = setup["alert"].id
    incident_id = setup["incident"].id
    key_id = setup["api_key"].id

    endpoints = [
        ("GET", "/api/v1/auth/me", None),
        (
            "POST",
            "/api/v1/auth/register",
            {
                "username": "unauth_user",
                "email": "unauth@sentinelx.local",
                "password": "Password123!",
                "role": "Analyst",
            },
        ),
        ("POST", "/api/v1/auth/api-keys", {"name": "unauth_key", "scope": "ingest"}),
        ("GET", "/api/v1/auth/api-keys", None),
        ("DELETE", f"/api/v1/auth/api-keys/{key_id}", None),
        ("GET", "/api/v1/assets", None),
        ("POST", "/api/v1/assets", {"hostname": "unauth_asset"}),
        ("GET", f"/api/v1/assets/{asset_id}", None),
        ("PUT", f"/api/v1/assets/{asset_id}", {"criticality": "low"}),
        ("DELETE", f"/api/v1/assets/{asset_id}", None),
        ("GET", "/api/v1/alerts", None),
        ("GET", f"/api/v1/alerts/{alert_id}", None),
        ("PATCH", f"/api/v1/alerts/{alert_id}/triage", {"status": "RESOLVED"}),
        ("GET", "/api/v1/incidents", None),
        ("GET", f"/api/v1/incidents/{incident_id}", None),
        ("PATCH", f"/api/v1/incidents/{incident_id}", {"status": "RESOLVED"}),
        ("GET", "/api/v1/reports/metrics", None),
        ("GET", "/api/v1/reports/executive", None),
        ("GET", "/api/v1/audit", None),
        ("GET", "/api/v1/audit/verify", None),
    ]

    for method, path, payload in endpoints:
        kwargs = {"json": payload} if payload is not None else {}
        resp = await client.request(method, path, **kwargs)
        assert (
            resp.status_code == 401
        ), f"Expected 401 for unauthenticated {method} {path}, got {resp.status_code}"


@pytest.mark.asyncio
async def test_auditor_permissions_matrix(client: AsyncClient, rbac_test_setup: dict):
    """Validates Auditor role permissions: read-only access, mutations strictly forbidden (403)."""
    setup = rbac_test_setup
    headers = setup["auditor_headers"]
    asset_id = setup["asset"].id
    alert_id = setup["alert"].id
    incident_id = setup["incident"].id
    key_id = setup["api_key"].id

    # 1. Permitted Read Operations (200 OK)
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/assets", headers=headers)).status_code == 200
    assert (await client.get(f"/api/v1/assets/{asset_id}", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/alerts", headers=headers)).status_code == 200
    assert (await client.get(f"/api/v1/alerts/{alert_id}", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/incidents", headers=headers)).status_code == 200
    assert (
        await client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    ).status_code == 200
    assert (await client.get("/api/v1/reports/metrics", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/reports/executive", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/audit", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/audit/verify", headers=headers)).status_code == 200

    # 2. Forbidden Mutation Operations (403 Forbidden)
    assert (
        await client.post(
            "/api/v1/auth/register",
            json={
                "username": "auditor_new_user",
                "email": "aud_new@sentinelx.local",
                "password": "Password123!",
                "role": "Analyst",
            },
            headers=headers,
        )
    ).status_code == 403
    assert (
        await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "forbidden_key", "scope": "ingest"},
            headers=headers,
        )
    ).status_code == 403
    assert (await client.get("/api/v1/auth/api-keys", headers=headers)).status_code == 403
    assert (
        await client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=headers)
    ).status_code == 403
    assert (
        await client.post(
            "/api/v1/assets",
            json={"hostname": "auditor_asset"},
            headers=headers,
        )
    ).status_code == 403
    assert (
        await client.put(
            f"/api/v1/assets/{asset_id}",
            json={"criticality": "low"},
            headers=headers,
        )
    ).status_code == 403
    assert (await client.delete(f"/api/v1/assets/{asset_id}", headers=headers)).status_code == 403
    assert (
        await client.patch(
            f"/api/v1/alerts/{alert_id}/triage", json={"status": "RESOLVED"}, headers=headers
        )
    ).status_code == 403
    assert (
        await client.patch(
            f"/api/v1/incidents/{incident_id}", json={"status": "RESOLVED"}, headers=headers
        )
    ).status_code == 403


@pytest.mark.asyncio
async def test_analyst_permissions_matrix(client: AsyncClient, rbac_test_setup: dict):
    """Validates Analyst role: triage allowed; admin endpoints and raw audit logs forbidden (403)."""
    setup = rbac_test_setup
    headers = setup["analyst_headers"]
    asset_id = setup["asset"].id
    alert_id = setup["alert"].id
    incident_id = setup["incident"].id
    key_id = setup["api_key"].id

    # 1. Permitted Operations
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/assets", headers=headers)).status_code == 200
    assert (await client.get(f"/api/v1/assets/{asset_id}", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/alerts", headers=headers)).status_code == 200
    assert (await client.get(f"/api/v1/alerts/{alert_id}", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/incidents", headers=headers)).status_code == 200
    assert (
        await client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    ).status_code == 200
    assert (await client.get("/api/v1/reports/metrics", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/reports/executive", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/audit/verify", headers=headers)).status_code == 200

    # Operational triage permitted for Analyst
    triage_res = await client.patch(
        f"/api/v1/alerts/{alert_id}/triage",
        json={"status": "INVESTIGATING", "notes": "Analyst investigating"},
        headers=headers,
    )
    assert triage_res.status_code == 200

    inc_update_res = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "INVESTIGATING", "notes": "Analyst engaged"},
        headers=headers,
    )
    assert inc_update_res.status_code == 200

    # 2. Forbidden Operations for Analyst (403 Forbidden)
    # Cannot view raw audit logs (only verify)
    assert (await client.get("/api/v1/audit", headers=headers)).status_code == 403
    # Cannot administer users or API keys
    assert (
        await client.post(
            "/api/v1/auth/register",
            json={
                "username": "analyst_new_user",
                "email": "ana_new@sentinelx.local",
                "password": "Password123!",
                "role": "Analyst",
            },
            headers=headers,
        )
    ).status_code == 403
    assert (
        await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "analyst_key", "scope": "ingest"},
            headers=headers,
        )
    ).status_code == 403
    assert (await client.get("/api/v1/auth/api-keys", headers=headers)).status_code == 403
    assert (
        await client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=headers)
    ).status_code == 403
    # Cannot mutate CMDB assets
    assert (
        await client.post(
            "/api/v1/assets",
            json={"hostname": "analyst_asset"},
            headers=headers,
        )
    ).status_code == 403
    assert (
        await client.put(
            f"/api/v1/assets/{asset_id}",
            json={"criticality": "low"},
            headers=headers,
        )
    ).status_code == 403
    assert (await client.delete(f"/api/v1/assets/{asset_id}", headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_admin_permissions_matrix(client: AsyncClient, rbac_test_setup: dict):
    """Validates Admin role has complete operational and administrative access."""
    setup = rbac_test_setup
    headers = setup["admin_headers"]
    asset_id = setup["asset"].id
    alert_id = setup["alert"].id
    incident_id = setup["incident"].id

    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/assets", headers=headers)).status_code == 200
    assert (await client.get(f"/api/v1/assets/{asset_id}", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/alerts", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/incidents", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/reports/metrics", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/reports/executive", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/audit", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/audit/verify", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/auth/api-keys", headers=headers)).status_code == 200

    # User registration permitted for Admin
    new_reg = await client.post(
        "/api/v1/auth/register",
        json={
            "username": "new_analyst_99",
            "email": "analyst99@sentinelx.local",
            "password": "Password99!",
            "role": "Analyst",
        },
        headers=headers,
    )
    assert new_reg.status_code == 201

    # Asset creation permitted for Admin
    new_asset = await client.post(
        "/api/v1/assets",
        json={"hostname": "admin-created-asset", "criticality": "low"},
        headers=headers,
    )
    assert new_asset.status_code == 201

    # Triage permitted for Admin
    triage_res = await client.patch(
        f"/api/v1/alerts/{alert_id}/triage",
        json={"status": "FALSE_POSITIVE", "notes": "Admin marked FP"},
        headers=headers,
    )
    assert triage_res.status_code == 200

    # Incident update permitted for Admin
    inc_update_res = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "CLOSED", "notes": "Admin closed incident"},
        headers=headers,
    )
    assert inc_update_res.status_code == 200
