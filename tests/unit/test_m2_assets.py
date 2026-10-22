"""Unit tests for CMDB Asset Inventory Management and Target Resolution (M2)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.security import create_access_token, hash_password
from backend.app.models.audit import AuditLog
from backend.app.models.user import User
from backend.app.schemas.assets import AssetCreate, AssetUpdate
from backend.app.services.asset_service import asset_service


@pytest.mark.asyncio
async def test_asset_crud_and_audit_logging(db_session: AsyncSession):
    """Validates asset registration, retrieval, updating, deletion, and audit logging."""
    # 1. Create asset
    asset_in = AssetCreate(
        hostname="db-prod-01",
        ip_address="10.0.0.15",
        asset_type="database",
        criticality="critical",
        description="Core PostgreSQL Cluster",
    )
    asset = await asset_service.create_asset(db_session, asset_in, user_id="admin_sec")
    assert asset.id is not None
    assert asset.hostname == "db-prod-01"
    assert asset.criticality == "critical"

    # Verify ASSET_CREATED audit log
    stmt = select(AuditLog).where(
        AuditLog.action == "ASSET_CREATED", AuditLog.resource_id == asset.id
    )
    audit_res = await db_session.execute(stmt)
    create_log = audit_res.scalars().first()
    assert create_log is not None
    assert create_log.user_id == "admin_sec"
    assert create_log.details["criticality"] == "critical"

    # 2. Get asset
    fetched = await asset_service.get_asset(db_session, asset.id)
    assert fetched is not None
    assert fetched.hostname == "db-prod-01"

    # 3. Update asset
    update_in = AssetUpdate(
        criticality="high",
        description="Downgraded to High post-failover",
    )
    updated = await asset_service.update_asset(db_session, asset.id, update_in, user_id="admin_sec")
    assert updated is not None
    assert updated.criticality == "high"
    assert updated.description == "Downgraded to High post-failover"

    # Verify ASSET_UPDATED audit log
    stmt_up = select(AuditLog).where(
        AuditLog.action == "ASSET_UPDATED", AuditLog.resource_id == asset.id
    )
    audit_up_res = await db_session.execute(stmt_up)
    update_log = audit_up_res.scalars().first()
    assert update_log is not None
    assert update_log.details["criticality"] == "high"

    # 4. Delete asset
    deleted = await asset_service.delete_asset(db_session, asset.id, user_id="admin_sec")
    assert deleted is True

    # Verify ASSET_DELETED audit log
    stmt_del = select(AuditLog).where(
        AuditLog.action == "ASSET_DELETED", AuditLog.resource_id == asset.id
    )
    audit_del_res = await db_session.execute(stmt_del)
    del_log = audit_del_res.scalars().first()
    assert del_log is not None

    # Verify asset is gone
    assert await asset_service.get_asset(db_session, asset.id) is None


@pytest.mark.asyncio
async def test_asset_pagination(db_session: AsyncSession):
    """Validates CMDB asset listing with skip and limit parameters."""
    for i in range(5):
        await asset_service.create_asset(
            db_session,
            AssetCreate(
                hostname=f"node-0{i}.cluster.local",
                ip_address=f"10.200.0.{i+1}",
                asset_type="server",
                criticality="medium",
            ),
        )

    all_assets = await asset_service.list_assets(db_session, skip=0, limit=10)
    assert len(all_assets) == 5

    page1 = await asset_service.list_assets(db_session, skip=0, limit=2)
    assert len(page1) == 2

    page2 = await asset_service.list_assets(db_session, skip=2, limit=2)
    assert len(page2) == 2
    assert page1[0].id != page2[0].id


@pytest.mark.asyncio
async def test_target_asset_resolution_priority(db_session: AsyncSession):
    """Validates target asset resolution priority: ID > Hostname > IP."""
    a1 = await asset_service.create_asset(
        db_session,
        AssetCreate(
            hostname="host-alpha",
            ip_address="172.16.0.10",
            criticality="critical",
        ),
    )
    a2 = await asset_service.create_asset(
        db_session,
        AssetCreate(
            hostname="host-beta",
            ip_address="172.16.0.20",
            criticality="medium",
        ),
    )

    # 1. Exact asset_id resolution
    res1 = await asset_service.resolve_target_asset(db_session, asset_id=a1.id)
    assert res1 is not None
    assert res1.id == a1.id

    # 2. Hostname resolution
    res2 = await asset_service.resolve_target_asset(db_session, target_host="host-beta")
    assert res2 is not None
    assert res2.id == a2.id

    # 3. IP address resolution
    res3 = await asset_service.resolve_target_asset(db_session, destination_ip="172.16.0.10")
    assert res3 is not None
    assert res3.id == a1.id

    # 4. Unknown host/IP returns None
    res_unknown = await asset_service.resolve_target_asset(
        db_session, target_host="nonexistent", destination_ip="1.1.1.1"
    )
    assert res_unknown is None


@pytest.mark.asyncio
async def test_assets_rest_api_endpoints(client: AsyncClient, db_session: AsyncSession):
    """Validates REST endpoints for CMDB asset management."""
    # Create admin user for API authorization
    admin = User(
        id=str(uuid.uuid4()),
        username="admin_asset_tester",
        email="assetadmin@sentinelx.local",
        hashed_password=hash_password("Pass123!"),
        role="Admin",
        is_active=True,
    )
    db_session.add(admin)
    await db_session.commit()

    token = create_access_token({"sub": admin.id, "role": admin.role, "username": admin.username})
    auth_header = {"Authorization": f"Bearer {token}"}

    # 1. POST /api/v1/assets
    create_resp = await client.post(
        "/api/v1/assets",
        json={
            "hostname": "firewall-edge-01",
            "ip_address": "192.168.0.1",
            "asset_type": "firewall",
            "criticality": "critical",
            "description": "Perimeter Next-Gen Firewall",
        },
        headers=auth_header,
    )
    assert create_resp.status_code == 201
    asset_data = create_resp.json()
    asset_id = asset_data["id"]
    assert asset_data["hostname"] == "firewall-edge-01"

    # 2. GET /api/v1/assets
    list_resp = await client.get("/api/v1/assets", headers=auth_header)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1

    # 3. GET /api/v1/assets/{id}
    get_resp = await client.get(f"/api/v1/assets/{asset_id}", headers=auth_header)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == asset_id

    # 4. PUT /api/v1/assets/{id}
    put_resp = await client.put(
        f"/api/v1/assets/{asset_id}",
        json={"criticality": "high", "description": "Updated FW description"},
        headers=auth_header,
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["criticality"] == "high"

    # 5. DELETE /api/v1/assets/{id}
    del_resp = await client.delete(f"/api/v1/assets/{asset_id}", headers=auth_header)
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "success"

    # 6. Verify 404 after deletion
    get_after_del = await client.get(f"/api/v1/assets/{asset_id}", headers=auth_header)
    assert get_after_del.status_code == 404
