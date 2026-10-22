"""Unit tests for Authentication, Rate Limiting, and API Key Management (M1)."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.security import (
    create_access_token,
    decode_access_token,
    hash_api_key,
    hash_password,
    verify_password,
)
from backend.app.models.asset import Asset
from backend.app.models.audit import AuditLog
from backend.app.schemas.api_keys import ApiKeyCreateRequest
from backend.app.schemas.auth import UserCreate
from backend.app.services.auth_service import auth_service


@pytest.mark.asyncio
async def test_password_hashing_and_verification():
    """Validates bcrypt password hashing, verification, and bounding."""
    pw = "SuperSecretPassword123!"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


@pytest.mark.asyncio
async def test_jwt_token_generation_and_decoding():
    """Validates PyJWT token generation, claims, and verification."""
    data = {"sub": "user-uuid-123", "role": "Analyst", "username": "analyst_bob"}
    token = create_access_token(data, expires_delta=timedelta(minutes=30))
    decoded = decode_access_token(token)
    assert decoded["sub"] == "user-uuid-123"
    assert decoded["role"] == "Analyst"
    assert decoded["username"] == "analyst_bob"


@pytest.mark.asyncio
async def test_register_user_success_and_duplicates(db_session: AsyncSession):
    """Validates user registration and unique constraint enforcement."""
    req = UserCreate(
        username="john_doe",
        email="john@sentinelx.local",
        password="SecurePassword123!",
        role="Analyst",
    )
    user = await auth_service.register_user(db_session, req, created_by="admin_alice")
    assert user.id is not None
    assert user.username == "john_doe"
    assert user.email == "john@sentinelx.local"
    assert user.role == "Analyst"
    assert verify_password("SecurePassword123!", user.hashed_password) is True

    # Duplicate username check
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.register_user(
            db_session,
            UserCreate(
                username="john_doe",
                email="different@sentinelx.local",
                password="SecurePassword123!",
                role="Analyst",
            ),
        )
    assert exc_info.value.status_code == 400
    assert "Username" in exc_info.value.detail

    # Duplicate email check
    with pytest.raises(HTTPException) as exc_info2:
        await auth_service.register_user(
            db_session,
            UserCreate(
                username="unique_name",
                email="john@sentinelx.local",
                password="SecurePassword123!",
                role="Analyst",
            ),
        )
    assert exc_info2.value.status_code == 400
    assert "Email" in exc_info2.value.detail


@pytest.mark.asyncio
async def test_login_success_and_audit(db_session: AsyncSession):
    """Validates successful login and audit trail logging."""
    await auth_service.register_user(
        db_session,
        UserCreate(
            username="alice_sec",
            email="alice@sentinelx.local",
            password="AlicePassword123!",
            role="Admin",
        ),
    )

    user = await auth_service.authenticate_user(
        db_session,
        username="alice_sec",
        password="AlicePassword123!",
        client_ip="192.168.1.50",
    )
    assert user.username == "alice_sec"

    # Verify LOGIN_SUCCESS audit log record
    stmt = (
        select(AuditLog)
        .where(AuditLog.action == "LOGIN_SUCCESS", AuditLog.user_id == "alice_sec")
        .order_by(AuditLog.sequence_number.desc())
    )
    result = await db_session.execute(stmt)
    log = result.scalars().first()
    assert log is not None
    assert log.resource_id == "192.168.1.50"
    assert log.status == "SUCCESS"


@pytest.mark.asyncio
async def test_login_invalid_password_and_inactive_user(db_session: AsyncSession):
    """Validates login rejection on wrong password and inactive account."""
    user = await auth_service.register_user(
        db_session,
        UserCreate(
            username="bob_sec",
            email="bob@sentinelx.local",
            password="BobPassword123!",
            role="Analyst",
        ),
    )

    # Wrong password -> 401
    with pytest.raises(HTTPException) as exc:
        await auth_service.authenticate_user(
            db_session,
            username="bob_sec",
            password="WrongPassword!",
            client_ip="10.0.0.1",
        )
    assert exc.value.status_code == 401

    # Verify LOGIN_FAILED audit log recorded
    stmt = select(AuditLog).where(AuditLog.action == "LOGIN_FAILED", AuditLog.user_id == "bob_sec")
    res = await db_session.execute(stmt)
    assert res.scalars().first() is not None

    # Inactivate user -> 403
    user.is_active = False
    await db_session.commit()

    with pytest.raises(HTTPException) as exc2:
        await auth_service.authenticate_user(
            db_session,
            username="bob_sec",
            password="BobPassword123!",
            client_ip="10.0.0.1",
        )
    assert exc2.value.status_code == 403
    assert "Inactive" in exc2.value.detail


@pytest.mark.asyncio
async def test_login_rate_limiting_and_flood_prevention(db_session: AsyncSession):
    """Validates dual-threshold rate limiting and table-flood mitigation (Law 4 / S3 / U5)."""
    await auth_service.register_user(
        db_session,
        UserCreate(
            username="target_user",
            email="target@sentinelx.local",
            password="TargetPassword123!",
            role="Analyst",
        ),
    )

    client_ip = "198.51.100.25"

    # Execute 5 failed login attempts (reaching the threshold)
    for _ in range(settings.RATE_LIMIT_LOGIN_ATTEMPTS):
        with pytest.raises(HTTPException) as exc:
            await auth_service.authenticate_user(
                db_session,
                username="target_user",
                password="WrongPassword!",
                client_ip=client_ip,
            )
        assert exc.value.status_code == 401

    # Count audit logs after 5 failures
    count_stmt = select(func.count()).select_from(AuditLog).where(AuditLog.action == "LOGIN_FAILED")
    initial_failed_logs = (await db_session.execute(count_stmt)).scalar() or 0
    assert initial_failed_logs == 5

    # 6th attempt: Must return 429 Too Many Requests
    with pytest.raises(HTTPException) as exc_limit:
        await auth_service.authenticate_user(
            db_session,
            username="target_user",
            password="WrongPassword!",
            client_ip=client_ip,
        )
    assert exc_limit.value.status_code == 429
    assert "Too many failed login attempts" in exc_limit.value.detail

    # Crucial Flood Protection Test: No new audit record should have been written for the 429!
    final_failed_logs = (await db_session.execute(count_stmt)).scalar() or 0
    assert final_failed_logs == initial_failed_logs, "Rate limiting must not flood AuditLog table"


@pytest.mark.asyncio
async def test_api_key_lifecycle_and_asset_binding(db_session: AsyncSession):
    """Validates API key creation, hashing, asset binding, and deletion."""
    # 1. Register monitored asset
    asset = Asset(
        id=str(uuid.uuid4()),
        hostname="telemetry-host-01",
        ip_address="10.10.10.1",
        asset_type="server",
        criticality="high",
        description="Edge Gateway",
    )
    db_session.add(asset)
    await db_session.commit()

    # 2. Create API key bound to asset
    req = ApiKeyCreateRequest(
        name="Agent Key 1",
        scope="ingest",
        asset_id=asset.id,
    )
    api_key, raw_key = await auth_service.create_api_key(db_session, req, created_by="admin_alice")

    assert raw_key.startswith("sen_")
    assert api_key.prefix == raw_key[:12]
    assert api_key.key_hash == hash_api_key(raw_key)
    assert api_key.asset_id == asset.id
    assert api_key.is_active is True

    # 3. List API keys
    keys = await auth_service.list_api_keys(db_session)
    assert len(keys) == 1
    assert keys[0].id == api_key.id
    assert keys[0].name == "Agent Key 1"

    # 4. Delete API key
    deleted = await auth_service.delete_api_key(db_session, api_key.id, deleted_by="admin_alice")
    assert deleted is True

    # Verify key deleted from DB
    remaining = await auth_service.list_api_keys(db_session)
    assert len(remaining) == 0

    # Non-existent delete returns False
    assert await auth_service.delete_api_key(db_session, "non-existent-id") is False


@pytest.mark.asyncio
async def test_auth_rest_api_endpoints(client: AsyncClient, db_session: AsyncSession):
    """Validates REST endpoints for login, profile, bootstrap registration, and API keys."""
    # 1. Bootstrap registration when user table is empty
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "username": "superadmin",
            "email": "admin@sentinelx.local",
            "password": "AdminPassword123!",
            "role": "Admin",
        },
    )
    assert reg_resp.status_code == 201
    admin_data = reg_resp.json()
    assert admin_data["username"] == "superadmin"
    assert admin_data["role"] == "Admin"

    # 2. Login via REST
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "AdminPassword123!"},
    )
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    token = token_data["access_token"]
    auth_header = {"Authorization": f"Bearer {token}"}

    # 3. GET /api/v1/auth/me
    me_resp = await client.get("/api/v1/auth/me", headers=auth_header)
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "superadmin"

    # 4. Generate API key via REST
    key_resp = await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "Logstash Collector", "scope": "ingest"},
        headers=auth_header,
    )
    assert key_resp.status_code == 201
    key_data = key_resp.json()
    assert "raw_key" in key_data
    key_id = key_data["id"]

    # 5. List API keys via REST
    list_keys_resp = await client.get("/api/v1/auth/api-keys", headers=auth_header)
    assert list_keys_resp.status_code == 200
    keys_list = list_keys_resp.json()
    assert len(keys_list) == 1
    assert "raw_key" not in keys_list[0]
    assert "key_hash" not in keys_list[0]

    # 6. Delete API key via REST
    del_resp = await client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=auth_header)
    assert del_resp.status_code == 200
