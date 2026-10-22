"""Unit tests for Tamper-Evident Hash Chaining and Audit Integrity (Law 4).

Verifies cryptographic SHA-256 chaining, genesis initialization, sequential concurrency
protection via asyncio.Lock, and automatic detection of database tampering.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.audit import AuditLog
from backend.app.services.audit_service import GENESIS_PREV_HASH, audit_service


@pytest.mark.asyncio
async def test_genesis_audit_entry(db_session: AsyncSession):
    entry = await audit_service.log_action(
        db_session,
        action="AUTH_LOGIN",
        resource_type="user",
        user_id="analyst-1",
        status="SUCCESS",
        details={"ip": "192.168.1.100"},
    )

    assert entry.sequence_number == 1
    assert entry.prev_hash == GENESIS_PREV_HASH
    assert len(entry.entry_hash) == 64

    is_valid, count, error, broken_seq = await audit_service.verify_chain(db_session)
    assert is_valid is True
    assert count == 1
    assert error is None


@pytest.mark.asyncio
async def test_hash_chaining_continuity(db_session: AsyncSession):
    e1 = await audit_service.log_action(
        db_session,
        action="USER_CREATE",
        resource_type="user",
        resource_id="user-1",
        user_id="admin-1",
    )
    e2 = await audit_service.log_action(
        db_session,
        action="ASSET_CREATE",
        resource_type="asset",
        resource_id="asset-1",
        user_id="admin-1",
    )
    e3 = await audit_service.log_action(
        db_session,
        action="ALERT_TRIAGE",
        resource_type="alert",
        resource_id="alert-1",
        user_id="analyst-1",
        details={"new_status": "INVESTIGATING"},
    )

    assert e1.sequence_number == 1
    assert e2.sequence_number == 2
    assert e3.sequence_number == 3

    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash

    is_valid, count, error, broken_seq = await audit_service.verify_chain(db_session)
    assert is_valid is True
    assert count == 3
    assert error is None


@pytest.mark.asyncio
async def test_tampering_detection_modified_payload(db_session: AsyncSession):
    await audit_service.log_action(
        db_session, action="AUTH_LOGIN", resource_type="user", status="SUCCESS"
    )
    e2 = await audit_service.log_action(
        db_session, action="ASSET_UPDATE", resource_type="asset", status="SUCCESS"
    )

    # Tamper with the database row directly
    stmt = select(AuditLog).where(AuditLog.id == e2.id)
    res = await db_session.execute(stmt)
    tampered_row = res.scalars().one()
    tampered_row.action = "UNAUTHORIZED_ACTION"
    await db_session.commit()

    # Verification must fail
    is_valid, count, error, broken_seq = await audit_service.verify_chain(db_session)
    assert is_valid is False
    assert broken_seq == 2
    assert "Tampered entry hash" in str(error)


@pytest.mark.asyncio
async def test_tampering_detection_deleted_row(db_session: AsyncSession):
    await audit_service.log_action(db_session, action="ACTION_1", resource_type="sys")
    e2 = await audit_service.log_action(db_session, action="ACTION_2", resource_type="sys")
    await audit_service.log_action(db_session, action="ACTION_3", resource_type="sys")

    # Delete intermediate row e2
    stmt = select(AuditLog).where(AuditLog.id == e2.id)
    res = await db_session.execute(stmt)
    row_to_delete = res.scalars().one()
    await db_session.delete(row_to_delete)
    await db_session.commit()

    is_valid, count, error, broken_seq = await audit_service.verify_chain(db_session)
    assert is_valid is False
    assert "Sequence break" in str(error)


@pytest.mark.asyncio
async def test_concurrent_audit_logging_order(db_session: AsyncSession):
    # Log 10 actions concurrently to test asyncio.Lock serialization
    async def log_item(idx: int):
        return await audit_service.log_action(
            db_session,
            action=f"CONCURRENT_ACTION_{idx}",
            resource_type="test",
            details={"index": idx},
        )

    tasks = [log_item(i) for i in range(10)]
    entries = await asyncio.gather(*tasks)

    # Check that sequence numbers are strictly 1..10
    sequences = sorted([e.sequence_number for e in entries])
    assert sequences == list(range(1, 11))

    # Cryptographic chain must be 100% valid
    is_valid, count, error, broken_seq = await audit_service.verify_chain(db_session)
    assert is_valid is True
    assert count == 10
    assert error is None
