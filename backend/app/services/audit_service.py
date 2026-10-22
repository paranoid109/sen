"""Tamper-Evident Hash-Chained Audit Service (Law 4).

Enforces sequential integrity and cryptographic chaining across security-critical mutations
using an asyncio.Lock mutex in a single-worker architecture.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.audit import AuditLog

GENESIS_PREV_HASH = "0" * 64


class AuditService:
    """Service managing tamper-evident audit logging and verification."""

    def __init__(self) -> None:
        self._lock: asyncio.Lock | None = None

    @property
    def lock(self) -> asyncio.Lock:
        """Lazily instantiates an asyncio.Lock bound to the current running loop."""
        try:
            curr_loop = asyncio.get_running_loop()
        except RuntimeError:
            curr_loop = None

        if self._lock is None or (
            hasattr(self._lock, "_loop")
            and self._lock._loop is not None
            and self._lock._loop is not curr_loop
        ):
            self._lock = asyncio.Lock()
        return self._lock

    @staticmethod
    def compute_entry_hash(
        prev_hash: str,
        timestamp_str: str,
        user_id: str | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        status: str,
        details: dict[str, Any],
    ) -> str:
        """Deterministically computes the SHA-256 entry hash."""
        details_str = json.dumps(details, sort_keys=True)
        raw_payload = (
            f"{prev_hash}|{timestamp_str}|{user_id or 'system'}|"
            f"{action}|{resource_type}|{resource_id or ''}|{status}|{details_str}"
        )
        return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    async def log_action(
        self,
        session: AsyncSession,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        user_id: str | None = None,
        status: str = "SUCCESS",
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Records an auditable mutation inside an asyncio.Lock to guarantee sequential ordering."""
        details_dict = details or {}
        now = datetime.now(UTC)
        iso_timestamp = now.isoformat()

        async with self.lock:
            # Query the latest entry in the chain
            stmt = select(AuditLog).order_by(AuditLog.sequence_number.desc()).limit(1)
            result = await session.execute(stmt)
            last_entry = result.scalars().first()

            if last_entry is None:
                next_seq = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                next_seq = last_entry.sequence_number + 1
                prev_hash = last_entry.entry_hash

            entry_hash = self.compute_entry_hash(
                prev_hash=prev_hash,
                timestamp_str=iso_timestamp,
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                details=details_dict,
            )

            audit_entry = AuditLog(
                id=str(uuid.uuid4()),
                sequence_number=next_seq,
                timestamp=now,
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                details=details_dict,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            session.add(audit_entry)
            await session.commit()
            await session.refresh(audit_entry)
            return audit_entry

    async def verify_chain(self, session: AsyncSession) -> tuple[bool, int, str | None, int | None]:
        """Walks the complete audit log sequence and cryptographically verifies the hash chain.

        Returns:
            (is_valid, total_records, error_message, broken_sequence_number)
        """
        stmt = select(AuditLog).order_by(AuditLog.sequence_number.asc())
        result = await session.execute(stmt)
        records = list(result.scalars().all())

        if not records:
            return True, 0, None, None

        expected_seq = 1
        expected_prev_hash = GENESIS_PREV_HASH

        for record in records:
            if record.sequence_number != expected_seq:
                return (
                    False,
                    len(records),
                    f"Sequence break: expected {expected_seq}, found {record.sequence_number}",
                    record.sequence_number,
                )

            if record.prev_hash != expected_prev_hash:
                return (
                    False,
                    len(records),
                    f"Previous hash mismatch at sequence {record.sequence_number}",
                    record.sequence_number,
                )

            recalculated = self.compute_entry_hash(
                prev_hash=record.prev_hash,
                timestamp_str=record.timestamp.isoformat(),
                user_id=record.user_id,
                action=record.action,
                resource_type=record.resource_type,
                resource_id=record.resource_id,
                status=record.status,
                details=record.details,
            )

            if record.entry_hash != recalculated:
                return (
                    False,
                    len(records),
                    f"Tampered entry hash at sequence {record.sequence_number}",
                    record.sequence_number,
                )

            expected_seq += 1
            expected_prev_hash = record.entry_hash

        return True, len(records), None, None


audit_service = AuditService()
