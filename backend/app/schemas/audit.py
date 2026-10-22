"""Pydantic Schemas for Tamper-Evident Audit Logging (Law 4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    """Public representation of a hash-chained audit record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    sequence_number: int
    timestamp: datetime
    user_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    status: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str


class AuditVerifyResponse(BaseModel):
    """Cryptographic verification status of the entire audit chain."""

    is_valid: bool
    total_records: int
    error_message: str | None = None
    broken_sequence: int | None = None
