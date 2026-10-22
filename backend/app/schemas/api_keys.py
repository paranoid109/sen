"""Pydantic Schemas for Ingest API Key Management."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ApiKeyCreateRequest(BaseModel):
    """Payload to generate a new API key."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    scope: str = "ingest"
    asset_id: str | None = None


class ApiKeyCreatedResponse(BaseModel):
    """One-time response returning the plaintext API key."""

    id: str
    name: str
    raw_key: str
    prefix: str
    scope: str
    asset_id: str | None
    created_at: datetime


class ApiKeyResponse(BaseModel):
    """Public representation of an existing API key without revealing the secret."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    prefix: str
    scope: str
    asset_id: str | None
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None
