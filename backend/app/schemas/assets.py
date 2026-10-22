"""Pydantic Schemas for CMDB Asset Management (M2)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class AssetCreate(BaseModel):
    """Payload to register a new tracked asset in CMDB."""

    model_config = ConfigDict(extra="forbid")

    hostname: str | None = None
    ip_address: str | None = None
    asset_type: str = "server"
    criticality: Literal["critical", "high", "medium", "low"] = "low"
    description: str | None = None


class AssetUpdate(BaseModel):
    """Payload to update an existing CMDB asset."""

    model_config = ConfigDict(extra="forbid")

    hostname: str | None = None
    ip_address: str | None = None
    asset_type: str | None = None
    criticality: Literal["critical", "high", "medium", "low"] | None = None
    description: str | None = None


class AssetResponse(BaseModel):
    """Public representation of an asset."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    hostname: str | None
    ip_address: str | None
    asset_type: str
    criticality: str
    description: str | None
    created_at: datetime
    updated_at: datetime
