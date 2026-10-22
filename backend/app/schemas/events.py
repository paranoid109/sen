"""Pydantic Schemas for Ingestion API Requests and Responses (M3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SingleIngestRequest(BaseModel):
    """Payload representing a single telemetry event submitted via HTTP."""

    model_config = ConfigDict(extra="forbid")

    source_ip: str
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    source_port: int | None = Field(default=None, ge=1, le=65535)
    event_type: str
    target_host: str | None = None
    asset_id: str | None = None
    event_time: datetime | None = None
    raw_payload: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class BatchIngestRequest(BaseModel):
    """Payload representing multiple telemetry events submitted together."""

    model_config = ConfigDict(extra="forbid")

    events: list[SingleIngestRequest]
    asset_id: str | None = None
    target_host: str | None = None


class IngestResponse(BaseModel):
    """API response summarizing the result of ingestion."""

    ingested_count: int
    event_ids: list[str]
    status: str = "success"
