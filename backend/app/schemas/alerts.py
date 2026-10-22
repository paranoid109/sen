"""Pydantic Schemas for Alert Triage and Retrieval (M5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class AlertTriageRequest(BaseModel):
    """Payload to transition the triage status of an alert."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    notes: str | None = None


class AlertEvidenceEventResponse(BaseModel):
    """Hydrated security event record linked to an alert's forensic evidence."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    event_time: datetime
    event_type: str
    source_ip: str
    destination_ip: str | None = None
    destination_port: int | None = None
    target_host: str | None = None
    raw_payload: str | None = None
    details: dict[str, Any] = {}


class AlertResponse(BaseModel):
    """Public representation of a curated alert."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    rule_name: str
    severity: str
    status: str
    mitre_attack_id: str | None
    source_ip: str
    target_asset_id: str | None
    target_host: str | None
    dedup_key: str
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]
    created_at: datetime
    updated_at: datetime
