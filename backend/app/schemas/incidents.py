"""Pydantic Schemas for Incident Investigation and Correlation (M6)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.alerts import AlertResponse


class IncidentTimelineResponse(BaseModel):
    """Timeline entry attached to an incident."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    event_type: str
    description: str
    source: str


class IncidentTimelineCreateRequest(BaseModel):
    """Payload to append a containment, remediation, or triage event to an incident timeline."""

    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(..., min_length=1, max_length=64)
    description: str = Field(..., min_length=1)
    source: str = Field(default="SOAR_Playbook", min_length=1, max_length=64)
    details: dict[str, object] | None = None


class IncidentUpdateRequest(BaseModel):
    """Payload to update an incident's lifecycle status or narrative."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"] | None = None
    description: str | None = None
    notes: str | None = None


class IncidentResponse(BaseModel):
    """Summary response for incident list views."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str | None
    severity: str
    status: str
    risk_score: int = Field(ge=0, le=100)
    target_asset_id: str | None
    target_host: str | None
    alert_count: int = 0
    created_at: datetime
    updated_at: datetime


class IncidentDetailResponse(BaseModel):
    """Full detail response including correlated alerts and chronological timeline."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str | None
    severity: str
    status: str
    risk_score: int = Field(ge=0, le=100)
    target_asset_id: str | None
    target_host: str | None
    alert_count: int = 0
    alerts: list[AlertResponse] = Field(default_factory=list)
    timeline: list[IncidentTimelineResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
