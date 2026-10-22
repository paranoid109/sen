"""Incidents API Endpoints (M6)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import require_role
from backend.app.models.user import User
from backend.app.schemas.alerts import AlertResponse
from backend.app.schemas.incidents import (
    IncidentDetailResponse,
    IncidentResponse,
    IncidentTimelineCreateRequest,
    IncidentTimelineResponse,
    IncidentUpdateRequest,
)
from backend.app.services.incident_service import incident_service

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
    status: str | None = Query(
        None, description="Filter by status (OPEN, INVESTIGATING, RESOLVED, CLOSED)"
    ),
    severity: str | None = Query(
        None, description="Filter by severity (critical, high, medium, low)"
    ),
    target_asset_id: str | None = Query(None, description="Filter by target asset UUID"),
    search: str | None = Query(None, description="Search by title, host, or description"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> list[IncidentResponse]:
    """Retrieves correlated security incidents with summary alert counts."""
    incidents = await incident_service.list_incidents(
        db,
        status=status,
        severity=severity,
        target_asset_id=target_asset_id,
        search=search,
        skip=skip,
        limit=limit,
    )
    results: list[IncidentResponse] = []
    for inc in incidents:
        results.append(
            IncidentResponse(
                id=inc.id,
                title=inc.title,
                description=inc.description,
                severity=inc.severity,
                status=inc.status,
                risk_score=inc.risk_score,
                target_asset_id=inc.target_asset_id,
                target_host=inc.target_host,
                alert_count=len(inc.incident_alerts),
                created_at=inc.created_at,
                updated_at=inc.updated_at,
            )
        )
    return results


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> IncidentDetailResponse:
    """Retrieves detailed incident view including correlated alerts and chronological timeline."""
    inc = await incident_service.get_incident(db, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    alerts_list = [
        AlertResponse.model_validate(ia.alert) for ia in inc.incident_alerts if ia.alert is not None
    ]
    timeline_list = [IncidentTimelineResponse.model_validate(t) for t in inc.timeline]

    return IncidentDetailResponse(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        risk_score=inc.risk_score,
        target_asset_id=inc.target_asset_id,
        target_host=inc.target_host,
        alert_count=len(inc.incident_alerts),
        alerts=alerts_list,
        timeline=timeline_list,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.patch("/{incident_id}", response_model=IncidentDetailResponse)
async def update_incident(
    incident_id: str,
    request: IncidentUpdateRequest,
    current_user: User = Depends(require_role(["Admin", "Analyst"])),
    db: AsyncSession = Depends(get_db),
) -> IncidentDetailResponse:
    """Updates an incident's lifecycle status or narrative and records an audit timeline entry."""
    inc = await incident_service.update_incident(
        db,
        incident_id=incident_id,
        new_status=request.status,
        description=request.description,
        notes=request.notes,
        user_id=current_user.username,
    )
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    alerts_list = [
        AlertResponse.model_validate(ia.alert) for ia in inc.incident_alerts if ia.alert is not None
    ]
    timeline_list = [IncidentTimelineResponse.model_validate(t) for t in inc.timeline]

    return IncidentDetailResponse(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        risk_score=inc.risk_score,
        target_asset_id=inc.target_asset_id,
        target_host=inc.target_host,
        alert_count=len(inc.incident_alerts),
        alerts=alerts_list,
        timeline=timeline_list,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.post(
    "/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_incident_timeline_entry(
    incident_id: str,
    request: IncidentTimelineCreateRequest,
    current_user: User = Depends(require_role(["Admin", "Analyst"])),
    db: AsyncSession = Depends(get_db),
) -> IncidentTimelineResponse:
    """Records a containment playbook execution or digital forensics triage entry onto the incident timeline."""
    entry = await incident_service.add_timeline_entry(
        db,
        incident_id=incident_id,
        event_type=request.event_type,
        description=request.description,
        source=request.source,
        user_id=current_user.username,
        details=request.details,
    )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return IncidentTimelineResponse.model_validate(entry)
