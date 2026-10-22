"""Alerts API Endpoints (M5)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import require_role
from backend.app.models.user import User
from backend.app.schemas.alerts import (
    AlertEvidenceEventResponse,
    AlertResponse,
    AlertTriageRequest,
)
from backend.app.services.alert_service import alert_service

router = APIRouter(prefix="/alerts", tags=["Alert Management"])


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    status: str | None = Query(
        None, description="Filter by status (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE)"
    ),
    severity: str | None = Query(
        None, description="Filter by severity (critical, high, medium, low)"
    ),
    rule_id: str | None = Query(None, description="Filter by detection rule ID"),
    target_asset_id: str | None = Query(None, description="Filter by target asset UUID"),
    search: str | None = Query(None, description="Search by IP, hostname, rule ID, or MITRE ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> list[AlertResponse]:
    """Retrieves curated alerts with optional status, severity, asset, and search filtering."""
    alerts = await alert_service.list_alerts(
        db,
        status=status,
        severity=severity,
        rule_id=rule_id,
        target_asset_id=target_asset_id,
        search=search,
        skip=skip,
        limit=limit,
    )
    return [AlertResponse.model_validate(a) for a in alerts]


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    """Retrieves detailed information for a specific alert."""
    alert = await alert_service.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )
    return AlertResponse.model_validate(alert)


@router.get("/{alert_id}/events", response_model=list[AlertEvidenceEventResponse])
async def get_alert_events(
    alert_id: str,
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> list[AlertEvidenceEventResponse]:
    """Retrieves full forensic event payloads linked to an alert's evidence list."""
    events = await alert_service.get_alert_events(db, alert_id)
    if events is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )
    return [AlertEvidenceEventResponse.model_validate(e) for e in events]


@router.patch("/{alert_id}/triage", response_model=AlertResponse)
async def triage_alert(
    alert_id: str,
    request: AlertTriageRequest,
    current_user: User = Depends(require_role(["Admin", "Analyst"])),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    """Transitions the triage lifecycle status of an alert and logs to audit trail."""
    alert = await alert_service.triage_alert(
        db,
        alert_id=alert_id,
        new_status=request.status,
        notes=request.notes,
        user_id=current_user.username,
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )
    return AlertResponse.model_validate(alert)
