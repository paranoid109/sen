"""Reporting and Dashboard Metrics REST API Endpoints (M7)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import require_role
from backend.app.models.user import User
from backend.app.schemas.reports import DashboardMetricsResponse, ExecutiveReportResponse
from backend.app.services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Reporting Engine"])


@router.get("/metrics", response_model=DashboardMetricsResponse)
@router.get("/kpi", response_model=DashboardMetricsResponse)
async def get_dashboard_metrics(
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> DashboardMetricsResponse:
    """Retrieves live security operational metrics and KPI indicators."""
    return await report_service.get_dashboard_metrics(db)


@router.get("/executive", response_model=ExecutiveReportResponse)
async def get_executive_report(
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> ExecutiveReportResponse:
    """Generates an executive security posture report with markdown debrief."""
    return await report_service.generate_executive_report(db)
