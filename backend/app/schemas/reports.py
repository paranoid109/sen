"""Pydantic Schemas for Dashboard Metrics and Executive Reports (M7)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class DashboardMetricsResponse(BaseModel):
    """Real-time security operational metrics for the SOC dashboard."""

    total_events: int
    active_alerts: int
    open_incidents: int
    monitored_assets: int
    severity_breakdown: dict[str, int]
    mttd_seconds: float | None = None


class ExecutiveReportResponse(BaseModel):
    """Executive security summary debrief."""

    generated_at: datetime
    report_markdown: str
    kpi_metrics: DashboardMetricsResponse
