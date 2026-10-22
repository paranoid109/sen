"""SentinelX REST API v1 Package."""

from fastapi import APIRouter

from backend.app.api.v1.alerts import router as alerts_router
from backend.app.api.v1.assets import router as assets_router
from backend.app.api.v1.audit import router as audit_router
from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.events import router as events_router
from backend.app.api.v1.incidents import router as incidents_router
from backend.app.api.v1.reports import router as reports_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth_router)
api_v1_router.include_router(assets_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(audit_router)

__all__ = ["api_v1_router"]
