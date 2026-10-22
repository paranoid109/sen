"""Tamper-Evident Audit Trail REST API Endpoints (Law 4)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import require_role
from backend.app.models.audit import AuditLog
from backend.app.models.user import User
from backend.app.schemas.audit import AuditLogResponse, AuditVerifyResponse
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/audit", tags=["Audit Trail Management"])


@router.get("", response_model=list[AuditLogResponse])
async def list_audit_logs(
    action: str | None = Query(None, description="Filter by action name"),
    user_id: str | None = Query(None, description="Filter by user/actor ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_role(["Admin", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLogResponse]:
    """Retrieves chronological tamper-evident audit logs (Admin and Auditor only)."""
    stmt = select(AuditLog).order_by(AuditLog.sequence_number.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    stmt = stmt.offset(skip).limit(limit)

    result = await db.execute(stmt)
    records = list(result.scalars().all())
    return [AuditLogResponse.model_validate(r) for r in records]


@router.get("/verify", response_model=AuditVerifyResponse)
@router.post("/verify", response_model=AuditVerifyResponse)
async def verify_audit_chain(
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> AuditVerifyResponse:
    """Cryptographically verifies the SHA-256 hash continuity of the audit log sequence."""
    is_valid, total, err, broken_seq = await audit_service.verify_chain(db)
    return AuditVerifyResponse(
        is_valid=is_valid,
        total_records=total,
        error_message=err,
        broken_sequence=broken_seq,
    )
