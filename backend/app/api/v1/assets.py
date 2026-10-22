"""CMDB Asset Inventory Management REST API Endpoints (M2)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import require_role
from backend.app.models.user import User
from backend.app.schemas.assets import AssetCreate, AssetResponse, AssetUpdate
from backend.app.services.asset_service import asset_service

router = APIRouter(prefix="/assets", tags=["CMDB Asset Management"])


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> list[AssetResponse]:
    """Retrieves monitored enterprise infrastructure assets with pagination."""
    assets = await asset_service.list_assets(db, skip=skip, limit=limit)
    return [AssetResponse.model_validate(a) for a in assets]


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: str,
    current_user: User = Depends(require_role(["Admin", "Analyst", "Auditor"])),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """Retrieves details of a specific monitored asset."""
    asset = await asset_service.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found",
        )
    return AssetResponse.model_validate(asset)


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_in: AssetCreate,
    current_user: User = Depends(require_role(["Admin"])),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """Registers a new monitored infrastructure asset in CMDB (Admin only)."""
    asset = await asset_service.create_asset(db, asset_in, user_id=current_user.username)
    return AssetResponse.model_validate(asset)


@router.put("/{asset_id}", response_model=AssetResponse)
@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: str,
    asset_in: AssetUpdate,
    current_user: User = Depends(require_role(["Admin"])),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """Updates attributes of an existing CMDB asset (Admin only)."""
    asset = await asset_service.update_asset(db, asset_id, asset_in, user_id=current_user.username)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found",
        )
    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: str,
    current_user: User = Depends(require_role(["Admin"])),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Deletes an asset from the inventory (Admin only)."""
    deleted = await asset_service.delete_asset(db, asset_id, user_id=current_user.username)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found",
        )
    return {"status": "success", "detail": f"Asset '{asset_id}' deleted"}
