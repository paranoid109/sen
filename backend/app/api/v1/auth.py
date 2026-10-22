"""Authentication and User Management REST API Endpoints (M1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import (
    create_access_token,
    get_current_user,
    require_role,
    security_bearer,
)
from backend.app.models.user import User
from backend.app.schemas.api_keys import (
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeyResponse,
)
from backend.app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserResponse
from backend.app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Identity & Access Management"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    credentials_in: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticates credentials, enforces rate limits, and issues a signed JWT access token."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = await auth_service.authenticate_user(
        db,
        username=credentials_in.username,
        password=credentials_in.password,
        client_ip=client_ip,
    )
    token = create_access_token(data={"sub": user.id, "role": user.role, "username": user.username})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role,
        username=user.username,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Retrieves profile details for the currently authenticated user."""
    return UserResponse.model_validate(current_user)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    credentials: HTTPAuthorizationCredentials | None = Security(security_bearer),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Registers a new user account.

    Restricted to Admins once users exist in the database (RBAC).
    Permits unauthenticated initial bootstrap when zero users exist.
    """
    stmt = select(func.count()).select_from(User)
    user_count = (await db.execute(stmt)).scalar() or 0

    if user_count > 0:
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        admin_user = await get_current_user(credentials, db)
        if admin_user.role != "Admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires Admin role, but user has role '{admin_user.role}'",
            )
        creator = admin_user.username
    else:
        creator = "bootstrap"

    user = await auth_service.register_user(db, user_in, created_by=creator)
    return UserResponse.model_validate(user)


# ==============================================================================
# Ingestion API Key Management Endpoints (Admin Only)
# ==============================================================================


@router.post("/api-keys", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_in: ApiKeyCreateRequest,
    current_user: User = Depends(require_role(["Admin"])),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyCreatedResponse:
    """Generates a new programmatic ingestion API key.

    Returns the plaintext raw_key exactly once. The raw key is not stored.
    """
    api_key, raw_key = await auth_service.create_api_key(
        db, key_in, created_by=current_user.username
    )
    return ApiKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        raw_key=raw_key,
        prefix=api_key.prefix,
        scope=api_key.scope,
        asset_id=api_key.asset_id,
        created_at=api_key.created_at,
    )


@router.get("/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_role(["Admin"])),
    db: AsyncSession = Depends(get_db),
) -> list[ApiKeyResponse]:
    """Lists registered ingestion API keys without exposing secrets."""
    keys = await auth_service.list_api_keys(db, skip=skip, limit=limit)
    return [ApiKeyResponse.model_validate(k) for k in keys]


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: User = Depends(require_role(["Admin"])),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Revokes and deletes an API key."""
    deleted = await auth_service.delete_api_key(db, key_id, deleted_by=current_user.username)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found",
        )
    return {"status": "success", "detail": f"API key '{key_id}' deleted"}
