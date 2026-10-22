"""Authentication and API Key Management Service (M1).

Implements login with rate-limiting via indexed AuditLog queries (mitigating authentication floods),
bcrypt password verification, user registration, and hashed API key generation and management.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.security import hash_api_key, hash_password, verify_password
from backend.app.models.api_key import ApiKey
from backend.app.models.asset import Asset
from backend.app.models.audit import AuditLog
from backend.app.models.user import User
from backend.app.schemas.api_keys import ApiKeyCreateRequest
from backend.app.schemas.auth import UserCreate
from backend.app.services.audit_service import audit_service


class AuthService:
    """Service managing platform identity, credentials, rate limiting, and API keys."""

    async def authenticate_user(
        self,
        session: AsyncSession,
        *,
        username: str,
        password: str,
        client_ip: str | None = None,
    ) -> User:
        """Authenticates a user by username and password with audit-backed rate limiting.

        Enforces dual-threshold flood protection (Law 4 / S3 / U5):
        - Max RATE_LIMIT_LOGIN_ATTEMPTS (5) failed attempts per window (300s)
          per client_ip OR per username.
        - When exceeded, returns HTTP 429 immediately without logging to AuditLog,
          preventing table flooding.
        """
        now = datetime.now(UTC)
        window_seconds = settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS
        window_start = now - timedelta(seconds=window_seconds)

        # 1. Rate-limit check via indexed AuditLog columns (action, resource_id=ip, user_id=username)
        actor_filters = [AuditLog.user_id == username]
        if client_ip:
            actor_filters.append(AuditLog.resource_id == client_ip)

        rate_limit_stmt = (
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "LOGIN_FAILED",
                AuditLog.timestamp >= window_start,
                or_(*actor_filters),
            )
        )
        failed_count = (await session.execute(rate_limit_stmt)).scalar() or 0

        if failed_count >= settings.RATE_LIMIT_LOGIN_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Account temporarily locked for {window_seconds // 60} minutes.",
            )

        # 2. Query user record
        user_stmt = select(User).where(User.username == username)
        result = await session.execute(user_stmt)
        user = result.scalars().first()

        # 3. Verify credentials
        if not user or not verify_password(password, user.hashed_password):
            # Record failed login to audit log
            await audit_service.log_action(
                session,
                action="LOGIN_FAILED",
                resource_type="auth",
                resource_id=client_ip,
                user_id=username,
                status="FAILURE",
                details={"reason": "invalid_credentials", "client_ip": client_ip},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user account",
            )

        # 4. Record successful login to audit log
        await audit_service.log_action(
            session,
            action="LOGIN_SUCCESS",
            resource_type="auth",
            resource_id=client_ip,
            user_id=user.username,
            status="SUCCESS",
            details={"user_id": user.id, "role": user.role, "client_ip": client_ip},
        )
        return user

    async def register_user(
        self,
        session: AsyncSession,
        user_in: UserCreate,
        *,
        created_by: str | None = None,
    ) -> User:
        """Registers a new platform user with unique username and email constraints."""
        stmt = select(User).where(
            or_(User.username == user_in.username, User.email == user_in.email)
        )
        existing = (await session.execute(stmt)).scalars().first()
        if existing:
            if existing.username == user_in.username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Username '{user_in.username}' is already registered",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{user_in.email}' is already registered",
            )

        hashed = hash_password(user_in.password)
        user = User(
            id=str(uuid.uuid4()),
            username=user_in.username,
            email=user_in.email,
            hashed_password=hashed,
            role=user_in.role,
            is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        await audit_service.log_action(
            session,
            action="USER_CREATED",
            resource_type="user",
            resource_id=user.id,
            user_id=created_by or "system",
            status="SUCCESS",
            details={"username": user.username, "role": user.role, "email": user.email},
        )
        return user

    async def create_api_key(
        self,
        session: AsyncSession,
        key_in: ApiKeyCreateRequest,
        *,
        created_by: str | None = None,
    ) -> tuple[ApiKey, str]:
        """Generates a cryptographically random API key and persists its SHA-256 hash.

        Returns (ApiKey model, raw_key plaintext string).
        The raw key is returned exactly once and is never stored in plaintext.
        """
        if key_in.asset_id:
            asset = await session.get(Asset, key_in.asset_id)
            if not asset:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Bound asset '{key_in.asset_id}' not found in CMDB",
                )

        raw_secret = secrets.token_urlsafe(32)
        raw_key = f"sen_{raw_secret}"
        prefix = raw_key[:12]
        key_hash = hash_api_key(raw_key)

        api_key = ApiKey(
            id=str(uuid.uuid4()),
            key_hash=key_hash,
            name=key_in.name,
            prefix=prefix,
            scope=key_in.scope,
            asset_id=key_in.asset_id,
            is_active=True,
        )
        session.add(api_key)
        await session.commit()
        await session.refresh(api_key)

        await audit_service.log_action(
            session,
            action="API_KEY_CREATED",
            resource_type="api_key",
            resource_id=api_key.id,
            user_id=created_by or "system",
            status="SUCCESS",
            details={
                "name": api_key.name,
                "prefix": prefix,
                "scope": api_key.scope,
                "asset_id": api_key.asset_id,
            },
        )
        return api_key, raw_key

    async def list_api_keys(
        self, session: AsyncSession, skip: int = 0, limit: int = 100
    ) -> list[ApiKey]:
        """Lists registered API keys with metadata (excluding hash and secrets)."""
        stmt = select(ApiKey).order_by(ApiKey.created_at.desc()).offset(skip).limit(limit)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def delete_api_key(
        self, session: AsyncSession, key_id: str, *, deleted_by: str | None = None
    ) -> bool:
        """Revokes and deletes an API key."""
        api_key = await session.get(ApiKey, key_id)
        if not api_key:
            return False

        key_name = api_key.name
        key_prefix = api_key.prefix
        await session.delete(api_key)
        await session.commit()

        await audit_service.log_action(
            session,
            action="API_KEY_DELETED",
            resource_type="api_key",
            resource_id=key_id,
            user_id=deleted_by or "system",
            status="SUCCESS",
            details={"name": key_name, "prefix": key_prefix},
        )
        return True


auth_service = AuthService()
