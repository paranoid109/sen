"""Asset Service: CMDB Inventory Management and Target Resolution (M2)."""

from __future__ import annotations

import uuid

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.asset import Asset
from backend.app.schemas.assets import AssetCreate, AssetUpdate
from backend.app.services.audit_service import audit_service


class AssetService:
    """Service managing monitored enterprise IT infrastructure assets (CMDB)."""

    async def create_asset(
        self,
        session: AsyncSession,
        asset_in: AssetCreate,
        *,
        user_id: str | None = None,
    ) -> Asset:
        """Registers a new monitored asset and records an audit log entry."""
        asset = Asset(
            id=str(uuid.uuid4()),
            hostname=asset_in.hostname,
            ip_address=asset_in.ip_address,
            asset_type=asset_in.asset_type,
            criticality=asset_in.criticality,
            description=asset_in.description,
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        await audit_service.log_action(
            session,
            action="ASSET_CREATED",
            resource_type="asset",
            resource_id=asset.id,
            user_id=user_id or "system",
            status="SUCCESS",
            details={
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "criticality": asset.criticality,
                "asset_type": asset.asset_type,
            },
        )
        return asset

    async def get_asset(self, session: AsyncSession, asset_id: str) -> Asset | None:
        """Retrieves an asset by primary key UUID."""
        stmt = select(Asset).where(Asset.id == asset_id)
        result = await session.execute(stmt)
        return result.scalars().first()

    async def list_assets(
        self, session: AsyncSession, skip: int = 0, limit: int = 100
    ) -> list[Asset]:
        """Lists registered CMDB assets with pagination."""
        stmt = select(Asset).offset(skip).limit(limit)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def update_asset(
        self,
        session: AsyncSession,
        asset_id: str,
        asset_in: AssetUpdate,
        *,
        user_id: str | None = None,
    ) -> Asset | None:
        """Updates attributes of an existing CMDB asset and records an audit log entry."""
        asset = await self.get_asset(session, asset_id)
        if not asset:
            return None

        update_data = asset_in.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(asset, key, value)

        await session.commit()
        await session.refresh(asset)

        await audit_service.log_action(
            session,
            action="ASSET_UPDATED",
            resource_type="asset",
            resource_id=asset.id,
            user_id=user_id or "system",
            status="SUCCESS",
            details=update_data,
        )
        return asset

    async def delete_asset(
        self,
        session: AsyncSession,
        asset_id: str,
        *,
        user_id: str | None = None,
    ) -> bool:
        """Deletes an asset from the inventory and records an audit log entry."""
        asset = await self.get_asset(session, asset_id)
        if not asset:
            return False

        hostname = asset.hostname
        ip_address = asset.ip_address

        await session.delete(asset)
        await session.commit()

        await audit_service.log_action(
            session,
            action="ASSET_DELETED",
            resource_type="asset",
            resource_id=asset_id,
            user_id=user_id or "system",
            status="SUCCESS",
            details={"hostname": hostname, "ip_address": ip_address},
        )
        return True

    async def resolve_target_asset(
        self,
        session: AsyncSession,
        *,
        asset_id: str | None = None,
        target_host: str | None = None,
        destination_ip: str | None = None,
    ) -> Asset | None:
        """Resolves the monitored target CMDB asset from event telemetry identifiers.

        Resolution priority:
        1. Exact asset_id UUID lookup
        2. target_host matching hostname
        3. destination_ip matching ip_address
        """
        if asset_id:
            asset = await self.get_asset(session, asset_id)
            if asset:
                return asset

        conditions = []
        if target_host:
            conditions.append(Asset.hostname == target_host)
        if destination_ip:
            conditions.append(Asset.ip_address == destination_ip)

        if not conditions:
            return None

        stmt = select(Asset).where(or_(*conditions)).limit(1)
        result = await session.execute(stmt)
        return result.scalars().first()

    @staticmethod
    def get_criticality(asset: Asset | None) -> str:
        """Returns the criticality tier of an asset, defaulting to 'low' for unassigned entities."""
        return asset.criticality if asset else "low"


asset_service = AssetService()
