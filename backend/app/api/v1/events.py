"""Ingest API Endpoints (M3)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import hash_api_key
from backend.app.models.api_key import ApiKey
from backend.app.schemas.events import (
    BatchIngestRequest,
    IngestResponse,
    SingleIngestRequest,
)
from backend.app.services.ingestion_service import ingestion_service

router = APIRouter(prefix="/events", tags=["Telemetry Ingestion"])


async def optional_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    db: AsyncSession = Depends(get_db),
) -> ApiKey | None:
    """Resolves optional ApiKey from X-API-Key header."""
    if not x_api_key:
        return None

    # Check against master/system ingest key
    if x_api_key == settings.INGEST_API_KEY:
        return ApiKey(
            id="master-ingest-key",
            key_hash=hash_api_key(x_api_key),
            name="System Ingest Key",
            prefix=x_api_key[:8],
            scope="ingest",
            asset_id=None,
            is_active=True,
        )

    # Check registered api_keys in database
    hashed = hash_api_key(x_api_key)
    stmt = select(ApiKey).where(ApiKey.key_hash == hashed, ApiKey.is_active.is_(True))
    result = await db.execute(stmt)
    key_obj = result.scalars().first()
    if not key_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key",
        )
    return key_obj


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    request: SingleIngestRequest,
    db: AsyncSession = Depends(get_db),
    api_key: ApiKey | None = Depends(optional_api_key),
) -> IngestResponse:
    """Ingests, persists, and publishes a single telemetry event."""
    event = await ingestion_service.ingest_single(db, request, api_key=api_key)
    return IngestResponse(
        ingested_count=1,
        event_ids=[event.id],
        status="success",
    )


@router.post("/batch", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_batch_events(
    request: BatchIngestRequest,
    db: AsyncSession = Depends(get_db),
    api_key: ApiKey | None = Depends(optional_api_key),
) -> IngestResponse:
    """Ingests, persists, and publishes a batch of telemetry events."""
    events = await ingestion_service.ingest_batch(db, request, api_key=api_key)
    return IngestResponse(
        ingested_count=len(events),
        event_ids=[e.id for e in events],
        status="success",
    )
