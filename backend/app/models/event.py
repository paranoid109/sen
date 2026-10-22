"""SQLAlchemy Telemetry Event Model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base, UTCDateTime


class Event(Base):
    """Normalized security telemetry event persisted during ingestion (M3)."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    target_host: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    target_asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), index=True, nullable=True
    )
    event_time: Mapped[datetime] = mapped_column(UTCDateTime, index=True, nullable=False)
    ingest_time: Mapped[datetime] = mapped_column(
        UTCDateTime, index=True, default=lambda: datetime.now(UTC), nullable=False
    )
    raw_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_events_source_type_time", "source_ip", "event_type", "event_time"),
        Index("ix_events_source_port_time", "source_ip", "destination_port", "event_time"),
    )
