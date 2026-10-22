"""SQLAlchemy Correlated Incident and Timeline Models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base, UTCDateTime
from backend.app.models.alert import Alert


class Incident(Base):
    """Correlated security incident aggregating alerts by monitored target asset with closed-form risk score (M6)."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    target_asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), index=True, nullable=True
    )
    target_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    incident_alerts: Mapped[list[IncidentAlert]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    timeline: Mapped[list[IncidentTimeline]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="IncidentTimeline.timestamp",
    )


class IncidentAlert(Base):
    """Join association between Incidents and correlated Alerts."""

    __tablename__ = "incident_alerts"

    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    added_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=lambda: datetime.now(UTC), nullable=False
    )

    incident: Mapped[Incident] = relationship(back_populates="incident_alerts")
    alert: Mapped[Alert] = relationship(lazy="selectin")


class IncidentTimeline(Base):
    """Audit timeline item tracking significant state transitions or events on an incident."""

    __tablename__ = "incident_timeline"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="timeline")
