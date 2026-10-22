"""Ingestion Service: Telemetry Ingest, Log Parsing, and Event Dispatch (M3)."""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.dispatcher import dispatcher
from backend.app.models.api_key import ApiKey
from backend.app.models.event import Event
from backend.app.schemas.events import BatchIngestRequest, SingleIngestRequest
from backend.app.services.asset_service import asset_service
from contracts.python.models import EventContract

logger = logging.getLogger("sentinelx.ingestion")

# Standard Linux syslog auth.log failed password pattern
SYSLOG_AUTH_RE = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)

# Standard Combined Web Access Log pattern
WEB_LOG_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/[\d\.]+)?\"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)


class IngestionService:
    """Service handling telemetry normalization, persistence, and pipeline dispatch."""

    @staticmethod
    def parse_auth_log_line(
        raw_line: str,
        default_year: int = 2026,
        reference_time: datetime | None = None,
    ) -> SingleIngestRequest | None:
        """Parses a Linux sshd syslog/auth.log line into a structured SingleIngestRequest."""
        line = raw_line.strip()
        match = SYSLOG_AUTH_RE.search(line)
        if not match:
            return None

        ts_str, host, user, source_ip, source_port = match.groups()

        effective_year = reference_time.year if reference_time else default_year

        # Parse syslog timestamp (e.g. "Oct  7 12:00:01")
        parts = ts_str.split()
        month, day, time_str = parts[0], parts[1], parts[2]
        formatted_ts = f"{effective_year} {month} {int(day):02d} {time_str}"
        try:
            event_time = datetime.strptime(formatted_ts, "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            event_time = datetime.now(UTC)

        return SingleIngestRequest(
            source_ip=source_ip,
            destination_ip=None,
            destination_port=22,
            source_port=int(source_port),
            event_type="auth_failed",
            target_host=host,
            event_time=event_time,
            raw_payload=line,
            details={"user": user, "service": "sshd"},
        )

    @staticmethod
    def parse_web_log_line(
        raw_line: str, target_host: str | None = None
    ) -> SingleIngestRequest | None:
        """Parses an Apache/Nginx combined access log line into a structured SingleIngestRequest."""
        import urllib.parse

        line = raw_line.strip()
        match = WEB_LOG_RE.search(line)
        if not match:
            return None

        client_ip, ts_str, method, raw_uri, status_str, _bytes, _ref, user_agent = match.groups()

        # Try parsing timestamp "[07/Oct/2026:12:30:01 +0000]"
        try:
            event_time = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
        except Exception:
            event_time = datetime.now(UTC)

        decoded_uri = urllib.parse.unquote(raw_uri)
        return SingleIngestRequest(
            source_ip=client_ip,
            destination_ip=None,
            destination_port=80,
            source_port=None,
            event_type="web_request",
            target_host=target_host,
            event_time=event_time,
            raw_payload=line,
            details={
                "method": method,
                "uri": decoded_uri,
                "status_code": int(status_str),
                "user_agent": user_agent or "",
            },
        )

    @staticmethod
    def parse_connection_json(data: dict[str, Any]) -> SingleIngestRequest | None:
        """Parses a network connection telemetry dictionary into a structured SingleIngestRequest."""
        source_ip = data.get("source_ip")
        if not source_ip:
            return None

        event_time = data.get("event_time")
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00")).astimezone(
                    UTC
                )
            except Exception:
                event_time = datetime.now(UTC)
        elif not isinstance(event_time, datetime):
            event_time = datetime.now(UTC)

        return SingleIngestRequest(
            source_ip=str(source_ip),
            destination_ip=data.get("destination_ip"),
            destination_port=data.get("destination_port"),
            source_port=data.get("source_port"),
            event_type=data.get("event_type", "connection"),
            target_host=data.get("target_host"),
            event_time=event_time,
            raw_payload=data.get("raw_payload"),
            details=data.get("details", {}),
        )

    async def ingest_single(
        self,
        session: AsyncSession,
        request: SingleIngestRequest,
        *,
        api_key: ApiKey | None = None,
    ) -> Event:
        """Normalizes, persists, and asynchronously dispatches a single telemetry event.

        Enforces API key asset-binding precedence (Law 1 / Security Model):
        If an ApiKey has an assigned asset_id, it strictly overrides any asset claim
        in the request payload to prevent asset spoofing.
        """
        # Resolve target asset identifier
        resolved_asset_id: str | None = None
        target_host = request.target_host

        if api_key and api_key.asset_id:
            resolved_asset_id = api_key.asset_id
            bound_asset = await asset_service.get_asset(session, resolved_asset_id)
            if bound_asset and not target_host:
                target_host = bound_asset.hostname
        else:
            resolved_asset = await asset_service.resolve_target_asset(
                session,
                asset_id=request.asset_id,
                target_host=request.target_host,
                destination_ip=request.destination_ip,
            )
            if resolved_asset:
                resolved_asset_id = resolved_asset.id
                if not target_host:
                    target_host = resolved_asset.hostname
            elif request.asset_id:
                resolved_asset_id = request.asset_id

        event_time = request.event_time or datetime.now(UTC)
        ingest_time = datetime.now(UTC)

        event_obj = Event(
            id=str(uuid.uuid4()),
            source_ip=request.source_ip,
            destination_ip=request.destination_ip,
            destination_port=request.destination_port,
            source_port=request.source_port,
            event_type=request.event_type,
            target_host=target_host,
            target_asset_id=resolved_asset_id,
            event_time=event_time,
            ingest_time=ingest_time,
            raw_payload=request.raw_payload,
            details=request.details,
        )

        session.add(event_obj)
        await session.commit()

        # Post-commit dispatch to in-process subscribers
        contract = EventContract(
            event_id=uuid.UUID(event_obj.id),
            source_ip=event_obj.source_ip,
            destination_ip=event_obj.destination_ip,
            destination_port=event_obj.destination_port,
            source_port=event_obj.source_port,
            event_type=event_obj.event_type,
            target_host=event_obj.target_host,
            target_asset_id=event_obj.target_asset_id,
            event_time=event_obj.event_time,
            ingest_time=event_obj.ingest_time,
            raw_payload=event_obj.raw_payload,
            details=event_obj.details,
        )
        dispatcher.dispatch(contract)

        return event_obj

    async def ingest_batch(
        self,
        session: AsyncSession,
        batch_request: BatchIngestRequest,
        *,
        api_key: ApiKey | None = None,
    ) -> list[Event]:
        """Ingests multiple events with fallback to batch-level asset/target metadata."""
        persisted_events: list[Event] = []
        for item in batch_request.events:
            # Fallback to batch-level values if not specified per item
            if not item.asset_id and batch_request.asset_id:
                item.asset_id = batch_request.asset_id
            if not item.target_host and batch_request.target_host:
                item.target_host = batch_request.target_host

            event = await self.ingest_single(session, item, api_key=api_key)
            persisted_events.append(event)

        return persisted_events


ingestion_service = IngestionService()
