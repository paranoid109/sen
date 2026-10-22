"""Alert Service: Alert Lifecycle, Deduplication, and Triage (M5).

Deduplicates active alerts via deterministic SHA-256 keys, manages triage state transitions,
and logs all mutations to the tamper-evident audit trail (Law 4).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.alert import Alert
from backend.app.models.event import Event
from backend.app.services.audit_service import audit_service
from backend.app.services.incident_service import incident_service

logger = logging.getLogger("sentinelx.alerts")


class AlertService:
    """Service managing curated alerts, deduplication windows, and triage workflows."""

    @staticmethod
    def compute_dedup_key(
        rule_id: str,
        target_asset_id: str | None,
        target_host: str | None,
        source_ip: str | None,
    ) -> str:
        """Computes the deterministic SHA-256 deduplication key.

        Formula (docs/CONTRACTS.md):
        dedup_key = sha256(rule_id : (target_asset_id or target_host or 'unassigned') : (source_ip or 'unknown'))
        """
        asset_component = target_asset_id or target_host or "unassigned"
        source_component = source_ip or "unknown"
        raw_key = f"{rule_id}:{asset_component}:{source_component}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    async def create_or_update_alert(
        self,
        session: AsyncSession,
        *,
        rule_id: str,
        rule_name: str,
        severity: str,
        mitre_attack_id: str | None = None,
        source_ip: str,
        target_asset_id: str | None = None,
        target_host: str | None = None,
        first_seen: datetime,
        last_seen: datetime,
        evidence: list[str],
    ) -> tuple[Alert, bool]:
        """Creates a new alert or deduplicates into an existing active alert.

        Returns:
            (alert_instance, is_created_bool)
        """
        dedup_key = self.compute_dedup_key(
            rule_id=rule_id,
            target_asset_id=target_asset_id,
            target_host=target_host,
            source_ip=source_ip,
        )

        # 1. Check for an active alert (status NEW or INVESTIGATING)
        stmt = (
            select(Alert)
            .where(
                Alert.dedup_key == dedup_key,
                Alert.status.in_(["NEW", "INVESTIGATING"]),
            )
            .limit(1)
            .with_for_update()
        )
        result = await session.execute(stmt)
        active_alert = result.scalars().first()

        if active_alert:
            # Deduplicate into active alert
            active_alert.occurrence_count += 1
            active_alert.last_seen = last_seen
            active_alert.updated_at = datetime.now(UTC)

            # Append new evidence IDs capped at 100 items
            current_evidence = list(active_alert.evidence or [])
            for ev_id in evidence:
                if ev_id not in current_evidence:
                    current_evidence.append(ev_id)
            active_alert.evidence = current_evidence[:100]

            await session.commit()

            # Trigger incident risk score recalculation
            recalc = await incident_service.recalculate_incident_for_alert(session, active_alert)
            if not recalc:
                await incident_service.correlate_alert(session, active_alert)
            return active_alert, False

        # 2. No active alert; instantiate a new alert
        new_alert = Alert(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            status="NEW",
            mitre_attack_id=mitre_attack_id,
            source_ip=source_ip,
            target_asset_id=target_asset_id,
            target_host=target_host,
            dedup_key=dedup_key,
            occurrence_count=1,
            first_seen=first_seen,
            last_seen=last_seen,
            evidence=evidence[:100],
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        session.add(new_alert)
        try:
            await session.commit()
        except IntegrityError:
            # Concurrent race caught by partial unique index: rollback and deduplicate
            await session.rollback()
            stmt_retry = (
                select(Alert)
                .where(
                    Alert.dedup_key == dedup_key,
                    Alert.status.in_(["NEW", "INVESTIGATING"]),
                )
                .limit(1)
                .with_for_update()
            )
            retry_res = await session.execute(stmt_retry)
            retry_alert = retry_res.scalars().first()
            if retry_alert:
                retry_alert.occurrence_count += 1
                retry_alert.last_seen = last_seen
                await session.commit()
                recalc = await incident_service.recalculate_incident_for_alert(session, retry_alert)
                if not recalc:
                    await incident_service.correlate_alert(session, retry_alert)
                return retry_alert, False
            return new_alert, True

        # Correlate into incident
        await incident_service.correlate_alert(session, new_alert)

        # Log creation in tamper-evident audit log (Law 4)
        await audit_service.log_action(
            session,
            action="ALERT_CREATE",
            resource_type="alert",
            resource_id=new_alert.id,
            status="SUCCESS",
            details={
                "rule_id": rule_id,
                "severity": severity,
                "dedup_key": dedup_key,
            },
        )

        return new_alert, True

    async def triage_alert(
        self,
        session: AsyncSession,
        alert_id: str,
        *,
        new_status: str,
        notes: str | None = None,
        user_id: str | None = None,
    ) -> Alert | None:
        """Transitions alert triage status, recalculates incident risk score, and audits mutation."""
        alert = await self.get_alert(session, alert_id)
        if not alert:
            return None

        old_status = alert.status
        alert.status = new_status
        alert.updated_at = datetime.now(UTC)

        await session.commit()
        await session.refresh(alert)

        # Recalculate correlated incident (handles false-positive exclusion or auto-closure)
        await incident_service.recalculate_incident_for_alert(session, alert)

        # Audit log mutation (Law 4)
        await audit_service.log_action(
            session,
            action="ALERT_TRIAGE",
            resource_type="alert",
            resource_id=alert.id,
            user_id=user_id,
            status="SUCCESS",
            details={
                "old_status": old_status,
                "new_status": new_status,
                "notes": notes,
            },
        )

        return alert

    async def get_alert(self, session: AsyncSession, alert_id: str) -> Alert | None:
        """Retrieves an alert by UUID."""
        stmt = select(Alert).where(Alert.id == alert_id)
        result = await session.execute(stmt)
        return result.scalars().first()

    async def get_alert_events(self, session: AsyncSession, alert_id: str) -> list[Event] | None:
        """Retrieves hydrated Event records corresponding to an alert's evidence UUIDs."""
        alert = await self.get_alert(session, alert_id)
        if not alert:
            return None
        if not alert.evidence:
            return []
        stmt = (
            select(Event)
            .where(Event.id.in_(alert.evidence))
            .order_by(Event.event_time.asc())
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def list_alerts(
        self,
        session: AsyncSession,
        *,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        target_asset_id: str | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[Alert]:
        """Lists alerts with optional status, severity, rule, asset, and search filtering."""
        conditions = []
        if status:
            conditions.append(Alert.status == status)
        if severity:
            conditions.append(Alert.severity == severity)
        if rule_id:
            conditions.append(Alert.rule_id == rule_id)
        if target_asset_id:
            conditions.append(Alert.target_asset_id == target_asset_id)
        if search:
            search_pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    Alert.source_ip.ilike(search_pattern),
                    Alert.target_host.ilike(search_pattern),
                    Alert.rule_id.ilike(search_pattern),
                    Alert.rule_name.ilike(search_pattern),
                    Alert.mitre_attack_id.ilike(search_pattern),
                )
            )

        stmt = (
            select(Alert)
            .where(*conditions)
            .order_by(Alert.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())


alert_service = AlertService()
