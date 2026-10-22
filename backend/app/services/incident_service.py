"""Incident Service: Correlation, Risk Scoring, and Investigation Timelines (M6).

Aggregates alerts N:1 by monitored target asset, calculates deterministic closed-form
risk scores [0, 100], and manages investigation audit timelines.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.alert import Alert
from backend.app.models.incident import Incident, IncidentAlert, IncidentTimeline
from backend.app.services.asset_service import asset_service
from backend.app.services.audit_service import audit_service
from backend.app.services.notification_service import notification_service

logger = logging.getLogger("sentinelx.incidents")

# BaseScore numeric map (docs/CONTRACTS.md)
BASE_SCORES: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
}

# AssetMultiplier numeric map
ASSET_MULTIPLIERS: dict[str, float] = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.2,
    "low": 1.0,
}

SEVERITY_ORDER: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class IncidentService:
    """Service correlating security alerts into enterprise security incidents."""

    @staticmethod
    def calculate_risk_score(alerts: list[Alert], asset_criticality: str = "low") -> int:
        """Calculates the closed-form bounded incident risk score [0, 100].

        Formula:
        RawScore = (max(BaseScore)) * AssetMultiplier + (|alerts| - 1) * 15 + min(20, sum((cnt - 1) * 2))
        RiskScore = min(100, max(0, round(RawScore)))
        """
        # Exclude false-positive alerts from scoring
        active_alerts = [a for a in alerts if a.status != "FALSE_POSITIVE"]
        if not active_alerts:
            return 0

        max_base = max(BASE_SCORES.get(a.severity.lower(), 5) for a in active_alerts)
        multiplier = ASSET_MULTIPLIERS.get(asset_criticality.lower(), 1.0)
        multi_alert_penalty = (len(active_alerts) - 1) * 15
        recurrence_bonus = min(20, sum((a.occurrence_count - 1) * 2 for a in active_alerts))

        raw_score = (max_base * multiplier) + multi_alert_penalty + recurrence_bonus
        return min(100, max(0, round(raw_score)))

    async def correlate_alert(self, session: AsyncSession, alert: Alert) -> Incident:
        """Correlates an incoming alert into an existing open incident or creates a new incident.

        Correlation Window: 15 minutes (900 seconds) by target asset.
        """
        now = datetime.now(UTC)
        window_start = now - timedelta(seconds=900)

        # 1. Look for existing open incident for this target asset/host within the window
        conditions = [
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.updated_at >= window_start,
        ]
        if alert.target_asset_id:
            conditions.append(Incident.target_asset_id == alert.target_asset_id)
        elif alert.target_host:
            conditions.append(Incident.target_host == alert.target_host)
        else:
            # If both are null, unassigned alerts share an open unassigned incident
            conditions.append(Incident.target_asset_id.is_(None))
            conditions.append(Incident.target_host.is_(None))

        stmt = select(Incident).where(*conditions).order_by(Incident.updated_at.desc()).limit(1)
        result = await session.execute(stmt)
        existing_incident = result.scalars().first()

        # Resolve asset criticality
        asset_crit = "low"
        if alert.target_asset_id:
            asset = await asset_service.get_asset(session, alert.target_asset_id)
            if asset:
                asset_crit = asset.criticality

        if existing_incident:
            # Check if this alert is already associated
            link_stmt = select(IncidentAlert).where(
                IncidentAlert.incident_id == existing_incident.id,
                IncidentAlert.alert_id == alert.id,
            )
            link_res = await session.execute(link_stmt)
            if not link_res.scalars().first():
                session.add(IncidentAlert(incident_id=existing_incident.id, alert_id=alert.id))
                timeline_entry = IncidentTimeline(
                    id=str(uuid.uuid4()),
                    incident_id=existing_incident.id,
                    timestamp=now,
                    event_type="alert_correlated",
                    description=f"Correlated alert '{alert.rule_name}' (severity: {alert.severity})",
                    source="IncidentService",
                )
                session.add(timeline_entry)

            # Update severity if new alert is higher
            if SEVERITY_ORDER.get(alert.severity.lower(), 1) > SEVERITY_ORDER.get(
                existing_incident.severity.lower(), 1
            ):
                existing_incident.severity = alert.severity

            # Re-fetch all alerts associated with this incident to recalculate risk score
            all_alerts_stmt = (
                select(Alert)
                .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                .where(IncidentAlert.incident_id == existing_incident.id)
            )
            all_alerts_res = await session.execute(all_alerts_stmt)
            all_alerts = list(all_alerts_res.scalars().all())
            if alert not in all_alerts:
                all_alerts.append(alert)

            existing_incident.risk_score = self.calculate_risk_score(all_alerts, asset_crit)
            existing_incident.updated_at = now

            # Enrich multi-stage title and description if 2+ distinct MITRE techniques correlate
            techniques = [a.mitre_attack_id for a in all_alerts if a.mitre_attack_id]
            unique_techniques = list(dict.fromkeys(techniques))
            if len(unique_techniques) >= 2:
                target_name = alert.target_host or alert.target_asset_id or "target host"
                existing_incident.title = f"Multi-Stage Attack on {target_name}: {' -> '.join(unique_techniques)}"
                existing_incident.description = (
                    f"Correlated multi-stage attack campaign spanning {len(unique_techniques)} MITRE ATT&CK techniques "
                    f"({' -> '.join(unique_techniques)}) across {len(all_alerts)} alerts on {target_name}."
                )

            await session.commit()
            await session.refresh(existing_incident)
            return existing_incident

        # 2. No matching open incident within window; create a new incident
        new_incident_id = str(uuid.uuid4())
        initial_risk = self.calculate_risk_score([alert], asset_crit)
        target_name = alert.target_host or alert.target_asset_id or "unassigned host"
        incident = Incident(
            id=new_incident_id,
            title=f"Incident: {alert.rule_name} on {target_name}",
            description=f"Automated incident triggered by rule {alert.rule_id} ({alert.rule_name})",
            severity=alert.severity,
            status="OPEN",
            risk_score=initial_risk,
            target_asset_id=alert.target_asset_id,
            target_host=alert.target_host,
            created_at=now,
            updated_at=now,
        )
        session.add(incident)

        # Link alert
        session.add(IncidentAlert(incident_id=new_incident_id, alert_id=alert.id))

        # Initial timeline entry
        timeline_entry = IncidentTimeline(
            id=str(uuid.uuid4()),
            incident_id=new_incident_id,
            timestamp=now,
            event_type="incident_created",
            description=f"Incident opened from detection rule '{alert.rule_name}' with risk score {initial_risk}",
            source="IncidentService",
        )
        session.add(timeline_entry)
        await session.commit()
        await session.refresh(incident)

        # Emit notification action
        await notification_service.notify_incident(
            incident_id=incident.id,
            title=incident.title,
            severity=incident.severity,
            risk_score=incident.risk_score,
            details={"rule_id": alert.rule_id, "source_ip": alert.source_ip},
        )

        return incident

    async def recalculate_incident_for_alert(
        self, session: AsyncSession, alert: Alert
    ) -> Incident | None:
        """Recalculates risk score and applies auto-closure rules after an alert state change."""
        stmt = (
            select(Incident)
            .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
            .where(IncidentAlert.alert_id == alert.id)
            .limit(1)
        )
        result = await session.execute(stmt)
        incident = result.scalars().first()
        if not incident:
            return None

        # Fetch all alerts linked to this incident
        alerts_stmt = (
            select(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == incident.id)
        )
        alerts_res = await session.execute(alerts_stmt)
        alerts = list(alerts_res.scalars().all())

        # Resolve asset criticality
        asset_crit = "low"
        if incident.target_asset_id:
            asset = await asset_service.get_asset(session, incident.target_asset_id)
            if asset:
                asset_crit = asset.criticality

        # Recalculate risk score (automatically excludes false positives)
        incident.risk_score = self.calculate_risk_score(alerts, asset_crit)
        incident.updated_at = datetime.now(UTC)

        # Auto-closure rule: If all alerts are RESOLVED or FALSE_POSITIVE, auto-resolve incident
        if alerts and all(a.status in ["RESOLVED", "FALSE_POSITIVE"] for a in alerts):
            if incident.status not in ["RESOLVED", "CLOSED"]:
                incident.status = "RESOLVED"
                timeline_entry = IncidentTimeline(
                    id=str(uuid.uuid4()),
                    incident_id=incident.id,
                    timestamp=incident.updated_at,
                    event_type="incident_auto_resolved",
                    description="Incident automatically resolved: all correlated alerts are resolved or false positive",
                    source="IncidentService",
                )
                session.add(timeline_entry)

        await session.commit()
        await session.refresh(incident)
        return incident

    async def get_incident(self, session: AsyncSession, incident_id: str) -> Incident | None:
        """Retrieves an incident by UUID."""
        stmt = select(Incident).where(Incident.id == incident_id)
        result = await session.execute(stmt)
        return result.scalars().first()

    async def list_incidents(
        self,
        session: AsyncSession,
        *,
        status: str | None = None,
        severity: str | None = None,
        target_asset_id: str | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[Incident]:
        """Lists incidents with optional status, severity, asset, and search filtering."""
        conditions = []
        if status:
            conditions.append(Incident.status == status)
        if severity:
            conditions.append(Incident.severity == severity)
        if target_asset_id:
            conditions.append(Incident.target_asset_id == target_asset_id)
        if search:
            search_pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    Incident.title.ilike(search_pattern),
                    Incident.target_host.ilike(search_pattern),
                    Incident.description.ilike(search_pattern),
                )
            )

        stmt = (
            select(Incident)
            .where(*conditions)
            .order_by(Incident.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def update_incident(
        self,
        session: AsyncSession,
        incident_id: str,
        *,
        new_status: str | None = None,
        description: str | None = None,
        notes: str | None = None,
        user_id: str | None = None,
    ) -> Incident | None:
        """Updates an incident's lifecycle status or narrative and logs to audit trail."""
        incident = await self.get_incident(session, incident_id)
        if not incident:
            return None

        old_status = incident.status
        now = datetime.now(UTC)

        if new_status:
            incident.status = new_status
        if description:
            incident.description = description
        incident.updated_at = now

        if new_status or notes:
            desc_text = f"Incident updated to status '{incident.status}'"
            if notes:
                desc_text += f". Notes: {notes}"
            timeline_entry = IncidentTimeline(
                id=str(uuid.uuid4()),
                incident_id=incident.id,
                timestamp=now,
                event_type="incident_updated",
                description=desc_text,
                source=user_id or "Analyst",
            )
            session.add(timeline_entry)

        await session.commit()
        await session.refresh(incident)

        # Tamper-evident audit log mutation (Law 4)
        await audit_service.log_action(
            session,
            action="INCIDENT_UPDATE",
            resource_type="incident",
            resource_id=incident.id,
            user_id=user_id,
            status="SUCCESS",
            details={
                "old_status": old_status,
                "new_status": incident.status,
                "notes": notes,
            },
        )

        return incident

    async def add_timeline_entry(
        self,
        session: AsyncSession,
        incident_id: str,
        *,
        event_type: str,
        description: str,
        source: str = "SOAR_Playbook",
        user_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> IncidentTimeline | None:
        """Appends a containment or triage action to an incident's chronological timeline and audit trail."""
        incident = await self.get_incident(session, incident_id)
        if not incident:
            return None

        now = datetime.now(UTC)
        timeline_entry = IncidentTimeline(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            timestamp=now,
            event_type=event_type,
            description=description,
            source=source,
        )
        session.add(timeline_entry)
        incident.timeline.append(timeline_entry)
        incident.updated_at = now
        await session.commit()
        await session.refresh(timeline_entry)
        await session.refresh(incident)

        # Tamper-evident audit log mutation (Law 4)
        await audit_service.log_action(
            session,
            action="INCIDENT_CONTAINMENT_ACTION",
            resource_type="incident",
            resource_id=incident.id,
            user_id=user_id,
            status="SUCCESS",
            details={
                "event_type": event_type,
                "description": description,
                "source": source,
                "action_details": details or {},
            },
        )

        return timeline_entry


incident_service = IncidentService()
