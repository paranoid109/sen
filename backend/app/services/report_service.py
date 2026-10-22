"""Reporting and KPI Metrics Service (M7).

Calculates real-time SOC operational metrics (events, active alerts, open incidents,
monitored assets, severity distribution, Mean Time to Detect) and generates executive debriefs.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.alert import Alert
from backend.app.models.asset import Asset
from backend.app.models.event import Event
from backend.app.models.incident import Incident, IncidentTimeline
from backend.app.schemas.reports import DashboardMetricsResponse, ExecutiveReportResponse


class ReportService:
    """Service generating operational dashboards and executive security reports."""

    async def get_dashboard_metrics(self, session: AsyncSession) -> DashboardMetricsResponse:
        """Calculates live operational telemetry and threat metrics."""
        # 1. Total events
        ev_stmt = select(func.count()).select_from(Event)
        total_events = (await session.execute(ev_stmt)).scalar() or 0

        # 2. Active alerts (NEW, INVESTIGATING)
        al_stmt = (
            select(func.count())
            .select_from(Alert)
            .where(Alert.status.in_(["NEW", "INVESTIGATING"]))
        )
        active_alerts = (await session.execute(al_stmt)).scalar() or 0

        # 3. Open incidents (OPEN, INVESTIGATING)
        inc_stmt = (
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(["OPEN", "INVESTIGATING"]))
        )
        open_incidents = (await session.execute(inc_stmt)).scalar() or 0

        # 4. Monitored assets
        asset_stmt = select(func.count()).select_from(Asset)
        monitored_assets = (await session.execute(asset_stmt)).scalar() or 0

        # 5. Severity breakdown
        sev_stmt = select(Alert.severity, func.count()).group_by(Alert.severity)
        sev_rows = (await session.execute(sev_stmt)).all()
        severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev, count in sev_rows:
            if sev in severity_map:
                severity_map[sev] = count

        # 6. Mean Time to Detect (MTTD in seconds)
        # Latency per alert = max(0.0, (alert.created_at - alert.first_seen).total_seconds())
        alerts_stmt = select(Alert.created_at, Alert.first_seen)
        alerts_result = (await session.execute(alerts_stmt)).all()
        if alerts_result:
            latencies = [
                max(0.0, (created_at - first_seen).total_seconds())
                for created_at, first_seen in alerts_result
                if created_at is not None and first_seen is not None
            ]
            mttd_seconds = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        else:
            mttd_seconds = None

        return DashboardMetricsResponse(
            total_events=total_events,
            active_alerts=active_alerts,
            open_incidents=open_incidents,
            monitored_assets=monitored_assets,
            severity_breakdown=severity_map,
            mttd_seconds=mttd_seconds,
        )

    async def generate_executive_report(self, session: AsyncSession) -> ExecutiveReportResponse:
        """Generates an executive security posture report with markdown debrief."""
        metrics = await self.get_dashboard_metrics(session)
        now = datetime.now(UTC)

        mttd_str = (
            f"{metrics.mttd_seconds:.1f}s"
            if metrics.mttd_seconds is not None
            else "N/A (No alerts)"
        )

        # Query MITRE ATT&CK breakdown across active alerts
        mitre_stmt = (
            select(Alert.mitre_attack_id, Alert.rule_name, func.count())
            .where(Alert.mitre_attack_id.is_not(None))
            .group_by(Alert.mitre_attack_id, Alert.rule_name)
            .order_by(func.count().desc())
        )
        mitre_rows = (await session.execute(mitre_stmt)).all()
        if mitre_rows:
            mitre_lines = "\n".join(
                f"- **`{mid}` ({rname}):** {cnt} alert(s)"
                for mid, rname, cnt in mitre_rows
            )
        else:
            mitre_lines = "- No MITRE ATT&CK techniques triggered during this period."

        # Query top targeted hosts
        host_stmt = (
            select(Alert.target_host, func.count())
            .where(Alert.target_host.is_not(None))
            .group_by(Alert.target_host)
            .order_by(func.count().desc())
            .limit(5)
        )
        host_rows = (await session.execute(host_stmt)).all()
        if host_rows:
            host_lines = "\n".join(
                f"- **`{host}`:** {cnt} alert(s)" for host, cnt in host_rows
            )
        else:
            host_lines = "- No specific host assets targeted during this period."

        # Query containment & forensics actions from incident timeline
        containment_stmt = (
            select(IncidentTimeline.event_type, func.count())
            .where(
                IncidentTimeline.event_type.in_([
                    "soar_containment_executed",
                    "soar_containment_rollback",
                    "forensic_triage_package_created",
                ])
            )
            .group_by(IncidentTimeline.event_type)
        )
        containment_rows = dict((await session.execute(containment_stmt)).all())
        soar_executed = containment_rows.get("soar_containment_executed", 0)
        soar_rollback = containment_rows.get("soar_containment_rollback", 0)
        forensics_pkg = containment_rows.get("forensic_triage_package_created", 0)

        report_markdown = f"""# SentinelX Executive Security Summary Debrief

**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}
**Classification:** Internal SOC Operational Debrief

---

## 1. Executive Summary & Security Posture
During this reporting period, the SentinelX detection and response engine monitored **{metrics.monitored_assets} enterprise assets** across the infrastructure perimeter. A total of **{metrics.total_events} raw security events** were ingested and normalized.

- **Active Alerts Under Triage:** {metrics.active_alerts}
- **Open Correlated Incidents:** {metrics.open_incidents}
- **Mean Time to Detect (MTTD):** {mttd_str}

---

## 2. Threat Severity Breakdown
The platform classified triaged security alerts into the following severity distribution:
- **Critical:** {metrics.severity_breakdown.get('critical', 0)}
- **High:** {metrics.severity_breakdown.get('high', 0)}
- **Medium:** {metrics.severity_breakdown.get('medium', 0)}
- **Low:** {metrics.severity_breakdown.get('low', 0)}

---

## 3. MITRE ATT&CK Coverage & Top Targeted Assets
### Observed Adversary Techniques
{mitre_lines}

### Top Targeted Infrastructure Hosts
{host_lines}

---

## 4. Autonomous & Supervised Containment Actions
- **Active SOAR Directives Executed:** {soar_executed} (IP Drops, Host Quarantines, Account Locks)
- **Reversible Containment Rollbacks:** {soar_rollback}
- **Sealed Forensics Triage Packages:** {forensics_pkg} (Volatile memory & disk chains of custody)

---

## 5. Operational Recommendations
1. **Critical & High Alerts:** Prioritize investigation of active incidents linked to critical server infrastructure.
2. **Detection Tuning:** Review recurring low-severity alert correlations to refine false-positive suppression rules.
3. **Audit Verification:** Ensure periodic cryptographic verification of the SHA-256 tamper-evident audit log sequence.
4. **Containment Review:** Audit active SOAR firewall drop rules and verify whether temporary TTL isolations require extension or reversal.
"""

        return ExecutiveReportResponse(
            generated_at=now,
            report_markdown=report_markdown,
            kpi_metrics=metrics,
        )


report_service = ReportService()
