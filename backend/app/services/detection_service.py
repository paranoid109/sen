"""Detection Service: YAML Rule Engine and Sliding-Window Evaluation (M4)."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core import database
from backend.app.core.dispatcher import dispatcher
from backend.app.models.alert import Alert
from backend.app.models.event import Event
from backend.app.services.alert_service import alert_service
from contracts.python.models import EventContract

logger = logging.getLogger("sentinelx.detection")

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass
class DetectionRule:
    """In-memory representation of a declarative YAML detection rule."""

    id: str
    name: str
    description: str
    severity: str
    mitre_attack_id: str | None
    window_seconds: int
    threshold: int
    match: dict[str, Any] = field(default_factory=dict)
    group_by: list[str] = field(default_factory=list)


class DetectionService:
    """Service evaluating declarative security rules over sliding temporal windows."""

    def __init__(self, rules_directory: Path | None = None) -> None:
        self.rules_directory = rules_directory or RULES_DIR
        self.rules: list[DetectionRule] = []
        self._lock: asyncio.Lock | None = None
        self.load_rules()
        # Register automatic pipeline trigger on in-process dispatcher
        dispatcher.subscribe("*", self.handle_event)

    @property
    def lock(self) -> asyncio.Lock:
        """Lazily instantiates an asyncio.Lock bound to the current running loop."""
        try:
            curr_loop = asyncio.get_running_loop()
        except RuntimeError:
            curr_loop = None

        if self._lock is None or (
            hasattr(self._lock, "_loop")
            and self._lock._loop is not None
            and self._lock._loop is not curr_loop
        ):
            self._lock = asyncio.Lock()
        return self._lock

    def load_rules(self) -> None:
        """Parses and loads all declarative YAML detection rules."""
        self.rules.clear()
        if not self.rules_directory.exists():
            logger.warning("Rules directory %s does not exist", self.rules_directory)
            return

        for rule_path in self.rules_directory.glob("*.yaml"):
            try:
                with open(rule_path, encoding="utf-8") as f:
                    raw = yaml.safe_load(f)
                    rule = DetectionRule(
                        id=raw["id"],
                        name=raw["name"],
                        description=raw.get("description", ""),
                        severity=raw.get("severity", "medium"),
                        mitre_attack_id=raw.get("mitre_attack_id"),
                        window_seconds=int(raw.get("window_seconds", 60)),
                        threshold=int(raw.get("threshold", 1)),
                        match=raw.get("match", {}),
                        group_by=raw.get("group_by", ["source_ip"]),
                    )
                    self.rules.append(rule)
                    logger.debug("Loaded rule %s: %s", rule.id, rule.name)
            except Exception:
                logger.exception("Failed loading detection rule from %s", rule_path)

    async def evaluate_event(self, session: AsyncSession, event: EventContract) -> list[Alert]:
        """Evaluates all loaded rules against an incoming event using Python-bound timedelta windows."""
        triggered_alerts: list[Alert] = []

        for rule in self.rules:
            # Check match predicate
            expected_event_type = rule.match.get("event_type")
            if expected_event_type and expected_event_type != event.event_type:
                continue

            # Reference clock semantics: window computed relative to event timestamp
            window_start = event.event_time - timedelta(seconds=rule.window_seconds)

            # Query historical events in window honoring rule.group_by (Dialect-Agnostic SQL, Law 3)
            conditions = [
                Event.event_type == event.event_type,
                Event.event_time >= window_start,
                Event.event_time <= event.event_time,
            ]
            group_fields = rule.group_by or ["source_ip"]
            for g_field in group_fields:
                if hasattr(Event, g_field) and hasattr(event, g_field):
                    conditions.append(getattr(Event, g_field) == getattr(event, g_field))

            stmt = select(Event).where(*conditions).order_by(Event.event_time.asc())
            result = await session.execute(stmt)
            matching_events = list(result.scalars().all())

            # Pattern filtering if specified by rule
            patterns = rule.match.get("patterns", [])
            if patterns:
                filtered_events: list[Event] = []
                for ev in matching_events:
                    payload_str = ev.raw_payload or ""
                    details_str = (
                        " ".join(f"{k}={v}" for k, v in ev.details.items()) if ev.details else ""
                    )
                    search_text = f"{payload_str} {details_str}"
                    if any(re.search(pat, search_text) for pat in patterns):
                        filtered_events.append(ev)
                matching_events = filtered_events

            # Distinct aggregation if specified by rule
            distinct_field = rule.match.get("distinct")
            if distinct_field:
                distinct_values = {
                    getattr(e, distinct_field)
                    for e in matching_events
                    if getattr(e, distinct_field, None) is not None
                }
                current_count = len(distinct_values)
            else:
                current_count = len(matching_events)

            if current_count >= rule.threshold and matching_events:
                evidence_ids = [e.id for e in matching_events]
                first_seen = matching_events[0].event_time
                last_seen = matching_events[-1].event_time

                alert, is_created = await alert_service.create_or_update_alert(
                    session,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    mitre_attack_id=rule.mitre_attack_id,
                    source_ip=event.source_ip,
                    target_asset_id=event.target_asset_id,
                    target_host=event.target_host,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    evidence=evidence_ids,
                )
                triggered_alerts.append(alert)

        return triggered_alerts

    async def handle_event(self, event: EventContract) -> None:
        """Asynchronous subscriber callback invoked by dispatcher in sequential order."""
        async with self.lock:
            async with database.async_session_factory() as session:
                try:
                    await self.evaluate_event(session, event)
                except Exception:
                    logger.exception(
                        "Failed evaluating detection rules for event %s", event.event_id
                    )


detection_service = DetectionService()
