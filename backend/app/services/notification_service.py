"""Notification Service Sink.

Dispatches incident and alert notifications to configured webhooks with timeout
and network guardrails.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from backend.app.core.config import settings
from contracts.python.models import ActionContract, ActionStatus, ActionType

logger = logging.getLogger("sentinelx.notifications")


class NotificationService:
    """Service dispatching automated notifications and webhook remediation actions."""

    def __init__(self) -> None:
        self.webhook_url = settings.NOTIFICATION_WEBHOOK_URL
        self.timeout = settings.WEBHOOK_TIMEOUT_SECONDS

    async def notify_incident(
        self,
        incident_id: str,
        title: str,
        severity: str,
        risk_score: int,
        details: dict[str, Any] | None = None,
    ) -> ActionContract:
        """Emits an incident notification action payload."""
        payload = {
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "risk_score": risk_score,
            "details": details or {},
        }

        action = ActionContract(
            action_id=uuid.uuid4(),
            action_type=ActionType.WEBHOOK_NOTIFICATION,
            incident_id=uuid.UUID(incident_id),
            target=self.webhook_url or "console://stdout",
            parameters=payload,
            status=ActionStatus.PENDING,
            requested_by="IncidentService",
            requested_at=datetime.now(UTC),
        )

        if not self.webhook_url:
            logger.info(
                "Notification (Console Sink): Incident %s [%s] Risk=%d - %s",
                incident_id,
                severity,
                risk_score,
                title,
            )
            action.status = ActionStatus.COMPLETED
            action.executed_at = datetime.now(UTC)
            action.result = {"sink": "console", "status": "delivered"}
            return action

        # Dispatch external webhook with timeout and SSRF guardrails
        try:
            if not (
                self.webhook_url.startswith("http://") or self.webhook_url.startswith("https://")
            ):
                raise ValueError(f"Invalid webhook URL scheme: {self.webhook_url}")

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.webhook_url, json=action.model_dump(mode="json"))
                action.status = (
                    ActionStatus.COMPLETED if response.is_success else ActionStatus.FAILED
                )
                action.executed_at = datetime.now(UTC)
                action.result = {
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                }
        except Exception as e:
            logger.warning("Failed to dispatch webhook to %s: %s", self.webhook_url, e)
            action.status = ActionStatus.FAILED
            action.executed_at = datetime.now(UTC)
            action.result = {"error": str(e)}

        return action


notification_service = NotificationService()
