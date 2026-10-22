"""Advanced Multi-Stage Correlation Engine Capability Module (X7).

Reconstructs multi-stage cyber attack kill-chains using Complex Event Processing (CEP)
and Directed Acyclic Graph (DAG) state tracking across multi-hour temporal windows (Law 1 & Law 2).
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from contracts.python.models import (
    IncidentContract,
    IncidentStatus,
    SeverityLevel,
    TimelineItem,
)


class KillChainStage(enum.IntEnum):
    """Linearized MITRE ATT&CK Kill-Chain Stages."""

    RECONNAISSANCE = 1
    INITIAL_ACCESS = 2
    EXECUTION = 3
    COMMAND_AND_CONTROL = 4


# MITRE Technique to Kill-Chain Stage Mapping
TECHNIQUE_STAGE_MAP: dict[str, KillChainStage] = {
    # Stage 1: Reconnaissance
    "T1046": KillChainStage.RECONNAISSANCE,  # Network Service Discovery / Port Scan
    "T1595": KillChainStage.RECONNAISSANCE,  # Active Scanning
    "RULE-NET-001": KillChainStage.RECONNAISSANCE,
    # Stage 2: Initial Access & Credential Access
    "T1110": KillChainStage.INITIAL_ACCESS,  # Brute Force
    "T1110.001": KillChainStage.INITIAL_ACCESS,
    "T1190": KillChainStage.INITIAL_ACCESS,  # Exploit Public-Facing Application / SQLi / KEV
    "RULE-AUTH-001": KillChainStage.INITIAL_ACCESS,
    "RULE-WEB-001": KillChainStage.INITIAL_ACCESS,
    "RULE-VULN-001": KillChainStage.INITIAL_ACCESS,
    # Stage 3: Execution, Persistence, Defense Evasion
    "T1059": KillChainStage.EXECUTION,  # Command and Scripting Interpreter / LOLBAS
    "T1059.001": KillChainStage.EXECUTION,
    "T1059.004": KillChainStage.EXECUTION,
    "T1078": KillChainStage.EXECUTION,  # Valid Accounts / UEBA Behavioral Anomaly
    "T1565": KillChainStage.EXECUTION,  # Data/System Tampering / FIM
    "T1565.001": KillChainStage.EXECUTION,
    "RULE-EDR-001": KillChainStage.EXECUTION,
    "RULE-EDR-002": KillChainStage.EXECUTION,
    "RULE-ML-001": KillChainStage.EXECUTION,
    # Stage 4: Command and Control & Exfiltration
    "T1071": KillChainStage.COMMAND_AND_CONTROL,  # Application Layer Protocol / C2
    "T1071.004": KillChainStage.COMMAND_AND_CONTROL,  # DNS Tunneling
    "T1041": KillChainStage.COMMAND_AND_CONTROL,  # Exfiltration Over C2 Channel
    "RULE-TI-001": KillChainStage.COMMAND_AND_CONTROL,
    "RULE-NET-002": KillChainStage.COMMAND_AND_CONTROL,
}


@dataclass
class AlertNode:
    """Normalized representation of an alert in the correlation graph."""

    alert_id: str
    rule_id: str
    rule_name: str
    mitre_id: str | None
    stage: KillChainStage
    severity: str
    source_ip: str
    target_host: str | None
    target_asset_id: str | None
    timestamp: datetime
    raw_alert: dict[str, Any] = field(default_factory=dict)


@dataclass
class KillChainCampaign:
    """A tracked multi-stage attack sequence progressing across an asset."""

    campaign_id: str
    entity_key: str
    target_host: str | None
    target_asset_id: str | None
    nodes: list[AlertNode] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def stages_covered(self) -> set[KillChainStage]:
        return {node.stage for node in self.nodes}


class AdvancedCorrelationEngine:
    """Directed temporal graph correlator tracking multi-stage attack campaigns."""

    def __init__(self, time_window_hours: int = 4) -> None:
        self.time_window = timedelta(hours=time_window_hours)
        self.campaigns: dict[str, KillChainCampaign] = {}

    def _resolve_stage(self, mitre_id: str | None, rule_id: str | None) -> KillChainStage:
        """Resolves MITRE ID or rule ID to a KillChainStage."""
        if mitre_id and mitre_id in TECHNIQUE_STAGE_MAP:
            return TECHNIQUE_STAGE_MAP[mitre_id]
        if rule_id and rule_id in TECHNIQUE_STAGE_MAP:
            return TECHNIQUE_STAGE_MAP[rule_id]
        return KillChainStage.INITIAL_ACCESS

    def process_alert(self, alert: dict[str, Any]) -> IncidentContract | None:
        """Processes an incoming alert dictionary and checks if it forms a multi-stage campaign."""
        alert_id = str(alert.get("alert_id") or alert.get("id") or uuid.uuid4())
        rule_id = str(alert.get("rule_id", "UNKNOWN"))
        rule_name = str(alert.get("rule_name", "Security Alert"))
        mitre_id = alert.get("mitre_attack_id") or alert.get("mitre_id")
        stage = self._resolve_stage(mitre_id, rule_id)

        raw_time = alert.get("first_seen") or alert.get("created_at") or alert.get("timestamp")
        if isinstance(raw_time, str):
            try:
                alert_time = datetime.fromisoformat(raw_time)
            except Exception:
                alert_time = datetime.now(UTC)
        elif isinstance(raw_time, datetime):
            alert_time = raw_time
        else:
            alert_time = datetime.now(UTC)

        source_ip = str(alert.get("source_ip", "0.0.0.0"))
        target_host = alert.get("target_host")
        target_asset_id = alert.get("target_asset_id")
        severity = str(alert.get("severity", "medium")).lower()

        node = AlertNode(
            alert_id=alert_id,
            rule_id=rule_id,
            rule_name=rule_name,
            mitre_id=mitre_id,
            stage=stage,
            severity=severity,
            source_ip=source_ip,
            target_host=target_host,
            target_asset_id=target_asset_id,
            timestamp=alert_time,
            raw_alert=alert,
        )

        # Primary correlation key is the targeted entity
        entity_key = target_host or target_asset_id or source_ip

        if entity_key not in self.campaigns:
            campaign = KillChainCampaign(
                campaign_id=str(uuid.uuid4()),
                entity_key=entity_key,
                target_host=target_host,
                target_asset_id=target_asset_id,
                nodes=[node],
                created_at=alert_time,
                updated_at=alert_time,
            )
            self.campaigns[entity_key] = campaign
            return None

        campaign = self.campaigns[entity_key]

        # Check temporal window (prune or reset if expired)
        if alert_time - campaign.updated_at > self.time_window:
            # Window expired; start fresh campaign
            campaign = KillChainCampaign(
                campaign_id=str(uuid.uuid4()),
                entity_key=entity_key,
                target_host=target_host,
                target_asset_id=target_asset_id,
                nodes=[node],
                created_at=alert_time,
                updated_at=alert_time,
            )
            self.campaigns[entity_key] = campaign
            return None

        # Append alert node and update campaign state
        campaign.nodes.append(node)
        campaign.updated_at = alert_time

        # Check if campaign spans 2 or more distinct kill-chain stages
        stages = campaign.stages_covered
        if len(stages) >= 2:
            return self._synthesize_incident(campaign)

        return None

    def _synthesize_incident(self, campaign: KillChainCampaign) -> IncidentContract:
        """Synthesizes a high-confidence IncidentContract from correlated campaign stages."""
        sorted_nodes = sorted(campaign.nodes, key=lambda n: n.timestamp)
        stages_ordered = sorted(list(campaign.stages_covered))
        stage_names = [s.name.replace("_", " ").title() for s in stages_ordered]

        title = f"Multi-Stage Attack Campaign: {' -> '.join(stage_names)}"
        description = (
            f"Correlated {len(sorted_nodes)} security alerts across {len(stages_ordered)} MITRE ATT&CK "
            f"kill-chain stages targeting {campaign.entity_key}. Progression: {' -> '.join(stage_names)}."
        )

        # Calculate Closed-Form Risk Score [0, 100]
        # Base weight from stages + severity bonus
        stage_weight = len(stages_ordered) * 20  # 2 stages = 40, 3 stages = 60, 4 stages = 80
        has_critical = any(n.severity == "critical" for n in sorted_nodes)
        has_high = any(n.severity == "high" for n in sorted_nodes)

        severity_bonus = 20 if has_critical else (10 if has_high else 0)
        volume_bonus = min(len(sorted_nodes) * 2, 10)
        risk_score = min(max(stage_weight + severity_bonus + volume_bonus, 10), 100)

        incident_severity: SeverityLevel
        if risk_score >= 80 or has_critical:
            incident_severity = "critical"
        elif risk_score >= 60 or has_high:
            incident_severity = "high"
        elif risk_score >= 40:
            incident_severity = "medium"
        else:
            incident_severity = "low"

        # Build chronological TimelineItem audit entries
        timeline: list[TimelineItem] = []
        for n in sorted_nodes:
            timeline.append(
                TimelineItem(
                    timestamp=n.timestamp,
                    event_type=f"KILLCHAIN_{n.stage.name}",
                    description=f"{n.rule_name} ({n.rule_id}) from {n.source_ip}",
                    source="correlation_engine",
                )
            )

        return IncidentContract(
            incident_id=uuid.UUID(campaign.campaign_id),
            title=title,
            description=description,
            severity=incident_severity,
            status=IncidentStatus.OPEN,
            risk_score=risk_score,
            target_asset_id=campaign.target_asset_id,
            target_host=campaign.target_host,
            alert_ids=[n.alert_id for n in sorted_nodes],
            timeline=timeline,
            created_at=campaign.created_at,
            updated_at=campaign.updated_at,
        )
