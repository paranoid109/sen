"""Dynamic Risk Engine Capability Module (X9).

Provides multi-factor graph-aware quantitative risk scoring incorporating
asset criticality, threat velocity, CISA KEV exploitability, and topological
blast radius with closed-form [0, 100] bounds (Law 1, Law 2, Law 6).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from contracts.python.models import FindingContract, SeverityLevel

# Quantitative Asset Criticality Multipliers
CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.8,
}

# Base Threat Severity Scores
BASE_SEVERITY_SCORES: dict[str, float] = {
    "critical": 35.0,
    "high": 25.0,
    "medium": 15.0,
    "low": 5.0,
}


@dataclass
class DynamicRiskEvaluation:
    """Detailed quantitative risk assessment breakdown for an asset or incident."""

    asset_id: str
    risk_score: int  # [0, 100]
    risk_tier: SeverityLevel  # "critical", "high", "medium", "low"
    base_severity_score: float
    criticality_multiplier: float
    threat_velocity_factor: float
    exploitability_factor: float
    blast_radius_factor: float
    factors_summary: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class DynamicRiskEngine:
    """Advanced quantitative risk engine with topological and threat intelligence factors."""

    def __init__(self, risk_threshold_critical: int = 80, risk_threshold_high: int = 60) -> None:
        self.risk_threshold_critical = risk_threshold_critical
        self.risk_threshold_high = risk_threshold_high

    def calculate_risk(
        self,
        asset_id: str,
        asset_criticality: str = "medium",
        highest_alert_severity: str = "medium",
        alert_count: int = 1,
        has_cisa_kev: bool = False,
        cvss_score: float | None = None,
        reachable_nodes: int = 0,
        crown_jewel_exposed: bool = False,
    ) -> DynamicRiskEvaluation:
        """Computes multi-factor closed-form bounded dynamic risk score [0, 100]."""
        # 1. Base Severity & Asset Multiplier
        crit_key = asset_criticality.lower()
        multiplier = CRITICALITY_MULTIPLIERS.get(crit_key, 1.0)
        sev_key = highest_alert_severity.lower()
        base_score = BASE_SEVERITY_SCORES.get(sev_key, 15.0)
        base_component = base_score * multiplier

        # 2. Threat Velocity Factor (capped at 20)
        velocity_factor = min(20.0, max(0.0, (alert_count - 1) * 3.0))

        # 3. Exploitability & Vulnerability Exposure Factor (capped at 25)
        exploit_factor = 0.0
        if has_cisa_kev or (cvss_score is not None and cvss_score >= 9.0):
            exploit_factor = 25.0
        elif cvss_score is not None and cvss_score >= 7.0:
            exploit_factor = 15.0

        # 4. Topological Blast Radius Factor (capped at 20)
        blast_factor = 0.0
        if crown_jewel_exposed:
            blast_factor = 20.0
        elif reachable_nodes > 0:
            blast_factor = min(15.0, reachable_nodes * 2.5)

        # 5. Composite Bounded Score
        raw_score = base_component + velocity_factor + exploit_factor + blast_factor
        final_score = min(100, max(0, round(raw_score)))

        # Determine Risk Tier
        tier: SeverityLevel
        if final_score >= self.risk_threshold_critical:
            tier = "critical"
        elif final_score >= self.risk_threshold_high:
            tier = "high"
        elif final_score >= 35:
            tier = "medium"
        else:
            tier = "low"

        # Actionable recommendations
        recommendations: list[str] = []
        if has_cisa_kev:
            recommendations.append("Immediate patch priority: CVE actively exploited in the wild (CISA KEV).")
        if crown_jewel_exposed:
            recommendations.append("Topological risk: Direct lateral attack path exists to Core Crown Jewel.")
        if velocity_factor >= 15.0:
            recommendations.append("Active attack campaign: Rapid multi-alert velocity detected.")
        if not recommendations:
            recommendations.append("Maintain standard SOC monitoring cadence.")

        factors = {
            "asset_criticality": crit_key,
            "multiplier": multiplier,
            "highest_alert_severity": sev_key,
            "base_component": round(base_component, 2),
            "alert_count": alert_count,
            "threat_velocity": round(velocity_factor, 2),
            "has_cisa_kev": has_cisa_kev,
            "cvss_score": cvss_score,
            "exploit_factor": round(exploit_factor, 2),
            "reachable_nodes": reachable_nodes,
            "crown_jewel_exposed": crown_jewel_exposed,
            "blast_factor": round(blast_factor, 2),
        }

        return DynamicRiskEvaluation(
            asset_id=asset_id,
            risk_score=final_score,
            risk_tier=tier,
            base_severity_score=base_score,
            criticality_multiplier=multiplier,
            threat_velocity_factor=velocity_factor,
            exploitability_factor=exploit_factor,
            blast_radius_factor=blast_factor,
            factors_summary=factors,
            recommendations=recommendations,
        )

    def evaluate_to_finding(
        self,
        asset_id: str,
        asset_criticality: str = "medium",
        highest_alert_severity: str = "medium",
        alert_count: int = 1,
        has_cisa_kev: bool = False,
        cvss_score: float | None = None,
        reachable_nodes: int = 0,
        crown_jewel_exposed: bool = False,
    ) -> FindingContract | None:
        """Produces a FindingContract if the dynamic risk score is high or critical."""
        eval_result = self.calculate_risk(
            asset_id=asset_id,
            asset_criticality=asset_criticality,
            highest_alert_severity=highest_alert_severity,
            alert_count=alert_count,
            has_cisa_kev=has_cisa_kev,
            cvss_score=cvss_score,
            reachable_nodes=reachable_nodes,
            crown_jewel_exposed=crown_jewel_exposed,
        )

        if eval_result.risk_tier not in ("critical", "high"):
            return None

        return FindingContract(
            finding_id=uuid.uuid4(),
            tool_name="dynamic_risk_engine",
            rule_id="RULE-RISK-DYNAMIC-ESCALATION",
            severity=eval_result.risk_tier,
            target=asset_id,
            description=(
                f"Dynamic Risk Escalation for asset {asset_id}: Score {eval_result.risk_score}/100 "
                f"({eval_result.risk_tier.upper()}). Factors: {'; '.join(eval_result.recommendations)}"
            ),
            evidence=eval_result.factors_summary,
            timestamp=datetime.now(UTC),
            mitre_attack_id="T1190" if has_cisa_kev else "T1071",
        )
