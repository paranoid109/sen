"""Threat Intelligence Engine (X5).

Pluggable capability module providing:
1. Multi-format IOC feed ingestion (STIX 2.1 JSON Bundles, MISP JSON, CSV blocklists)
2. Confidence weighting and TTL-based indicator expiration/aging
3. High-throughput in-memory IOC lookup and cross-referencing
4. Telemetry event enrichment generating strongly-typed `FindingContract`

Emits findings conforming to `contracts/findings/finding_contract.json`.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from contracts.python.models import FindingContract, SeverityLevel


@dataclass
class ThreatIndicator:
    """Internal model for an Indicator of Compromise (IOC)."""

    value: str
    indicator_type: str  # "ipv4", "domain", "sha256", "url"
    severity: SeverityLevel
    confidence: int  # 0 to 100
    threat_actor: str | None = None
    campaign: str | None = None
    mitre_attack_id: str | None = None
    tags: list[str] = field(default_factory=list)
    source: str = "Unknown"
    valid_until: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def is_expired(self, current_time: datetime | None = None) -> bool:
        """Determines if the indicator has passed its expiration deadline."""
        now = current_time or datetime.now(UTC)
        if self.valid_until is None:
            return False
        return now > self.valid_until


class ThreatIntelligenceEngine:
    """Ingests threat feeds and matches security telemetry against known adversary infrastructure."""

    def __init__(self) -> None:
        # Key: normalized indicator value (lowercase) -> ThreatIndicator
        self._indicators: dict[str, ThreatIndicator] = {}

    @property
    def total_indicators(self) -> int:
        return len(self._indicators)

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Adds or updates an indicator in the local cache."""
        norm_key = indicator.value.strip().lower()
        self._indicators[norm_key] = indicator

    def lookup_ioc(self, value: str, current_time: datetime | None = None) -> ThreatIndicator | None:
        """Queries the engine for an indicator, respecting TTL expiration."""
        norm_key = value.strip().lower()
        indicator = self._indicators.get(norm_key)
        if not indicator:
            return None

        if indicator.is_expired(current_time):
            # Expired indicator is ignored
            return None

        return indicator

    def prune_expired(self, current_time: datetime | None = None) -> int:
        """Removes all expired indicators from memory."""
        now = current_time or datetime.now(UTC)
        expired_keys = [k for k, ind in self._indicators.items() if ind.is_expired(now)]
        for k in expired_keys:
            del self._indicators[k]
        return len(expired_keys)

    def ingest_csv_blocklist(
        self,
        lines: list[str],
        source: str = "CSV_Blocklist",
        default_severity: SeverityLevel = SeverityLevel.HIGH,
        default_confidence: int = 80,
    ) -> int:
        """Ingests plain list of IPs/domains or CSV (format: value[,confidence,actor,mitre_id])."""
        count = 0
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            val = parts[0]
            confidence = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else default_confidence
            actor = parts[2] if len(parts) > 2 and parts[2] else None
            mitre_id = parts[3] if len(parts) > 3 and parts[3] else "T1071"

            # Determine indicator type
            ind_type = "domain"
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
                ind_type = "ipv4"
            elif re.match(r"^[a-fA-F0-9]{64}$", val):
                ind_type = "sha256"

            self.add_indicator(
                ThreatIndicator(
                    value=val,
                    indicator_type=ind_type,
                    severity=default_severity,
                    confidence=confidence,
                    threat_actor=actor,
                    mitre_attack_id=mitre_id,
                    source=source,
                )
            )
            count += 1
        return count

    def ingest_stix_bundle(self, bundle: dict[str, Any], source: str = "STIX2.1") -> int:
        """Parses a standard STIX 2.1 JSON bundle containing indicator objects."""
        if bundle.get("type") != "bundle":
            return 0

        count = 0
        objects = bundle.get("objects", [])
        for obj in objects:
            if obj.get("type") != "indicator":
                continue

            pattern = obj.get("pattern", "")
            confidence = int(obj.get("confidence", 75))
            labels = obj.get("labels", [])

            # Extract actor/description
            desc = obj.get("description", "")
            actor = None
            if "actor:" in desc.lower():
                m = re.search(r"actor:\s*([A-Za-z0-9_-]+)", desc, re.IGNORECASE)
                if m:
                    actor = m.group(1)

            # Extract external MITRE ATT&CK reference
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name", "").lower() in ("mitre-attack", "mitre_attack"):
                    mitre_id = ref.get("external_id")

            # Extract expiration
            valid_until = None
            if obj.get("valid_until"):
                try:
                    valid_until = datetime.fromisoformat(obj["valid_until"].replace("Z", "+00:00"))
                except ValueError:
                    pass

            # Parse pattern: e.g. [ipv4-addr:value = '198.51.100.22'] or [domain-name:value = 'evil.com']
            ip_matches = re.findall(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", pattern)
            domain_matches = re.findall(r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern)
            file_matches = re.findall(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]", pattern)

            severity = SeverityLevel.CRITICAL if confidence >= 85 else SeverityLevel.HIGH

            for ip in ip_matches:
                self.add_indicator(
                    ThreatIndicator(
                        value=ip,
                        indicator_type="ipv4",
                        severity=severity,
                        confidence=confidence,
                        threat_actor=actor,
                        mitre_attack_id=mitre_id or "T1071",
                        tags=labels,
                        source=source,
                        valid_until=valid_until,
                    )
                )
                count += 1

            for dom in domain_matches:
                self.add_indicator(
                    ThreatIndicator(
                        value=dom,
                        indicator_type="domain",
                        severity=severity,
                        confidence=confidence,
                        threat_actor=actor,
                        mitre_attack_id=mitre_id or "T1071.004",
                        tags=labels,
                        source=source,
                        valid_until=valid_until,
                    )
                )
                count += 1

            for h in file_matches:
                self.add_indicator(
                    ThreatIndicator(
                        value=h,
                        indicator_type="sha256",
                        severity=SeverityLevel.CRITICAL,
                        confidence=confidence,
                        threat_actor=actor,
                        mitre_attack_id=mitre_id or "T1565.001",
                        tags=labels,
                        source=source,
                        valid_until=valid_until,
                    )
                )
                count += 1

        return count

    def ingest_misp_json(self, misp_export: dict[str, Any], source: str = "MISP") -> int:
        """Parses a MISP Event or Attribute export containing IOCs."""
        count = 0
        event = misp_export.get("Event", misp_export)
        attributes = event.get("Attribute", [])

        # Map MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
        threat_level = str(event.get("threat_level_id", "1"))
        sev_map = {
            "1": SeverityLevel.CRITICAL,
            "2": SeverityLevel.HIGH,
            "3": SeverityLevel.MEDIUM,
            "4": SeverityLevel.LOW,
        }
        severity = sev_map.get(threat_level, SeverityLevel.HIGH)

        for attr in attributes:
            attr_type = attr.get("type", "")
            val = attr.get("value", "").strip()
            if not val:
                continue

            ind_type = None
            if attr_type in ("ip-src", "ip-dst", "ip"):
                ind_type = "ipv4"
            elif attr_type in ("domain", "hostname"):
                ind_type = "domain"
            elif attr_type in ("sha256", "sha256-hash"):
                ind_type = "sha256"

            if ind_type:
                self.add_indicator(
                    ThreatIndicator(
                        value=val,
                        indicator_type=ind_type,
                        severity=severity,
                        confidence=90 if severity == SeverityLevel.CRITICAL else 75,
                        tags=[attr.get("category", "Payload delivery")],
                        source=source,
                    )
                )
                count += 1

        return count

    def enrich_event(self, event_data: dict[str, Any]) -> FindingContract | None:
        """Cross-checks an incoming telemetry event dictionary against active threat indicators."""
        candidates = []

        # Check source_ip
        if event_data.get("source_ip"):
            candidates.append(event_data["source_ip"])
        # Check destination_ip
        if event_data.get("destination_ip"):
            candidates.append(event_data["destination_ip"])
        # Check target_host
        if event_data.get("target_host"):
            candidates.append(event_data["target_host"])

        # Check details dictionary for query, domain, or hashes
        details = event_data.get("details", {})
        if isinstance(details, dict):
            for field in ("query", "domain", "sha256", "expected_sha256", "current_sha256"):
                if details.get(field):
                    candidates.append(str(details[field]))

        for candidate in candidates:
            match = self.lookup_ioc(candidate)
            if match:
                actor_str = f" attributed to adversary '{match.threat_actor}'" if match.threat_actor else ""
                desc = (
                    f"Threat Intel IOC Match: {match.value} ({match.indicator_type}){actor_str} "
                    f"from {match.source} (Confidence: {match.confidence}%)"
                )
                evidence = {
                    "matched_ioc": match.value,
                    "indicator_type": match.indicator_type,
                    "confidence": match.confidence,
                    "threat_actor": match.threat_actor,
                    "campaign": match.campaign,
                    "tags": match.tags,
                    "feed_source": match.source,
                    "event_source_ip": event_data.get("source_ip"),
                    "event_target": event_data.get("target_host"),
                }
                return FindingContract(
                    finding_id=uuid.uuid4(),
                    tool_name="threat_intelligence",
                    rule_id="RULE-TI-MATCH-001",
                    severity=match.severity,
                    target=candidate,
                    description=desc,
                    evidence=evidence,
                    timestamp=datetime.now(UTC),
                    mitre_attack_id=match.mitre_attack_id or "T1071",
                )

        return None

    def export_snapshot(self, output_path: Path | str) -> None:
        """Serializes all indicators to a JSON snapshot file."""
        data = {
            "version": "1.0",
            "exported_at": datetime.now(UTC).isoformat(),
            "indicator_count": len(self._indicators),
            "indicators": [
                {
                    **asdict(ind),
                    "severity": ind.severity.value,
                    "valid_until": ind.valid_until.isoformat() if ind.valid_until else None,
                    "created_at": ind.created_at.isoformat(),
                }
                for ind in self._indicators.values()
            ],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def import_snapshot(self, input_path: Path | str) -> int:
        """Loads indicators from a JSON snapshot file."""
        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)

        raw_list = data.get("indicators", [])
        for item in raw_list:
            vu = None
            if item.get("valid_until"):
                try:
                    vu = datetime.fromisoformat(item["valid_until"])
                except ValueError:
                    pass

            ca = datetime.now(UTC)
            if item.get("created_at"):
                try:
                    ca = datetime.fromisoformat(item["created_at"])
                except ValueError:
                    pass

            self.add_indicator(
                ThreatIndicator(
                    value=item["value"],
                    indicator_type=item["indicator_type"],
                    severity=SeverityLevel(item["severity"]),
                    confidence=int(item["confidence"]),
                    threat_actor=item.get("threat_actor"),
                    campaign=item.get("campaign"),
                    mitre_attack_id=item.get("mitre_attack_id"),
                    tags=item.get("tags", []),
                    source=item.get("source", "Snapshot"),
                    valid_until=vu,
                    created_at=ca,
                )
            )
        return len(raw_list)
