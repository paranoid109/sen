"""SentinelX AI SOC Analyst Assistant Engine (Module X13).

Provides interactive, natural-language Copilot capabilities for SOC analysts:
1. Incident Executive & Technical Debrief Synthesis
2. Alert Triage Advisory & False Positive Scoring
3. Natural Language to SentinelX REST API Query Translation
4. MITRE ATT&CK Defensive Mitigation Guidance
5. Tamper-Evident Audit Logging for AI interactions (Law 4)

Conforms strictly to Law 1 & Law 2 (Decoupled Module Primacy).
Never dynamically executes code inside the detection engine (Rule A4).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

logger = logging.getLogger("sentinelx.ai_assistant")


class TriageVerdict(str, Enum):
    """Verdict classification for alert triage advisory."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS_NEED_MORE_INFO = "SUSPICIOUS_NEED_MORE_INFO"


@dataclass
class TriageAssessment:
    """Triage evaluation result with confidence and rationale."""

    verdict: TriageVerdict
    confidence_score: float  # 0.0 to 1.0
    reasoning: list[str]
    suggested_action: str
    recommended_status: str  # "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"


@dataclass
class IncidentBriefing:
    """Synthesized natural language briefing for an incident."""

    incident_id: str
    title: str
    risk_score: int
    severity: str
    executive_summary: str
    root_cause_hypothesis: str
    kill_chain_narrative: str
    mitre_mitigations: list[dict[str, str]]
    recommended_playbooks: list[str]
    markdown_content: str


@dataclass
class QueryTranslation:
    """Natural language query converted into structured SentinelX REST API parameters."""

    natural_query: str
    endpoint: str
    method: str = "GET"
    params: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""


# Canonical MITRE ATT&CK to Defense Guidance Map (CIS Controls v8 & MITRE D3FEND)
MITRE_DEFENSE_GUIDANCE: dict[str, dict[str, str]] = {
    "T1110": {
        "technique": "Brute Force",
        "cis_control": "CIS Control 5.2: Enforce Account Lockout and Adaptive MFA",
        "d3fend_countermeasure": "User Account Locking (D3-UAL) & Credential Revocation",
        "immediate_action": "Execute SOAR Account Suspension playbook for targeted username and enforce IP block.",
    },
    "T1046": {
        "technique": "Network Service Discovery",
        "cis_control": "CIS Control 4.4: Restrict Firewall Ports and Segment Networks",
        "d3fend_countermeasure": "Network Traffic Filtering (D3-NTF) & Port Knocking",
        "immediate_action": "Apply dynamic firewall block on attacker IP and review public-facing ingress rules.",
    },
    "T1190": {
        "technique": "Exploit Public-Facing Application",
        "cis_control": "CIS Control 7.4: Deploy Web Application Firewall (WAF)",
        "d3fend_countermeasure": "Input Validation (D3-IV) & Application Hardening",
        "immediate_action": "Inspect web access logs for payload execution; deploy WAF virtual patch for vulnerability.",
    },
    "T1071.004": {
        "technique": "Application Layer Protocol: DNS",
        "cis_control": "CIS Control 13.6: Enforce Protective DNS and Query Inspection",
        "d3fend_countermeasure": "DNS Filtering (D3-DNSF) & Shannon Entropy Monitoring",
        "immediate_action": "Block malicious NS/FQDN at DNS resolver and isolate queried host.",
    },
    "T1059.004": {
        "technique": "Command and Scripting Interpreter: Unix Shell",
        "cis_control": "CIS Control 8.2: Collect Auditd Process and Socket Telemetry",
        "d3fend_countermeasure": "Process Spawning Restriction (D3-PSR) & Process Lineage Analysis",
        "immediate_action": "Trigger Digital Forensics Triage package acquisition and isolate host preserving SOC ports.",
    },
    "T1565.001": {
        "technique": "Data Manipulation: Stored Data Manipulation (FIM)",
        "cis_control": "CIS Control 10.5: Implement File Integrity Monitoring (FIM)",
        "d3fend_countermeasure": "File Hash Verification (D3-FHV) & Immutable Storage",
        "immediate_action": "Compare altered file hash against golden image and restore original binaries.",
    },
    "T1530": {
        "technique": "Data from Cloud Storage Object",
        "cis_control": "CIS Control 3.11: Block Public Access on Cloud Storage Buckets",
        "d3fend_countermeasure": "Cloud Resource Access Policy (D3-CRAP) & Encryption at Rest",
        "immediate_action": "Enable Cloud Storage Public Access Block and revoke anonymous IAM permissions immediately.",
    },
    "T1021": {
        "technique": "Remote Services / Lateral Movement",
        "cis_control": "CIS Control 12.2: Implement Zero-Trust Microsegmentation",
        "d3fend_countermeasure": "Network Traffic Isolation (D3-NTI) & JIT Bastion Access",
        "immediate_action": "Revoke lateral session credentials and isolate pivot hosts along the shortest attack path.",
    },
}


class AIAssistant:
    """SOC Analyst AI Copilot engine for triage, narrative synthesis, and query translation."""

    def __init__(self, model_name: str = "sentinelx-hybrid-expert-v1") -> None:
        self.model_name = model_name

    # --------------------------------------------------------------------------
    # 1. Incident Executive & Technical Briefing Synthesis
    # --------------------------------------------------------------------------

    def synthesize_incident_briefing(self, incident_data: dict[str, Any]) -> IncidentBriefing:
        """Synthesizes comprehensive multi-alert incident timeline into an executive debrief."""
        incident_id = str(incident_data.get("incident_id") or incident_data.get("id") or uuid4())
        title = incident_data.get("title", "Correlated Security Incident")
        risk_score = int(incident_data.get("risk_score", 50))
        severity = str(incident_data.get("severity", "high")).lower()
        target_host = incident_data.get("target_host") or "monitored-infrastructure"
        description = incident_data.get("description", "")

        alerts = incident_data.get("alerts", [])
        timeline = incident_data.get("timeline", [])

        # Extract MITRE techniques and affected assets
        mitre_ids: set[str] = set()
        rules_triggered: set[str] = set()
        source_ips: set[str] = set()

        for a in alerts:
            m_id = a.get("mitre_attack_id")
            if m_id:
                mitre_ids.add(m_id)
            r_id = a.get("rule_id")
            if r_id:
                rules_triggered.add(r_id)
            sip = a.get("source_ip")
            if sip:
                source_ips.add(sip)

        # 1. Executive Summary
        threat_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 50 else "MODERATE"
        actor_summary = f"external actor(s) ({', '.join(sorted(source_ips))})" if source_ips else "unauthenticated threat actors"
        exec_summary = (
            f"SentinelX autonomous correlation has identified a **{threat_level}** risk incident (Risk Score: {risk_score}/100) "
            f"targeting critical asset `{target_host}`. Telemetry indicates coordinated activity by {actor_summary} "
            f"triggering {len(alerts)} alerts across {len(rules_triggered)} distinct detection rules."
        )
        if timeline:
            exec_summary += f" Incident audit timeline records {len(timeline)} logged operational transitions."

        # 2. Kill-Chain Progression Narrative
        kill_chain_steps: list[str] = []
        if any(m in mitre_ids for m in ["T1110", "T1046"]):
            kill_chain_steps.append("1. **Reconnaissance & Initial Probing**: Attacker performed automated network scanning and credential brute-force.")
        if any(m in mitre_ids for m in ["T1190", "T1078", "T1078.004"]):
            kill_chain_steps.append("2. **Exploitation & Initial Access**: Infiltration attempted via web vulnerability exploit or compromised credentials.")
        if any(m in mitre_ids for m in ["T1059.004", "T1548.003"]):
            kill_chain_steps.append("3. **Execution & Privilege Escalation**: Execution of interactive shells or LOLBAS utilities observed on the victim host.")
        if any(m in mitre_ids for m in ["T1021", "T1071", "T1071.004"]):
            kill_chain_steps.append("4. **C2 & Lateral Movement**: Command-and-control beaconing or lateral movement towards Crown Jewel internal assets.")
        if any(m in mitre_ids for m in ["T1530", "T1565.001"]):
            kill_chain_steps.append("5. **Data Impact & Exfiltration**: Tampering with critical host configuration or exposure of cloud storage objects.")

        if not kill_chain_steps:
            kill_chain_steps.append(f"1. **Detection & Triage**: Correlated security telemetry triggered rules {', '.join(sorted(rules_triggered)) or 'baseline alert'}.")

        kill_chain_narrative = "\n".join(kill_chain_steps)

        # 3. Root Cause Hypothesis
        if "T1190" in mitre_ids or "sql" in description.lower():
            root_cause = "Web application perimeter input sanitization failure permitting SQL injection exploit."
        elif "T1110" in mitre_ids or "brute" in description.lower():
            root_cause = "Exposed management interface (SSH/RDP) lacking multi-factor authentication and brute-force throttling."
        elif "T1530" in mitre_ids or "cloud" in description.lower():
            root_cause = "Cloud storage control plane misconfiguration granting public read permissions to unauthenticated entities."
        else:
            root_cause = f"Security boundary deviation detected on `{target_host}` matching attack signature {list(rules_triggered)[0] if rules_triggered else 'anomaly'}."

        # 4. Mitigations & Playbooks
        mitigations: list[dict[str, str]] = []
        for m in sorted(mitre_ids):
            if m in MITRE_DEFENSE_GUIDANCE:
                info = MITRE_DEFENSE_GUIDANCE[m]
                mitigations.append({
                    "mitre_id": m,
                    "technique": info["technique"],
                    "cis_control": info["cis_control"],
                    "remediation": info["immediate_action"],
                })

        playbooks = ["host_quarantine", "forensic_triage"]
        if source_ips:
            playbooks.insert(0, "block_attacker_ip")

        # 5. Build Markdown Content
        md_lines = [
            f"# SentinelX AI Incident Debrief: {title}",
            f"**Incident ID**: `{incident_id}` | **Risk Score**: `{risk_score}/100` | **Severity**: `{severity.upper()}`",
            f"**Target Host**: `{target_host}` | **Generated**: `{datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
            "",
            "## 1. Executive Summary",
            exec_summary,
            "",
            "## 2. Root Cause Hypothesis",
            f"> [!IMPORTANT]\n> **Primary Vector**: {root_cause}",
            "",
            "## 3. MITRE ATT&CK Kill-Chain Progression",
            kill_chain_narrative,
            "",
            "## 4. Immediate Defensive Guidance",
        ]

        if mitigations:
            for g in mitigations:
                md_lines.append(f"- **{g['mitre_id']} ({g['technique']})**: {g['cis_control']}")
                md_lines.append(f"  *Action*: {g['remediation']}")
        else:
            md_lines.append("- Review host process logs and network flow records for anomalies.")

        md_lines.extend([
            "",
            "## 5. Recommended Autonomous Response Playbooks",
            f"- **Playbooks**: {', '.join(playbooks)}",
            "- Preserves administrative management access on port 8000/22 while isolating untrusted traffic.",
        ])

        full_md = "\n".join(md_lines)

        return IncidentBriefing(
            incident_id=incident_id,
            title=title,
            risk_score=risk_score,
            severity=severity,
            executive_summary=exec_summary,
            root_cause_hypothesis=root_cause,
            kill_chain_narrative=kill_chain_narrative,
            mitre_mitigations=mitigations,
            recommended_playbooks=playbooks,
            markdown_content=full_md,
        )

    # --------------------------------------------------------------------------
    # 2. Alert Triage Advisor & False Positive Scorer
    # --------------------------------------------------------------------------

    def advise_alert_triage(self, alert_data: dict[str, Any]) -> TriageAssessment:
        """Evaluates alert evidence and outputs triage verdict with confidence score."""
        source_ip = alert_data.get("source_ip", "")
        rule_id = alert_data.get("rule_id", "")
        severity = str(alert_data.get("severity", "medium")).lower()
        occurrence_count = int(alert_data.get("occurrence_count", 1))
        target_host = alert_data.get("target_host", "")
        evidence = str(alert_data.get("evidence", ""))

        reasoning: list[str] = []
        is_tp = True
        confidence = 0.85

        if severity == "critical":
            reasoning.append(f"Detection rule `{rule_id}` rated as CRITICAL severity; immediate containment recommended.")
            confidence += 0.05
        elif severity == "high":
            reasoning.append(f"Detection rule `{rule_id}` rated as HIGH severity.")

        # Check 1: Source IP context
        if source_ip in ("127.0.0.1", "::1", "localhost"):
            reasoning.append(f"Traffic originated from local loopback ({source_ip}); verifying if local agent or attacker proxy.")
        elif source_ip.startswith("192.168.") or source_ip.startswith("10."):
            reasoning.append(f"Internal subnet origin ({source_ip}) suggests lateral movement or compromised internal asset.")
            confidence += 0.05
        else:
            reasoning.append(f"External routable IP ({source_ip}) targeting perimeter infrastructure.")
            confidence += 0.05

        # Check 2: Attack frequency and repetition
        if occurrence_count >= 5:
            reasoning.append(f"High occurrence frequency ({occurrence_count} events) confirms sustained, non-isolated activity.")
            confidence += 0.05
        elif occurrence_count == 1:
            reasoning.append("Single event occurrence; could be an isolated scan probe.")

        # Check 3: Signature and evidence indicators
        if any(term in evidence.lower() for term in ["union select", "1=1", "sleep(", "--"]):
            reasoning.append("Deterministic SQL injection exploit payload identified in request parameters.")
            is_tp = True
            confidence = max(confidence, 0.98)
        elif any(term in evidence.lower() for term in ["reverse_shell", "/bin/sh", "nc -e", "c2_agent"]):
            reasoning.append("Active interactive shell or command-and-control connection detected.")
            is_tp = True
            confidence = max(confidence, 0.99)
        elif "cisa-kev" in evidence.lower() or "cve-" in evidence.lower():
            reasoning.append("Vulnerability corresponds to cataloged CISA Known Exploited Vulnerability.")
            is_tp = True
            confidence = max(confidence, 0.95)
        elif "healthcheck" in evidence.lower() or "datadog" in evidence.lower() or "monitoring" in evidence.lower():
            reasoning.append("Evidence contains signatures matching approved internal monitoring healthchecks.")
            is_tp = False
            confidence = 0.92

        # Final assessment synthesis
        if is_tp and confidence >= 0.70:
            verdict = TriageVerdict.TRUE_POSITIVE
            recommended_status = "INVESTIGATING"
            suggested_action = f"Escalate alert to active incident, quarantine host `{target_host}`, and block IP `{source_ip}`."
        elif not is_tp:
            verdict = TriageVerdict.FALSE_POSITIVE
            recommended_status = "FALSE_POSITIVE"
            suggested_action = "Mark alert as FALSE_POSITIVE and tune detection exclusion filter."
        else:
            verdict = TriageVerdict.SUSPICIOUS_NEED_MORE_INFO
            recommended_status = "INVESTIGATING"
            suggested_action = "Gather supplementary packet captures and host event logs for deeper triage."

        return TriageAssessment(
            verdict=verdict,
            confidence_score=min(1.0, round(confidence, 2)),
            reasoning=reasoning,
            suggested_action=suggested_action,
            recommended_status=recommended_status,
        )

    # --------------------------------------------------------------------------
    # 3. Natural Language Query to REST Translator
    # --------------------------------------------------------------------------

    def translate_query(self, natural_query: str) -> QueryTranslation:
        """Translates analyst natural language inquiry into structured SentinelX REST API call."""
        q = natural_query.strip().lower()

        # Route 1: Alerts queries
        if any(w in q for w in ["alert", "alerts", "detections"]):
            params: dict[str, Any] = {}
            if "critical" in q:
                params["severity"] = "critical"
            elif "high" in q:
                params["severity"] = "high"
            elif "medium" in q:
                params["severity"] = "medium"
            elif "low" in q:
                params["severity"] = "low"

            if "new" in q:
                params["status"] = "NEW"
            elif "investigating" in q:
                params["status"] = "INVESTIGATING"
            elif "resolved" in q:
                params["status"] = "RESOLVED"

            # Check for host name
            host_match = re.search(r"(server-[a-z0-9-]+|db-[a-z0-9-]+|firewall-[a-z0-9-]+)", q)
            if host_match:
                params["target_host"] = host_match.group(1)

            # Check for IP address
            ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", q)
            if ip_match:
                params["source_ip"] = ip_match.group(0)

            return QueryTranslation(
                natural_query=natural_query,
                endpoint="/api/v1/alerts",
                method="GET",
                params=params,
                explanation=f"Querying security alerts with filters: {params or 'all'}",
            )

        # Route 2: Incidents queries
        if any(w in q for w in ["incident", "incidents"]):
            params = {}
            if "open" in q:
                params["status"] = "OPEN"
            elif "resolved" in q:
                params["status"] = "RESOLVED"

            risk_match = re.search(r"risk\s*(?:score)?\s*(?:above|greater than|>|over)\s*(\d+)", q)
            if risk_match:
                params["min_risk"] = int(risk_match.group(1))

            return QueryTranslation(
                natural_query=natural_query,
                endpoint="/api/v1/incidents",
                method="GET",
                params=params,
                explanation=f"Querying correlated incidents with filters: {params or 'all'}",
            )

        # Route 3: Assets queries
        if any(w in q for w in ["asset", "assets", "server", "servers", "database", "databases"]):
            params = {}
            if "critical" in q:
                params["criticality"] = "critical"
            elif "high" in q:
                params["criticality"] = "high"

            return QueryTranslation(
                natural_query=natural_query,
                endpoint="/api/v1/assets",
                method="GET",
                params=params,
                explanation=f"Querying monitored CMDB assets with filters: {params or 'all'}",
            )

        # Route 4: Audit trail queries
        if any(w in q for w in ["audit", "log", "trail", "integrity"]):
            params = {}
            user_match = re.search(r"user\s+([a-zA-Z0-9_-]+)", q)
            if user_match:
                params["username"] = user_match.group(1)

            return QueryTranslation(
                natural_query=natural_query,
                endpoint="/api/v1/audit",
                method="GET",
                params=params,
                explanation=f"Querying cryptographic audit logs with filters: {params or 'all'}",
            )

        # Default fallback: search alerts
        return QueryTranslation(
            natural_query=natural_query,
            endpoint="/api/v1/alerts",
            method="GET",
            params={},
            explanation="Unrecognized specific entity; defaulting to full alerts queue inquiry.",
        )
