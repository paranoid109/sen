"""Web Security Analyzer (X1).

Standalone analyzer inspecting HTTP request logs and URIs for SQL injection exploits.
Loads canonical detection signatures from `backend/app/rules/sql_injection.yaml` (Decision S8).
"""

from __future__ import annotations

import re
import urllib.parse
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml

from contracts.python.models import FindingContract, SeverityLevel

DEFAULT_RULE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "backend"
    / "app"
    / "rules"
    / "sql_injection.yaml"
)

# Standard Combined Access Log regex
WEB_LOG_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/[\d\.]+)?\"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)


class WebSecurityAnalyzer:
    """Analyzer detecting web application vulnerabilities using declarative rule signatures."""

    def __init__(self, rule_path: Path | str | None = None) -> None:
        self.rule_path = Path(rule_path) if rule_path else DEFAULT_RULE_PATH
        self.rule_id: str = "RULE-WEB-001"
        self.rule_name: str = "SQL Injection Attack Detected"
        self.severity: SeverityLevel = SeverityLevel.HIGH
        self.mitre_attack_id: str | None = "T1190"
        self.patterns: list[re.Pattern[str]] = []
        self.load_rules()

    def load_rules(self) -> None:
        """Loads canonical SQL injection patterns from the backend YAML rule."""
        if not self.rule_path.exists():
            # Fallback patterns in case file is absent in isolated environment
            raw_patterns = [
                r"(?i)(union\s+all\s+select|union\s+select)",
                r"(?i)(\bor\b\s+['\"]?\d+['\"]?\s*=\\s*['\"]?\d+)",
                r"(?i)('\s*or\s*'1'\s*=\s*'1)",
                r"(?i)(exec(\s|\+)+(s|x)p\w+)",
                r"(?i)(--|#|/\*).*$",
                r"(?i)(';\s*drop\s+table)",
            ]
        else:
            with open(self.rule_path, encoding="utf-8") as f:
                rule_data = yaml.safe_load(f)
                self.rule_id = rule_data.get("id", self.rule_id)
                self.rule_name = rule_data.get("name", self.rule_name)
                sev_str = rule_data.get("severity", "high").lower()
                self.severity = (
                    SeverityLevel(sev_str)
                    if sev_str in SeverityLevel._value2member_map_
                    else SeverityLevel.HIGH
                )
                self.mitre_attack_id = rule_data.get("mitre_attack_id", self.mitre_attack_id)
                raw_patterns = rule_data.get("match", {}).get("patterns", [])

        self.patterns = [re.compile(p) for p in raw_patterns]

    def analyze_text(
        self,
        text: str,
        *,
        source_ip: str = "127.0.0.1",
        target: str = "web-service",
    ) -> FindingContract | None:
        """Analyzes a single text string or query parameter payload for SQLi exploit patterns."""
        decoded = urllib.parse.unquote(text)
        for pattern in self.patterns:
            match = pattern.search(decoded)
            if match:
                return FindingContract(
                    finding_id=uuid.uuid4(),
                    tool_name="web_security",
                    rule_id=self.rule_id,
                    severity=self.severity,
                    target=target,
                    description=f"SQL injection exploit pattern detected matching signature '{pattern.pattern}'",
                    evidence={
                        "matched_pattern": pattern.pattern,
                        "matched_string": match.group(0),
                        "payload": text,
                        "source_ip": source_ip,
                    },
                    timestamp=datetime.now(UTC),
                    mitre_attack_id=self.mitre_attack_id,
                )
        return None

    def analyze_log_line(
        self,
        line: str,
        *,
        target_host: str = "web-service",
    ) -> FindingContract | None:
        """Parses a web server access log line and scans request URI and payload for SQLi."""
        match = WEB_LOG_RE.search(line.strip())
        if match:
            client_ip, _ts, _method, raw_uri, _status, _bytes, _ref, _agent = match.groups()
            finding = self.analyze_text(
                raw_uri, source_ip=client_ip, target=f"{target_host}{raw_uri}"
            )
            if finding:
                return finding
        else:
            # Fallback to direct raw line scan
            finding = self.analyze_text(line, target=target_host)
            if finding:
                return finding

        return None

    analyze_line = analyze_log_line

    def analyze_file(
        self,
        file_path: Path | str,
        *,
        target_host: str = "web-service",
    ) -> list[FindingContract]:
        """Scans an entire web log file, returning a list of all detected security findings."""
        findings: list[FindingContract] = []
        path = Path(file_path)
        if not path.exists():
            return findings

        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                finding = self.analyze_log_line(line, target_host=target_host)
                if finding:
                    findings.append(finding)

        return findings
