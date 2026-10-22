"""Unit tests for Network Security Capability Module (X2).

Tests Shannon entropy, DNS tunneling detection, Port sweep detection,
C2 beaconing jitter analysis, Zeek log parsing, and FindingContract compliance.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

from contracts.python.models import FindingContract, SeverityLevel
from modules.network_security.analyzer import (
    NetworkSecurityAnalyzer,
    calculate_shannon_entropy,
)


def test_shannon_entropy() -> None:
    """Verifies Shannon entropy edge cases and character diversity scoring."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaa") == 0.0

    low_entropy = calculate_shannon_entropy("abcabcabc")
    high_entropy = calculate_shannon_entropy("4b8a1c902e88ad98a2f7c00192e4")

    assert low_entropy < 2.0
    assert high_entropy > 3.5


def test_dns_tunneling_detection() -> None:
    """Verifies legitimate queries pass while high-entropy exfiltration triggers T1071.004."""
    analyzer = NetworkSecurityAnalyzer()

    # Legitimate queries
    assert analyzer.analyze_dns_query("api.github.com", "10.0.0.5") is None
    assert analyzer.analyze_dns_query("subdomain.company.com", "10.0.0.5") is None

    # Tunneling query
    exfil_domain = "a9f82d1c0042e88b9021a8f9001bca2d.tunnel.attacker.com"
    finding = analyzer.analyze_dns_query(exfil_domain, "10.0.0.45", target_ip="8.8.8.8")

    assert finding is not None
    assert isinstance(finding, FindingContract)
    assert isinstance(finding.finding_id, UUID)
    assert finding.rule_id == "RULE-NET-DNS-001"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.mitre_attack_id == "T1071.004"
    assert finding.target == "8.8.8.8"
    assert isinstance(finding.evidence, dict)
    assert finding.evidence["source_ip"] == "10.0.0.45"


def test_port_sweep_detection() -> None:
    """Verifies multi-port scanning triggers T1046 alert upon threshold."""
    analyzer = NetworkSecurityAnalyzer(port_sweep_threshold=5)
    src_ip = "192.168.1.150"
    target_ip = "192.168.1.1"

    all_findings = []
    for port in [22, 80, 443, 8080]:
        res = analyzer.analyze_flow(src_ip, target_ip, port)
        all_findings.extend(res)
    assert len(all_findings) == 0

    # 5th distinct port triggers the alert
    res_trigger = analyzer.analyze_flow(src_ip, target_ip, 8443)
    assert len(res_trigger) == 1
    sweep_finding = res_trigger[0]
    assert sweep_finding.rule_id == "RULE-NET-SCAN-001"
    assert sweep_finding.severity == SeverityLevel.MEDIUM
    assert sweep_finding.mitre_attack_id == "T1046"
    assert sweep_finding.target == target_ip


def test_c2_beaconing_detection() -> None:
    """Verifies low-jitter periodic heartbeat flows trigger C2 beaconing alert."""
    analyzer = NetworkSecurityAnalyzer(
        beacon_min_connections=5,
        beacon_max_jitter_cv=0.10,
    )
    src_ip = "10.0.5.20"
    c2_ip = "198.51.100.99"
    c2_port = 4444

    base_time = 1700000000.0
    findings = []

    # 6 connections spaced strictly 15.0s apart (+/- 0.02s jitter)
    for i in range(6):
        jitter = 0.02 if i % 2 == 0 else -0.02
        ts = datetime.fromtimestamp(base_time + (i * 15.0) + jitter, tz=UTC)
        res = analyzer.analyze_flow(src_ip, c2_ip, c2_port, timestamp=ts)
        findings.extend(res)

    assert len(findings) == 1
    c2_finding = findings[0]
    assert c2_finding.rule_id == "RULE-NET-C2-001"
    assert c2_finding.severity == SeverityLevel.CRITICAL
    assert c2_finding.mitre_attack_id == "T1071"
    assert c2_finding.target == c2_ip


def test_zeek_json_parsing() -> None:
    """Verifies Zeek conn.log and dns.log parsing into FindingContract."""
    analyzer = NetworkSecurityAnalyzer()

    # Zeek DNS log line
    zeek_dns = json.dumps({
        "ts": 1700000000.0,
        "id.orig_h": "10.1.1.20",
        "id.resp_h": "10.1.1.1",
        "query": "c00192e44b8a1c902e88ad98a2f7.malicious.io",
        "qtype_name": "A",
    })

    dns_findings = analyzer.parse_zeek_json_line(zeek_dns)
    assert len(dns_findings) == 1
    assert dns_findings[0].mitre_attack_id == "T1071.004"

    # Comment / invalid line ignored
    assert analyzer.parse_zeek_json_line("#separator \x09") == []
    assert analyzer.parse_zeek_json_line("invalid json string") == []
