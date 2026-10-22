"""Network Security Analyzer (X2).

Pluggable capability module analyzing network telemetry for:
1. DNS Tunneling & Exfiltration (MITRE ATT&CK T1071.004) via Shannon entropy & query length
2. Command & Control (C2) Periodic Beaconing (MITRE ATT&CK T1071) via connection delta variance
3. Multi-port Reconnaissance & Port Sweeps (MITRE ATT&CK T1046)

Supports Dual-Mode Ingestion:
- Structured Zeek / Suricata / NetFlow JSON log streams
- Native binary PCAP stream parser (pure Python, driver-free)

Emits strongly-typed `FindingContract` compliant with `contracts/findings/finding_contract.json`.
"""

from __future__ import annotations

import json
import math
import struct
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from contracts.python.models import FindingContract, SeverityLevel


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character.

    Entropy H(X) = -sum(P(x) * log2(P(x)))
    Random/encrypted/base64 strings exhibit high entropy (typically > 3.8).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class NetworkSecurityAnalyzer:
    """Analyzes network flow records and DNS requests for security anomalies."""

    def __init__(
        self,
        dns_entropy_threshold: float = 3.3,
        dns_length_threshold: int = 28,
        beacon_min_connections: int = 5,
        beacon_max_jitter_cv: float = 0.15,
        port_sweep_threshold: int = 10,
    ) -> None:
        self.dns_entropy_threshold = dns_entropy_threshold
        self.dns_length_threshold = dns_length_threshold
        self.beacon_min_connections = beacon_min_connections
        self.beacon_max_jitter_cv = beacon_max_jitter_cv
        self.port_sweep_threshold = port_sweep_threshold

        # In-memory tracking for stateful anomaly correlation
        self._connection_history: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        self._port_scan_history: dict[str, set[int]] = defaultdict(set)

    def analyze_dns_query(
        self,
        query: str,
        source_ip: str,
        target_ip: str | None = None,
        query_type: str = "A",
        timestamp: datetime | None = None,
    ) -> FindingContract | None:
        """Analyzes a single DNS query for tunneling or data exfiltration markers."""
        ts = timestamp or datetime.now(UTC)
        clean_query = query.strip().rstrip(".")

        # Extract subdomain prefix (e.g. "a9f82d1c.attacker.com" -> "a9f82d1c")
        parts = clean_query.split(".")
        subdomain = parts[0] if len(parts) > 2 else clean_query

        entropy = calculate_shannon_entropy(subdomain)
        is_high_entropy = entropy >= self.dns_entropy_threshold
        is_suspicious_length = len(subdomain) >= self.dns_length_threshold

        if is_high_entropy and is_suspicious_length:
            return FindingContract(
                finding_id=uuid.uuid4(),
                tool_name="network_security",
                rule_id="RULE-NET-DNS-001",
                severity=SeverityLevel.HIGH,
                target=target_ip or "dns_resolver",
                description=f"DNS Tunneling / Data Exfiltration Anomaly: '{clean_query}' (Entropy: {round(entropy, 3)}, length: {len(subdomain)})",
                evidence={
                    "query": clean_query,
                    "subdomain": subdomain,
                    "entropy": round(entropy, 3),
                    "length": len(subdomain),
                    "query_type": query_type,
                    "source_ip": source_ip,
                    "mitre_technique": "DNS Tunneling",
                },
                timestamp=ts,
                mitre_attack_id="T1071.004",
            )
        return None

    def analyze_flow(
        self,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        proto: str = "tcp",
        timestamp: datetime | None = None,
    ) -> list[FindingContract]:
        """Analyzes network connection flows for port sweeping and C2 beaconing."""
        ts = timestamp or datetime.now(UTC)
        findings: list[FindingContract] = []
        epoch = ts.timestamp()

        # 1. Port Sweep Detection (T1046)
        ports = self._port_scan_history[source_ip]
        ports.add(dest_port)
        if len(ports) == self.port_sweep_threshold:
            findings.append(
                FindingContract(
                    finding_id=uuid.uuid4(),
                    tool_name="network_security",
                    rule_id="RULE-NET-SCAN-001",
                    severity=SeverityLevel.MEDIUM,
                    target=dest_ip,
                    description=f"Port Sweep Activity: Host {source_ip} probed {len(ports)} distinct ports on {dest_ip}",
                    evidence={
                        "source_ip": source_ip,
                        "unique_ports_contacted": len(ports),
                        "probed_ports": sorted(list(ports))[:20],
                        "protocol": proto,
                    },
                    timestamp=ts,
                    mitre_attack_id="T1046",
                )
            )

        # 2. C2 Beaconing Jitter Analysis (T1071)
        flow_key = (source_ip, dest_ip, dest_port)
        history = self._connection_history[flow_key]
        history.append(epoch)

        if len(history) >= self.beacon_min_connections:
            # Calculate intervals between consecutive connections
            deltas = [history[i] - history[i - 1] for i in range(1, len(history))]
            avg_delta = sum(deltas) / len(deltas)

            # Avoid division by zero on simultaneous bursts
            if avg_delta > 1.0:
                variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
                std_dev = math.sqrt(variance)
                coeff_of_variation = std_dev / avg_delta

                if coeff_of_variation <= self.beacon_max_jitter_cv:
                    findings.append(
                        FindingContract(
                            finding_id=uuid.uuid4(),
                            tool_name="network_security",
                            rule_id="RULE-NET-C2-001",
                            severity=SeverityLevel.CRITICAL,
                            target=dest_ip,
                            description=f"Periodic C2 Beaconing Pattern Detected from {source_ip} to {dest_ip}:{dest_port} (mean interval: {avg_delta:.1f}s, jitter CV: {coeff_of_variation:.4f})",
                            evidence={
                                "source_ip": source_ip,
                                "dest_ip": dest_ip,
                                "dest_port": dest_port,
                                "connections_count": len(history),
                                "mean_interval_sec": round(avg_delta, 2),
                                "jitter_cv": round(coeff_of_variation, 4),
                            },
                            timestamp=ts,
                            mitre_attack_id="T1071",
                        )
                    )
                    # Reset history to prevent flood
                    self._connection_history[flow_key] = [epoch]

        return findings

    def parse_zeek_json_line(self, line: str) -> list[FindingContract]:
        """Parses a structured JSON line from Zeek (conn.log or dns.log)."""
        line = line.strip()
        if not line or line.startswith("#"):
            return []

        try:
            record: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            return []

        findings: list[FindingContract] = []
        ts_val = record.get("ts")
        timestamp = (
            datetime.fromtimestamp(float(ts_val), tz=UTC)
            if ts_val
            else datetime.now(UTC)
        )

        # Zeek dns.log format
        if "query" in record:
            src = record.get("id.orig_h") or record.get("source_ip", "0.0.0.0")
            dst = record.get("id.resp_h") or record.get("dest_ip")
            query = record.get("query", "")
            qtype = record.get("qtype_name") or record.get("qtype", "A")
            finding = self.analyze_dns_query(query, src, dst, qtype, timestamp)
            if finding:
                findings.append(finding)

        # Zeek conn.log format
        if "id.resp_p" in record or "dest_port" in record:
            src = record.get("id.orig_h") or record.get("source_ip", "0.0.0.0")
            dst = record.get("id.resp_h") or record.get("dest_ip", "0.0.0.0")
            port = int(record.get("id.resp_p") or record.get("dest_port", 0))
            proto = record.get("proto", "tcp")
            if port > 0:
                flow_findings = self.analyze_flow(src, dst, port, proto, timestamp)
                findings.extend(flow_findings)

        return findings

    def parse_pcap_file(self, pcap_path: Path | str) -> list[FindingContract]:
        """Reads a binary PCAP file using native pure Python struct parsing.

        No external C-libpcap or driver dependencies required.
        Extracts IPv4 TCP/UDP packets and basic DNS headers.
        """
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        findings: list[FindingContract] = []

        with open(path, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return []

            magic, _, _, _, _, _, link_type = struct.unpack("=IHHiIII", header)
            if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
                # Unsupported or non-standard PCAP
                return []

            # Link type 1 = Ethernet
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, _ = struct.unpack("=IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                pkt_ts = datetime.fromtimestamp(ts_sec + (ts_usec / 1e6), tz=UTC)

                # Ethernet frame (14 bytes)
                if link_type == 1 and len(pkt_data) > 34:
                    eth_type = struct.unpack("!H", pkt_data[12:14])[0]
                    if eth_type == 0x0800:  # IPv4
                        ip_header = pkt_data[14:34]
                        ip_proto = ip_header[9]
                        src_ip = ".".join(str(b) for b in ip_header[12:16])
                        dst_ip = ".".join(str(b) for b in ip_header[16:20])

                        # TCP (6) or UDP (17)
                        if ip_proto in (6, 17) and len(pkt_data) >= 38:
                            transport_hdr = pkt_data[34:38]
                            src_port, dst_port = struct.unpack("!HH", transport_hdr)

                            # Check flow
                            flow_res = self.analyze_flow(src_ip, dst_ip, dst_port, "tcp" if ip_proto == 6 else "udp", pkt_ts)
                            findings.extend(flow_res)

                            # Check DNS (UDP port 53)
                            if dst_port == 53 and len(pkt_data) > 46:
                                dns_payload = pkt_data[42:]
                                # Simple extraction of DNS QNAME (RFC 1035 labels)
                                try:
                                    labels = []
                                    idx = 12  # DNS header is 12 bytes
                                    while idx < len(dns_payload):
                                        length = dns_payload[idx]
                                        if length == 0 or length > 63:
                                            break
                                        idx += 1
                                        labels.append(dns_payload[idx : idx + length].decode("utf-8", errors="ignore"))
                                        idx += length
                                    if labels:
                                        qname = ".".join(labels)
                                        dns_res = self.analyze_dns_query(qname, src_ip, dst_ip, "A", pkt_ts)
                                        if dns_res:
                                            findings.append(dns_res)
                                except Exception:
                                    pass

        return findings
