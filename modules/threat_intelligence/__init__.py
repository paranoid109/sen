"""SentinelX Threat Intelligence Capability Module (X5).

Provides STIX 2.1, MISP, and CSV indicator of compromise (IOC) ingestion,
TTL-based indicator lifecycle aging, and real-time telemetry enrichment.
"""

from modules.threat_intelligence.analyzer import ThreatIntelligenceEngine

__all__ = ["ThreatIntelligenceEngine"]
