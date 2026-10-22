"""SentinelX Endpoint Security Capability Module (X3).

Provides host-based process execution monitoring, LOLBAS detection,
and File Integrity Monitoring (FIM) with baseline persistence.
"""

from modules.endpoint_security.analyzer import EndpointSecurityAnalyzer

__all__ = ["EndpointSecurityAnalyzer"]
