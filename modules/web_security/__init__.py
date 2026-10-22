"""Web Security Capability Module (X1).

Pluggable security analyzer inspecting HTTP request logs and URIs for web application attacks
such as SQL Injection (CWE-89, MITRE ATT&CK T1190).
"""

from __future__ import annotations

from modules.web_security.analyzer import WebSecurityAnalyzer

__all__ = ["WebSecurityAnalyzer"]
