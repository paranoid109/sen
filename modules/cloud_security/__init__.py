"""SentinelX Cloud Security Posture Management Module (X12)."""

from modules.cloud_security.evaluator import (
    CIS_BENCHMARK_RULES,
    CloudBenchmarkRule,
    CloudPostureReport,
    CloudProvider,
    CloudSecurityEvaluator,
)

__all__ = [
    "CloudBenchmarkRule",
    "CloudPostureReport",
    "CloudProvider",
    "CloudSecurityEvaluator",
    "CIS_BENCHMARK_RULES",
]
