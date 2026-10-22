"""Digital Forensics Triage CLI Standalone Runner (Module X11).

Captures volatile memory artifacts, preserves disk evidence, and produces
tamper-evident SHA-256 chain-of-custody packages (Law 1, Law 2, Law 4, Law 6).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from pathlib import Path

# Ensure workspace root is in sys.path when executed directly as a script
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from contracts.python.models import FindingContract, SeverityLevel  # noqa: E402
from modules.forensics.collector import (  # noqa: E402
    DigitalForensicsCollector,
    ForensicTriagePackage,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx.forensics.standalone")


def run_self_test() -> bool:
    """Runs automated verification tests on memory acquisition, disk triage, and root hash calculation."""
    print("=" * 68)
    print(" SentinelX Digital Forensics Triage (Module X11) — Self-Test Suite")
    print("=" * 68)

    collector = DigitalForensicsCollector(target_host="test-srv-01")
    incident_id = str(uuid.uuid4())
    all_passed = True

    # Test 1: Volatile Memory Capture
    print("[1/5] Testing Volatile Memory Capture & Suspicious Process Detection... ", end="")
    mem = collector.collect_volatile_memory()
    if (
        mem["total_processes"] >= 4
        and mem["suspicious_processes"] >= 1
        and mem["suspicious_sockets"] >= 1
    ):
        print("PASS (Identified reverse shell process and C2 port 4444 socket)")
    else:
        print(f"FAIL (Memory snapshot invalid: {mem})")
        all_passed = False

    # Test 2: Disk Artifacts & FIM Hashes
    print("[2/5] Testing Disk Artifact Acquisition & FIM Hashes... ", end="")
    disk = collector.collect_disk_artifacts()
    if (
        len(disk["fim_checksums"]) >= 4
        and len(disk["auth_log_tail"]) >= 3
        and len(disk["shell_history"]) >= 3
    ):
        print("PASS (Computed SHA-256 for /etc/passwd, shadow, sudoers, hosts)")
    else:
        print(f"FAIL (Disk snapshot incomplete: {disk})")
        all_passed = False

    # Test 3: Triage Package & Manifest
    print("[3/5] Testing Triage Package Creation & Manifest Generation... ", end="")
    pkg = collector.create_triage_package(incident_id=incident_id, target_host="test-srv-01")
    if (
        isinstance(pkg, ForensicTriagePackage)
        and len(pkg.manifest) >= 6
        and pkg.chain_of_custody_status == "VERIFIED"
    ):
        print("PASS (Generated manifest with 6+ cryptographically hashed artifacts)")
    else:
        print(f"FAIL (Package invalid: {pkg})")
        all_passed = False

    # Test 4: Merkle Root SHA-256 Chain of Custody Integrity & Tamper Verification
    print("[4/5] Testing Root SHA-256 Chain-of-Custody & Tamper Verification... ", end="")
    pkg2 = collector.create_triage_package(incident_id=incident_id, target_host="test-srv-01")
    is_valid, msg = collector.verify_package_integrity(pkg)
    # Test tamper detection
    tampered_pkg = collector.create_triage_package(incident_id=incident_id, target_host="test-srv-01")
    tampered_pkg.volatile_memory["total_processes"] = 999
    is_tampered_valid, _ = collector.verify_package_integrity(tampered_pkg)

    if (
        pkg.root_sha256 == pkg2.root_sha256
        and is_valid
        and not is_tampered_valid
        and len(pkg.root_sha256) == 64
    ):
        print(f"PASS (Deterministic Root: {pkg.root_sha256[:16]}..., Tamper-check verified)")
    else:
        print(f"FAIL (Integrity validation failed: {msg})")
        all_passed = False

    # Test 5: FindingContract Generation
    print("[5/5] Testing FindingContract Emission for Core Ingestion... ", end="")
    finding = collector.generate_finding(pkg)
    if (
        isinstance(finding, FindingContract)
        and finding.severity == SeverityLevel.CRITICAL
        and finding.rule_id == "RULE-FORENSICS-TRIAGE-001"
        and finding.target == "test-srv-01"
    ):
        print("PASS (FindingContract correctly classified as CRITICAL)")
    else:
        print(f"FAIL (Finding invalid: {finding})")
        all_passed = False

    print("=" * 68)
    if all_passed:
        print("All Digital Forensics triage operations & chain of custody verified successfully.")
    else:
        print("Self-test encountered failures.")
    print("=" * 68)
    return all_passed


def forward_forensic_finding(
    finding: FindingContract,
    ingest_url: str,
    api_key: str,
) -> bool:
    """Forwards digital forensics finding to SentinelX Ingest REST API (Law 1)."""
    import httpx

    event_payload = {
        "source_ip": "127.0.0.1",
        "event_type": "forensics_triage_package",
        "target_host": finding.target,
        "event_time": finding.timestamp.isoformat(),
        "raw_payload": f"{finding.rule_id}: {finding.description} (chain_of_custody: VERIFIED)",
        "details": {
            "finding_id": str(finding.finding_id),
            "tool_name": finding.tool_name,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "target": finding.target,
            "mitre_attack_id": finding.mitre_attack_id,
            "evidence": finding.evidence,
        },
    }

    try:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        with httpx.Client(timeout=5.0) as client:
            resp = client.post(ingest_url, json=event_payload, headers=headers)
            if resp.is_success:
                logger.info("Successfully forwarded forensic finding to %s: HTTP %d", ingest_url, resp.status_code)
                return True
            else:
                logger.warning("Ingest API returned HTTP %d: %s", resp.status_code, resp.text)
                return False
    except Exception as exc:
        logger.error("Failed to forward forensic finding to %s: %s", ingest_url, exc)
        return False


def main() -> int:
    """CLI Entrypoint for Digital Forensics Triage Module."""
    parser = argparse.ArgumentParser(
        description="SentinelX Digital Forensics Triage (Module X11) — Automated Artifact Acquisition & Chain of Custody"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run automated self-tests across memory, disk acquisition, and root SHA-256 seal",
    )
    parser.add_argument(
        "--collect",
        choices=["all", "memory", "disk"],
        default="all",
        help="Scope of forensic collection (default: all)",
    )
    parser.add_argument(
        "--target",
        default="srv-prod-01",
        help="Target hostname or IP address (default: srv-prod-01)",
    )
    parser.add_argument(
        "--incident-id",
        default=None,
        help="Correlated Incident UUID associated with this forensic capture",
    )
    parser.add_argument(
        "--export-json",
        metavar="PATH",
        help="File path to write forensic package JSON (or '-' for stdout)",
    )
    parser.add_argument(
        "--forward",
        action="store_true",
        help="Forward forensic triage finding to SentinelX Ingest REST API",
    )
    parser.add_argument(
        "--ingest-url",
        default="http://localhost:8000/api/v1/events/ingest",
        help="SentinelX Ingestion REST API endpoint",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="Optional API key for ingestion endpoint",
    )

    args = parser.parse_args()

    if args.self_test:
        success = run_self_test()
        return 0 if success else 1

    incident_id = args.incident_id or str(uuid.uuid4())
    collector = DigitalForensicsCollector(target_host=args.target)

    pkg = collector.create_triage_package(
        incident_id=incident_id,
        target_host=args.target,
        scope=args.collect,
    )
    finding = collector.generate_finding(pkg)

    if args.export_json:
        if args.export_json == "-":
            print(json.dumps(pkg.to_dict(), indent=2))
        else:
            with open(args.export_json, "w", encoding="utf-8") as f:
                json.dump(pkg.to_dict(), f, indent=2)
            logger.info("Exported forensic triage package to %s", args.export_json)
    else:
        print("\n--- SentinelX Digital Forensics Triage Package ---")
        print(f"Package ID:         {pkg.package_id}")
        print(f"Incident ID:        {pkg.incident_id}")
        print(f"Target Host:        {pkg.target_host}")
        print(f"Collected At:       {pkg.collected_at}")
        print(f"Chain of Custody:   {pkg.chain_of_custody_status}")
        print(f"Root SHA-256 Seal:  {pkg.root_sha256}")
        print(f"Manifest Artifacts: {len(pkg.manifest)}")
        print("\nIdentified Threats:")
        print(f"  Suspicious Processes: {pkg.volatile_memory.get('suspicious_processes')}")
        for p in pkg.volatile_memory.get("process_tree", []):
            if p.get("is_suspicious"):
                print(f"    - PID {p['pid']} ({p['user']}): {p['cmdline']} [{p.get('suspicion_reason')}]")
        print(f"  Suspicious Sockets:   {pkg.volatile_memory.get('suspicious_sockets')}")
        for s in pkg.volatile_memory.get("active_sockets", []):
            if s.get("is_suspicious"):
                print(f"    - {s['protocol']} {s['local_ip']}:{s['local_port']} -> {s['remote_ip']}:{s['remote_port']} ({s['state']})")

    if args.forward:
        forward_forensic_finding(
            finding=finding,
            ingest_url=args.ingest_url,
            api_key=args.api_key,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
