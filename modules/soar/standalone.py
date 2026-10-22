"""SOAR Containment Playbook CLI Standalone Runner (Module X10).

Executes automated containment playbooks (network IP blocking, host quarantine,
identity suspension) with safety whitelisting guardrails and reversible rollback directives (Law 1, Law 2, Law 6).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

# Ensure workspace root is in sys.path when executed directly as a script
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from contracts.python.models import ActionContract, ActionStatus  # noqa: E402
from modules.soar.playbooks import (  # noqa: E402
    ContainmentDirective,
    SOARPlaybookEngine,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx.soar.standalone")


def run_self_test() -> bool:
    """Executes verification self-tests across all playbooks and safety guardrails."""
    print("=" * 68)
    print(" SentinelX SOAR Playbook Engine (Module X10) — Self-Test Suite")
    print("=" * 68)

    engine = SOARPlaybookEngine()
    test_incident_id = str(uuid.uuid4())
    all_passed = True

    # Test 1: Valid IP Blocking
    print("[1/7] Testing Network IP Containment (Target: 203.0.113.55)... ", end="")
    act1, dir1 = engine.execute_block_ip(
        ip="203.0.113.55",
        incident_id=test_incident_id,
        requested_by="SelfTest",
        ttl_seconds=1800,
    )
    if (
        dir1.guardrail_passed
        and act1.status == ActionStatus.COMPLETED
        and len(dir1.commands) >= 3
        and len(dir1.rollback_commands) >= 3
    ):
        print("PASS")
    else:
        print(f"FAIL (status={act1.status}, guardrail={dir1.guardrail_passed})")
        all_passed = False

    # Test 2: Whitelisted Core Gateway Protection
    print("[2/7] Testing Whitelist Guardrail: Core Gateway (192.168.1.1)... ", end="")
    act2, dir2 = engine.execute_block_ip(
        ip="192.168.1.1",
        incident_id=test_incident_id,
        requested_by="SelfTest",
    )
    if (
        not dir2.guardrail_passed
        and act2.status == ActionStatus.FAILED
        and "whitelist" in str(dir2.details.get("reason", "")).lower()
    ):
        print("PASS (Safeguard correctly prevented gateway lockout)")
    else:
        print(f"FAIL (Expected rejection, got status={act2.status})")
        all_passed = False

    # Test 3: Loopback Protection
    print("[3/7] Testing Whitelist Guardrail: Loopback (127.0.0.2)... ", end="")
    act3, dir3 = engine.execute_block_ip(
        ip="127.0.0.2",
        incident_id=test_incident_id,
        requested_by="SelfTest",
    )
    if (
        not dir3.guardrail_passed
        and act3.status == ActionStatus.FAILED
        and "loopback" in str(dir3.details.get("reason", "")).lower()
    ):
        print("PASS (Safeguard correctly prevented loopback lockout)")
    else:
        print(f"FAIL (Expected rejection, got status={act3.status}, reason={dir3.details.get('reason')})")
        all_passed = False

    # Test 4: Host Quarantine Playbook
    print("[4/7] Testing Endpoint Quarantine (Target: srv-app-01)... ", end="")
    act4, dir4 = engine.execute_isolate_host(
        hostname="srv-app-01",
        incident_id=test_incident_id,
        requested_by="SelfTest",
        allowed_ports=[8000, 22],
    )
    if (
        dir4.guardrail_passed
        and act4.status == ActionStatus.COMPLETED
        and any("8000,22" in cmd for cmd in dir4.commands)
    ):
        print("PASS (Preserved SOC management channel on ports 8000, 22)")
    else:
        print(f"FAIL (status={act4.status})")
        all_passed = False

    # Test 5: Identity Suspension Playbook
    print("[5/7] Testing Identity Revocation (Target: jdoe)... ", end="")
    act5, dir5 = engine.execute_disable_user(
        username="jdoe",
        incident_id=test_incident_id,
        requested_by="SelfTest",
    )
    if (
        dir5.guardrail_passed
        and act5.status == ActionStatus.COMPLETED
        and any("usermod -L" in cmd for cmd in dir5.commands)
    ):
        print("PASS")
    else:
        print(f"FAIL (status={act5.status})")
        all_passed = False

    # Test 6: Root Administrative Account Protection
    print("[6/7] Testing Identity Whitelist Guardrail (Target: root)... ", end="")
    act6, dir6 = engine.execute_disable_user(
        username="root",
        incident_id=test_incident_id,
        requested_by="SelfTest",
    )
    if (
        not dir6.guardrail_passed
        and act6.status == ActionStatus.FAILED
        and "whitelist" in str(dir6.details.get("reason", "")).lower()
    ):
        print("PASS (Safeguard correctly prevented root lockout)")
    else:
        print(f"FAIL (Expected rejection, got status={act6.status})")
        all_passed = False

    # Test 7: Reversible Containment Rollback Execution
    print("[7/7] Testing Reversible Containment Rollback Execution... ", end="")
    rollback_act, rollback_dir = engine.execute_rollback(act1.action_id, requested_by="SelfTest")
    if (
        rollback_dir.guardrail_passed
        and rollback_act.status == ActionStatus.COMPLETED
        and len(rollback_dir.commands) >= 3
        and rollback_dir.details.get("reverted_type") == "block_ip"
    ):
        print("PASS (Successfully generated reversal directives and contracts)")
    else:
        print(f"FAIL (status={rollback_act.status})")
        all_passed = False

    print("=" * 68)
    if all_passed:
        print("All SOAR containment playbooks & safety guardrails verified successfully.")
    else:
        print("Self-test encountered failures.")
    print("=" * 68)
    return all_passed


def forward_action_event(
    action: ActionContract,
    directive: ContainmentDirective,
    ingest_url: str,
    api_key: str,
) -> bool:
    """Forwards containment execution event to public SentinelX Ingest REST API (Law 1)."""
    import httpx

    event_payload = {
        "source_ip": "127.0.0.1",
        "event_type": "soar_containment_executed",
        "target_host": action.target,
        "event_time": directive.timestamp.isoformat(),
        "raw_payload": f"[SOAR] {action.action_type.value} on {action.target} (status: {action.status.value})",
        "details": {
            "action_id": str(action.action_id),
            "action_type": action.action_type.value,
            "incident_id": str(action.incident_id),
            "target": action.target,
            "status": action.status.value,
            "guardrail_passed": directive.guardrail_passed,
            "commands_count": len(directive.commands),
            "directive_details": directive.details,
        },
    }

    try:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        with httpx.Client(timeout=5.0) as client:
            resp = client.post(ingest_url, json=event_payload, headers=headers)
            if resp.is_success:
                logger.info("Successfully forwarded containment event to %s: HTTP %d", ingest_url, resp.status_code)
                return True
            else:
                logger.warning("Ingest API returned HTTP %d: %s", resp.status_code, resp.text)
                return False
    except Exception as exc:
        logger.error("Failed to forward containment event to %s: %s", ingest_url, exc)
        return False


def main() -> int:
    """CLI Entrypoint for SOAR Playbook Engine."""
    parser = argparse.ArgumentParser(
        description="SentinelX SOAR Playbook Engine (Module X10) — Automated & Supervised Incident Containment"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run automated self-tests across all playbooks and safety guardrails",
    )
    parser.add_argument(
        "--playbook",
        choices=["block_ip", "isolate_host", "disable_user"],
        help="Containment playbook to execute",
    )
    parser.add_argument(
        "--target",
        help="Target entity for containment (IP address, hostname, or username)",
    )
    parser.add_argument(
        "--rollback",
        metavar="ACTION_ID",
        help="Action ID of previously recorded containment directive to rollback",
    )
    parser.add_argument(
        "--incident-id",
        default=None,
        help="Correlated Incident UUID triggering this containment playbook",
    )
    parser.add_argument(
        "--ttl-seconds",
        type=int,
        default=3600,
        help="Time-to-live in seconds for temporary network IP block (default: 3600)",
    )
    parser.add_argument(
        "--allowed-ports",
        default="8000,22",
        help="Comma-separated ports to preserve during host quarantine (default: 8000,22)",
    )
    parser.add_argument(
        "--requested-by",
        default="SOAR_CLI",
        help="Operator or automated system triggering containment",
    )
    parser.add_argument(
        "--export-json",
        metavar="PATH",
        help="File path to write action result JSON (or '-' for stdout)",
    )
    parser.add_argument(
        "--forward",
        action="store_true",
        help="Forward containment action telemetry to SentinelX Ingest REST API",
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

    engine = SOARPlaybookEngine()

    action: ActionContract
    directive: ContainmentDirective

    if args.rollback:
        action, directive = engine.execute_rollback(
            action_id=args.rollback,
            requested_by=args.requested_by,
        )
    elif args.playbook and args.target:
        incident_id = args.incident_id or str(uuid.uuid4())
        if args.playbook == "block_ip":
            action, directive = engine.execute_block_ip(
                ip=args.target,
                incident_id=incident_id,
                requested_by=args.requested_by,
                ttl_seconds=args.ttl_seconds,
            )
        elif args.playbook == "isolate_host":
            ports = [int(p.strip()) for p in args.allowed_ports.split(",") if p.strip().isdigit()]
            action, directive = engine.execute_isolate_host(
                hostname=args.target,
                incident_id=incident_id,
                requested_by=args.requested_by,
                allowed_ports=ports,
            )
        elif args.playbook == "disable_user":
            action, directive = engine.execute_disable_user(
                username=args.target,
                incident_id=incident_id,
                requested_by=args.requested_by,
            )
        else:
            logger.error("Unknown playbook: %s", args.playbook)
            return 1
    else:
        parser.error("--playbook and --target, --rollback, or --self-test is required")

    output_data: dict[str, Any] = {
        "action": action.model_dump(mode="json"),
        "directive": {
            "action_id": directive.action_id,
            "action_type": directive.action_type,
            "target": directive.target,
            "commands": directive.commands,
            "rollback_commands": directive.rollback_commands,
            "guardrail_passed": directive.guardrail_passed,
            "status": directive.status,
            "details": directive.details,
            "timestamp": directive.timestamp.isoformat(),
        },
    }

    if args.export_json:
        if args.export_json == "-":
            print(json.dumps(output_data, indent=2))
        else:
            with open(args.export_json, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            logger.info("Exported containment result to %s", args.export_json)
    else:
        print("\n--- SentinelX SOAR Containment Result ---")
        print(f"Action ID:         {action.action_id}")
        print(f"Playbook:          {action.action_type.value}")
        print(f"Target:            {action.target}")
        print(f"Status:            {action.status.value}")
        print(f"Guardrail Passed:  {directive.guardrail_passed}")
        if not directive.guardrail_passed:
            print(f"Rejection Reason:  {directive.details.get('reason')}")
        else:
            print(f"Active Commands ({len(directive.commands)}):")
            for c in directive.commands:
                print(f"  $ {c}")
            print(f"Rollback Commands ({len(directive.rollback_commands)}):")
            for rc in directive.rollback_commands:
                print(f"  $ {rc}")

    if args.forward:
        forward_action_event(
            action=action,
            directive=directive,
            ingest_url=args.ingest_url,
            api_key=args.api_key,
        )

    return 0 if directive.guardrail_passed else 1


if __name__ == "__main__":
    sys.exit(main())
