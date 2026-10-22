"""SentinelX Platform End-to-End Verification & Demonstration Validation Script.

Simulates automated full-platform testing across all 7 delivered phases (M1-M7, X1-X13).
Validates authentication, RBAC boundaries, assets, reports, cryptographic audit chain,
detection rules, SOAR playbooks, forensics packages, CSPM checks, and AI Copilot services.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from modules.ai_assistant.standalone import run_self_test as run_x13_self_test
from modules.cloud_security.standalone import run_self_test as run_x12_self_test
from modules.correlation.standalone import run_self_test as run_x6_self_test
from modules.endpoint_security.standalone import run_self_test as run_x3_self_test
from modules.forensics.standalone import run_self_test as run_x11_self_test
from modules.knowledge_graph.standalone import run_self_test as run_x8_self_test
from modules.ml_detection.standalone import run_self_test as run_x9_self_test
from modules.network_security.standalone import run_self_test as run_x2_self_test
from modules.risk_engine.standalone import run_self_test as run_x7_self_test
from modules.soar.standalone import run_self_test as run_x10_self_test
from modules.threat_intelligence.standalone import run_self_test as run_x5_self_test
from modules.vulnerability_management.standalone import run_self_test as run_x4_self_test
from modules.web_security.standalone import run_self_test as run_x1_self_test

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinelx.verify_e2e")

BASE_URL = "http://localhost:8000"


def print_step(title: str):
    print("\n" + "=" * 80)
    print(f" >>> {title}")
    print("=" * 80)


def verify_api_live() -> bool:
    print_step("Step 1: Live Container Healthcheck")
    with httpx.Client(timeout=5.0) as client:
        r = client.get(f"{BASE_URL}/health")
        assert r.status_code == 200, f"Expected 200 from /health, got {r.status_code}"
        data = r.json()
        print(f"[+] Service Health: {data.get('status')} | Version: {data.get('version')} | Env: {data.get('env')}")
        return True


def verify_authentication_and_rbac() -> dict[str, str]:
    print_step("Step 2: Authentication & RBAC Governance (M1)")
    tokens: dict[str, str] = {}
    users = [
        ("admin", "Admin123!Secure", "Admin"),
        ("analyst", "Analyst123!Secure", "Analyst"),
        ("auditor", "Auditor123!Secure", "Auditor"),
    ]

    with httpx.Client(timeout=5.0) as client:
        for username, password, expected_role in users:
            r = client.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={"username": username, "password": password},
            )
            assert r.status_code == 200, f"Failed login for {username}: {r.status_code} {r.text}"
            body = r.json()
            tokens[username] = body["access_token"]
            assert body["role"] == expected_role, f"Expected role {expected_role}, got {body['role']}"
            print(f"[+] Login Verified: user={username} | role={body['role']} | token_issued=True")

        # Test RBAC boundary: Analyst trying to access Admin API keys
        r_analyst = client.get(
            f"{BASE_URL}/api/v1/auth/api-keys",
            headers={"Authorization": f"Bearer {tokens['analyst']}"},
        )
        assert r_analyst.status_code == 403, f"Expected 403 Forbidden for Analyst on /auth/api-keys, got {r_analyst.status_code}"
        print("[+] RBAC Guard Verified: Analyst forbidden from Admin API Key management (HTTP 403).")

        # Test RBAC boundary: Admin accessing API keys
        r_admin = client.get(
            f"{BASE_URL}/api/v1/auth/api-keys",
            headers={"Authorization": f"Bearer {tokens['admin']}"},
        )
        assert r_admin.status_code == 200, f"Admin failed to access /auth/api-keys: {r_admin.status_code}"
        print(f"[+] RBAC Guard Verified: Admin access granted to API Keys ({len(r_admin.json())} keys retrieved).")

    return tokens


def verify_assets_and_topology(admin_token: str):
    print_step("Step 3: CMDB Asset Inventory & Topology Context (M2, X8)")
    headers = {"Authorization": f"Bearer {admin_token}"}
    with httpx.Client(timeout=5.0) as client:
        r = client.get(f"{BASE_URL}/api/v1/assets", headers=headers)
        assert r.status_code == 200, f"Failed fetching assets: {r.status_code}"
        assets = r.json()
        print(f"[+] Retrieved {len(assets)} CMDB monitored assets.")
        hostnames = [a.get("hostname") for a in assets]
        assert "server-prod-01" in hostnames, "Missing server-prod-01"
        assert "db-prod-01" in hostnames, "Missing db-prod-01"
        for a in assets:
            print(f"    - Asset: {a.get('hostname'):<18} | IP: {a.get('ip_address'):<15} | Criticality: {a.get('criticality').upper()}")


def verify_reports_and_mttd(admin_token: str):
    print_step("Step 4: Operational Metrics & Executive Reporting (M7)")
    headers = {"Authorization": f"Bearer {admin_token}"}
    with httpx.Client(timeout=5.0) as client:
        r_metrics = client.get(f"{BASE_URL}/api/v1/reports/metrics", headers=headers)
        assert r_metrics.status_code == 200
        m = r_metrics.json()
        print(f"[+] Operational KPI Metrics: Total Events={m.get('total_events')}, Active Alerts={m.get('active_alerts')}, Open Incidents={m.get('open_incidents')}, Assets={m.get('monitored_assets')}")
        mttd = m.get("mttd_seconds")
        print(f"[+] Mean Time to Detect (MTTD): {mttd if mttd is not None else 'N/A'} seconds")

        r_report = client.get(f"{BASE_URL}/api/v1/reports/executive", headers=headers)
        assert r_report.status_code == 200
        rep = r_report.json()
        markdown = rep.get("report_markdown", "")
        assert len(markdown) > 100
        assert "SentinelX Executive Security Summary Debrief" in markdown
        print(f"[+] Generated Executive Report Markdown ({len(markdown)} characters).")


def verify_tamper_evident_audit_chain(auditor_token: str):
    print_step("Step 5: Cryptographic Audit Trail Verification (Law 4)")
    headers = {"Authorization": f"Bearer {auditor_token}"}
    with httpx.Client(timeout=5.0) as client:
        r_verify = client.get(f"{BASE_URL}/api/v1/audit/verify", headers=headers)
        assert r_verify.status_code == 200
        v = r_verify.json()
        assert v.get("is_valid") is True, f"Audit hash chain broken! {v}"
        print(f"[+] Cryptographic SHA-256 Hash Chain Integrity: VERIFIED (Total Records: {v.get('total_records')})")

        r_logs = client.get(f"{BASE_URL}/api/v1/audit?limit=5", headers=headers)
        assert r_logs.status_code == 200
        logs = r_logs.json()
        print(f"[+] Sampled {len(logs)} recent audit ledger entries:")
        for entry in logs[:3]:
            print(f"    - Seq #{entry.get('sequence_number')}: {entry.get('action'):<18} | Status: {entry.get('status')} | Hash: {entry.get('entry_hash')[:16]}...")


def verify_capability_modules_self_tests():
    print_step("Step 6: Pluggable Capability Modules Autonomous Self-Tests (X1-X13)")
    print("[*] Running X1 Web Security Self-Test...")
    assert run_x1_self_test() == 0, "X1 Web Security self-test failed"

    print("[*] Running X2 Network Security Self-Test...")
    assert run_x2_self_test() == 0, "X2 Network Security self-test failed"

    print("[*] Running X3 Endpoint Security Self-Test...")
    assert run_x3_self_test() == 0, "X3 Endpoint Security self-test failed"

    print("[*] Running X4 Vulnerability Management Self-Test...")
    assert run_x4_self_test() == 0, "X4 Vulnerability Management self-test failed"

    print("[*] Running X5 Threat Intelligence Self-Test...")
    assert run_x5_self_test() == 0, "X5 Threat Intelligence self-test failed"

    print("[*] Running X6 Alert Correlation Self-Test...")
    assert run_x6_self_test() == 0, "X6 Correlation self-test failed"

    print("[*] Running X7 Risk Engine Self-Test...")
    assert run_x7_self_test() == 0, "X7 Risk Engine self-test failed"

    print("[*] Running X8 Knowledge Graph Self-Test...")
    assert run_x8_self_test() == 0, "X8 Knowledge Graph self-test failed"

    print("[*] Running X9 ML Anomaly Detection Self-Test...")
    assert run_x9_self_test() == 0, "X9 ML Anomaly Detection self-test failed"

    print("[*] Running X10 SOAR Playbooks Self-Test...")
    assert run_x10_self_test() is True, "X10 SOAR self-test failed"

    print("[*] Running X11 Digital Forensics Self-Test...")
    assert run_x11_self_test() is True, "X11 Forensics self-test failed"

    print("[*] Running X12 Cloud Security (CSPM) Self-Test...")
    assert run_x12_self_test() is True, "X12 CSPM self-test failed"

    print("[*] Running X13 AI SOC Analyst Assistant Self-Test...")
    assert run_x13_self_test() is True, "X13 AI Assistant self-test failed"
    print("[+] All 13 capability module self-tests PASSED (100%).")


def main() -> int:
    print("\n" + "#" * 80)
    print(" SENTINELX FULL-PLATFORM END-TO-END VERIFICATION & PRE-DEMO AUDIT")
    print("#" * 80)

    try:
        verify_api_live()
        tokens = verify_authentication_and_rbac()
        verify_assets_and_topology(tokens["admin"])
        verify_reports_and_mttd(tokens["admin"])
        verify_tamper_evident_audit_chain(tokens["auditor"])
        verify_capability_modules_self_tests()

        print("\n" + "=" * 80)
        print(" [SUMMARY] ALL PLATFORM INTEGRATION CHECKS PASSED WITH ZERO DISCREPANCIES!")
        print(" SentinelX is 100% verified and ready for live demonstration (Option A).")
        print("=" * 80 + "\n")
        return 0
    except Exception as exc:
        print(f"\n[!] Verification FAILED with error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
