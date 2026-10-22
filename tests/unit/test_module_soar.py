"""Unit Tests for Module X10: SOAR Automated Containment Playbook Engine."""

from __future__ import annotations

import uuid

from contracts.python.models import ActionContract, ActionStatus, ActionType
from modules.soar.playbooks import (
    CRITICAL_IP_WHITELISTS,
    CRITICAL_USER_WHITELISTS,
    SOARPlaybookEngine,
)
from modules.soar.standalone import run_self_test


def test_soar_block_ip_success() -> None:
    """Asserts valid external IP blocking produces concrete firewall commands and rollback rules."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())
    target_ip = "198.51.100.22"

    action, directive = engine.execute_block_ip(
        ip=target_ip,
        incident_id=incident_id,
        ttl_seconds=7200,
    )

    assert isinstance(action, ActionContract)
    assert action.action_type == ActionType.BLOCK_IP
    assert action.status == ActionStatus.COMPLETED
    assert action.target == target_ip
    assert directive.guardrail_passed is True
    assert directive.status == "COMPLETED"

    # Multi-platform firewall commands verified
    assert any("iptables -I INPUT -s 198.51.100.22 -j DROP" in cmd for cmd in directive.commands)
    assert any("nft add element inet filter" in cmd for cmd in directive.commands)
    assert any("netsh advfirewall firewall add rule" in cmd for cmd in directive.commands)

    # Reversible rollback commands verified
    assert any("iptables -D INPUT -s 198.51.100.22 -j DROP" in rcmd for rcmd in directive.rollback_commands)
    assert any("netsh advfirewall firewall delete rule" in rcmd for rcmd in directive.rollback_commands)


def test_soar_block_ip_whitelist_rejection() -> None:
    """Asserts core gateway IP in whitelist triggers safety guardrail rejection."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())

    for whitelisted_ip in CRITICAL_IP_WHITELISTS:
        action, directive = engine.execute_block_ip(ip=whitelisted_ip, incident_id=incident_id)
        assert action.status == ActionStatus.FAILED
        assert directive.guardrail_passed is False
        assert "whitelist" in str(directive.details.get("reason", "")).lower()


def test_soar_block_ip_loopback_rejection() -> None:
    """Asserts loopback IP addresses (127.0.0.0/8) are rejected to prevent self-lockout."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())

    action, directive = engine.execute_block_ip(ip="127.0.0.99", incident_id=incident_id)
    assert action.status == ActionStatus.FAILED
    assert directive.guardrail_passed is False
    assert "loopback" in str(directive.details.get("reason", "")).lower()


def test_soar_block_ip_malformed_ip() -> None:
    """Asserts invalid IP format returns a rejected action without throwing uncaught exceptions."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())

    action, directive = engine.execute_block_ip(ip="not-an-ip-address", incident_id=incident_id)
    assert action.status == ActionStatus.FAILED
    assert directive.guardrail_passed is False
    assert "Invalid IP address format" in str(directive.details.get("reason", ""))


def test_soar_isolate_host_preserves_soc_channel() -> None:
    """Asserts endpoint quarantine blocks non-essential traffic while keeping ports 8000 and 22 open."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())
    hostname = "srv-payment-02"

    action, directive = engine.execute_isolate_host(
        hostname=hostname,
        incident_id=incident_id,
        allowed_ports=[8000, 22],
    )

    assert action.action_type == ActionType.ISOLATE_HOST
    assert action.status == ActionStatus.COMPLETED
    assert directive.guardrail_passed is True

    # Quarantines endpoint while preserving reporting socket
    assert any("iptables -P INPUT DROP" in cmd for cmd in directive.commands)
    assert any("--dports 8000,22 -j ACCEPT" in cmd for cmd in directive.commands)
    assert any("iptables -P INPUT ACCEPT" in rcmd for rcmd in directive.rollback_commands)


def test_soar_disable_user_success() -> None:
    """Asserts user suspension locks account, kills active sessions, and provides rollback."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())
    username = "attacker_compromised_acc"

    action, directive = engine.execute_disable_user(username=username, incident_id=incident_id)
    assert action.action_type == ActionType.DISABLE_USER
    assert action.status == ActionStatus.COMPLETED
    assert directive.guardrail_passed is True
    assert any(f"usermod -L {username}" in cmd for cmd in directive.commands)
    assert any(f"pkill -u {username}" in cmd for cmd in directive.commands)
    assert any(f"usermod -U {username}" in rcmd for rcmd in directive.rollback_commands)


def test_soar_disable_user_whitelist_rejection() -> None:
    """Asserts critical administrative accounts (root, sentinelx) are protected by safety guardrail."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())

    for admin_user in CRITICAL_USER_WHITELISTS:
        action, directive = engine.execute_disable_user(username=admin_user, incident_id=incident_id)
        assert action.status == ActionStatus.FAILED
        assert directive.guardrail_passed is False
        assert "whitelist" in str(directive.details.get("reason", "")).lower()


def test_soar_execute_rollback_success_and_missing() -> None:
    """Asserts execute_rollback reverses previously executed containment action."""
    engine = SOARPlaybookEngine()
    incident_id = str(uuid.uuid4())

    # 1. Execute initial IP block
    act_orig, dir_orig = engine.execute_block_ip(ip="198.51.100.99", incident_id=incident_id)
    assert act_orig.status == ActionStatus.COMPLETED

    # 2. Execute rollback
    act_rb, dir_rb = engine.execute_rollback(action_id=act_orig.action_id)
    assert act_rb.status == ActionStatus.COMPLETED
    assert dir_rb.status == "COMPLETED"
    assert dir_rb.action_type == "rollback_block_ip"
    assert any("iptables -D INPUT -s 198.51.100.99 -j DROP" in cmd for cmd in dir_rb.commands)

    # 3. Non-existent action returns FAILED
    act_bad, dir_bad = engine.execute_rollback(action_id=uuid.uuid4())
    assert act_bad.status == ActionStatus.FAILED
    assert dir_bad.guardrail_passed is False


def test_soar_standalone_self_test() -> None:
    """Asserts standalone runner self-test passes cleanly."""
    assert run_self_test() is True
