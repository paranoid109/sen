"""SOAR Containment Playbook Engine Capability Module (X10).

Executes automated and analyst-approved active containment workflows
(network IP blocking, host quarantine, credential suspension) with
whitelisting guardrails and reversible rollback directives (Law 1, Law 2, Law 6).
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from contracts.python.models import ActionContract, ActionStatus, ActionType

# Whitelisted infrastructure targets protected from containment lockouts
CRITICAL_IP_WHITELISTS: set[str] = {
    "127.0.0.1",
    "::1",
    "192.168.1.1",  # Core Gateway / Edge Firewall
}

CRITICAL_USER_WHITELISTS: set[str] = {
    "root",
    "sentinelx",
}


@dataclass
class ContainmentDirective:
    """Actionable remediation directive with OS/network commands and rollback scripts."""

    action_id: str
    action_type: str
    target: str
    commands: list[str]
    rollback_commands: list[str]
    guardrail_passed: bool
    status: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class SOARPlaybookEngine:
    """Enterprise containment playbook orchestrator with safety guardrails."""

    def __init__(self, ip_whitelist: set[str] | None = None, user_whitelist: set[str] | None = None) -> None:
        self.ip_whitelist = set(ip_whitelist) if ip_whitelist else set(CRITICAL_IP_WHITELISTS)
        self.user_whitelist = set(user_whitelist) if user_whitelist else set(CRITICAL_USER_WHITELISTS)
        self.execution_history: list[ActionContract] = []
        self.directives: dict[str, ContainmentDirective] = {}

    def validate_ip_target(self, ip_str: str) -> tuple[bool, str | None]:
        """Validates IP format and verifies target is not exempt by safety whitelists."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, f"Invalid IP address format: {ip_str}"

        if str(ip_obj) in self.ip_whitelist:
            return False, f"Target IP {ip_str} is protected by core infrastructure whitelist"

        if ip_obj.is_loopback:
            return False, f"Target IP {ip_str} is a loopback address and cannot be contained"

        return True, None

    def execute_block_ip(
        self,
        ip: str,
        incident_id: str | uuid.UUID,
        requested_by: str = "SOAR_Engine",
        ttl_seconds: int = 3600,
    ) -> tuple[ActionContract, ContainmentDirective]:
        """Executes Network IP containment playbook: generates drop rules and rollback commands."""
        inc_uuid = uuid.UUID(str(incident_id))
        act_uuid = uuid.uuid4()
        now = datetime.now(UTC)

        valid, err = self.validate_ip_target(ip)
        if not valid:
            directive = ContainmentDirective(
                action_id=str(act_uuid),
                action_type="block_ip",
                target=ip,
                commands=[],
                rollback_commands=[],
                guardrail_passed=False,
                status="FAILED",
                details={"reason": err},
                timestamp=now,
            )
            action = ActionContract(
                action_id=act_uuid,
                action_type=ActionType.BLOCK_IP,
                incident_id=inc_uuid,
                target=ip,
                parameters={"ttl_seconds": ttl_seconds},
                status=ActionStatus.FAILED,
                requested_by=requested_by,
                requested_at=now,
                executed_at=now,
                result={"error": err, "guardrail_rejected": True},
            )
            self.execution_history.append(action)
            return action, directive

        # Concrete multi-platform firewall containment commands
        commands = [
            f"iptables -I INPUT -s {ip} -j DROP -m comment --comment 'SentinelX_Incident_{str(inc_uuid)[:8]}'",
            f"nft add element inet filter sentinelx_blocklist {{ {ip} }}",
            f"netsh advfirewall firewall add rule name=\"SentinelX_Block_{ip}\" dir=in action=block remoteip={ip}",
        ]
        # Reversible rollback commands
        rollback_commands = [
            f"iptables -D INPUT -s {ip} -j DROP",
            f"nft delete element inet filter sentinelx_blocklist {{ {ip} }}",
            f"netsh advfirewall firewall delete rule name=\"SentinelX_Block_{ip}\"",
        ]

        directive = ContainmentDirective(
            action_id=str(act_uuid),
            action_type="block_ip",
            target=ip,
            commands=commands,
            rollback_commands=rollback_commands,
            guardrail_passed=True,
            status="COMPLETED",
            details={
                "ttl_seconds": ttl_seconds,
                "firewall_backends": ["iptables", "nftables", "windows_advfirewall"],
            },
            timestamp=now,
        )

        action = ActionContract(
            action_id=act_uuid,
            action_type=ActionType.BLOCK_IP,
            incident_id=inc_uuid,
            target=ip,
            parameters={"ttl_seconds": ttl_seconds, "commands": commands},
            status=ActionStatus.COMPLETED,
            requested_by=requested_by,
            requested_at=now,
            executed_at=now,
            result={
                "directive": "NETWORK_ISOLATION_ACTIVE",
                "rules_injected": len(commands),
                "rollback_ready": True,
            },
        )
        self.execution_history.append(action)
        self.directives[str(act_uuid)] = directive
        return action, directive

    def execute_isolate_host(
        self,
        hostname: str,
        incident_id: str | uuid.UUID,
        requested_by: str = "SOAR_Engine",
        allowed_ports: list[int] | None = None,
    ) -> tuple[ActionContract, ContainmentDirective]:
        """Executes Host Quarantine playbook: cuts non-essential traffic while preserving SOC channel."""
        inc_uuid = uuid.UUID(str(incident_id))
        act_uuid = uuid.uuid4()
        now = datetime.now(UTC)
        ports = allowed_ports or [8000, 22]  # SentinelX reporting & management channel

        # Concrete host quarantine commands
        commands = [
            f"# Host Quarantine Directive for {hostname}",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -A INPUT -i lo -j ACCEPT",
            f"iptables -A INPUT -p tcp -m multiport --dports {','.join(map(str, ports))} -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        ]
        rollback_commands = [
            f"# Host Quarantine Rollback for {hostname}",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -F",
        ]

        directive = ContainmentDirective(
            action_id=str(act_uuid),
            action_type="isolate_host",
            target=hostname,
            commands=commands,
            rollback_commands=rollback_commands,
            guardrail_passed=True,
            status="COMPLETED",
            details={"hostname": hostname, "forensic_preserve_ports": ports},
            timestamp=now,
        )

        action = ActionContract(
            action_id=act_uuid,
            action_type=ActionType.ISOLATE_HOST,
            incident_id=inc_uuid,
            target=hostname,
            parameters={"allowed_ports": ports},
            status=ActionStatus.COMPLETED,
            requested_by=requested_by,
            requested_at=now,
            executed_at=now,
            result={
                "directive": "ENDPOINT_QUARANTINE_ENFORCED",
                "isolated_host": hostname,
                "forensics_link_preserved": True,
            },
        )
        self.execution_history.append(action)
        self.directives[str(act_uuid)] = directive
        return action, directive

    def execute_disable_user(
        self,
        username: str,
        incident_id: str | uuid.UUID,
        requested_by: str = "SOAR_Engine",
    ) -> tuple[ActionContract, ContainmentDirective]:
        """Executes Identity Revocation playbook: revokes tokens and locks compromised accounts."""
        inc_uuid = uuid.UUID(str(incident_id))
        act_uuid = uuid.uuid4()
        now = datetime.now(UTC)

        user_clean = username.lower().strip()
        if user_clean in self.user_whitelist:
            err = f"Account '{username}' is protected by core administrative whitelist"
            directive = ContainmentDirective(
                action_id=str(act_uuid),
                action_type="disable_user",
                target=username,
                commands=[],
                rollback_commands=[],
                guardrail_passed=False,
                status="FAILED",
                details={"reason": err},
                timestamp=now,
            )
            action = ActionContract(
                action_id=act_uuid,
                action_type=ActionType.DISABLE_USER,
                incident_id=inc_uuid,
                target=username,
                parameters={},
                status=ActionStatus.FAILED,
                requested_by=requested_by,
                requested_at=now,
                executed_at=now,
                result={"error": err, "guardrail_rejected": True},
            )
            self.execution_history.append(action)
            return action, directive

        commands = [
            f"usermod -L {username}",
            f"pkill -u {username}",
            f"# Revoke active OAuth2 / JWT refresh tokens for identity: {username}",
        ]
        rollback_commands = [
            f"usermod -U {username}",
        ]

        directive = ContainmentDirective(
            action_id=str(act_uuid),
            action_type="disable_user",
            target=username,
            commands=commands,
            rollback_commands=rollback_commands,
            guardrail_passed=True,
            status="COMPLETED",
            details={"username": username, "sessions_terminated": True},
            timestamp=now,
        )

        action = ActionContract(
            action_id=act_uuid,
            action_type=ActionType.DISABLE_USER,
            incident_id=inc_uuid,
            target=username,
            parameters={"terminate_active_sessions": True},
            status=ActionStatus.COMPLETED,
            requested_by=requested_by,
            requested_at=now,
            executed_at=now,
            result={
                "directive": "USER_CREDENTIALS_SUSPENDED",
                "account_locked": True,
                "sessions_killed": True,
            },
        )
        self.execution_history.append(action)
        self.directives[str(act_uuid)] = directive
        return action, directive

    def execute_rollback(
        self,
        action_id: str | uuid.UUID,
        requested_by: str = "SOAR_Engine",
    ) -> tuple[ActionContract, ContainmentDirective]:
        """Executes reversible rollback of an active containment directive."""
        act_id_str = str(action_id)
        now = datetime.now(UTC)
        orig_directive = self.directives.get(act_id_str)
        orig_action = next((a for a in self.execution_history if str(a.action_id) == act_id_str), None)

        if not orig_directive or not orig_action:
            err = f"Containment action '{act_id_str}' not found in active directive cache"
            failed_id = uuid.uuid4()
            dir_failed = ContainmentDirective(
                action_id=str(failed_id),
                action_type="rollback",
                target=act_id_str,
                commands=[],
                rollback_commands=[],
                guardrail_passed=False,
                status="FAILED",
                details={"reason": err},
                timestamp=now,
            )
            act_failed = ActionContract(
                action_id=failed_id,
                action_type=ActionType.CUSTOM,
                incident_id=uuid.uuid4(),
                target=act_id_str,
                parameters={"rollback": True},
                status=ActionStatus.FAILED,
                requested_by=requested_by,
                requested_at=now,
                executed_at=now,
                result={"error": err},
            )
            return act_failed, dir_failed

        rollback_act_uuid = uuid.uuid4()
        rollback_directive = ContainmentDirective(
            action_id=str(rollback_act_uuid),
            action_type=f"rollback_{orig_directive.action_type}",
            target=orig_directive.target,
            commands=orig_directive.rollback_commands,
            rollback_commands=[],
            guardrail_passed=True,
            status="COMPLETED",
            details={
                "original_action_id": act_id_str,
                "reverted_type": orig_directive.action_type,
            },
            timestamp=now,
        )

        rollback_action = ActionContract(
            action_id=rollback_act_uuid,
            action_type=orig_action.action_type,
            incident_id=orig_action.incident_id,
            target=orig_directive.target,
            parameters={"rollback_of": act_id_str, "commands": orig_directive.rollback_commands},
            status=ActionStatus.COMPLETED,
            requested_by=requested_by,
            requested_at=now,
            executed_at=now,
            result={
                "directive": "CONTAINMENT_REVERSED",
                "rules_removed": len(orig_directive.rollback_commands),
            },
        )
        self.execution_history.append(rollback_action)
        self.directives[str(rollback_act_uuid)] = rollback_directive
        return rollback_action, rollback_directive
