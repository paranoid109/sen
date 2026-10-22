# Security Orchestration, Automation & Response (SOAR) Module (X10)

## 1. Overview
The **SOAR Playbook Engine** executes automated containment and remediation workflows in response to verified security incidents, supporting both autonomous and human-in-the-loop approval gates.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Consumes remediation action directives conforming to `contracts/actions/action_contract.json`.
* Emits completed or rejected `ActionContract` models with concrete OS/firewall commands and rollback scripts.
* Strictly decoupled from `backend/app/`; communicates via standard contracts and REST APIs (**Law 1**).
* Records all containment actions with reversible rollback instructions in the tamper-evident audit log (**Law 4**).

## 3. Supported Containment Playbooks
* **Network Isolation (`block_ip`)**:
  - Injects dynamic drop rules across multiple firewall backends (`iptables`, `nftables`, Windows `netsh advfirewall`).
  - Automatically synthesizes symmetrical, reversible rollback commands (`iptables -D`, `nft delete`, `netsh delete`).
  - Supports configurable TTL (time-to-live) for temporary containment windows.
* **Endpoint Quarantine (`isolate_host`)**:
  - Isolates compromised endpoints from lateral movement while preserving essential SOC telemetry and forensics management ports (e.g. ports `8000`, `22`).
* **Identity Suspension (`disable_user`)**:
  - Suspends local user accounts (`usermod -L`), terminates active shell/session processes (`pkill -u`), and invalidates active authentication tokens.

## 4. Safety Guardrails & Whitelisting
To prevent catastrophic accidental denial-of-service or lockouts of security analysts, the engine enforces strict pre-execution guardrails:
* **Core Infrastructure Whitelist**: Gateway (`192.168.1.1`), loopback interfaces (`127.0.0.0/8`, `::1`).
* **Root Administrative Account Protection**: Explicitly forbids disabling `root` or `sentinelx`.
* Any guardrail violation marks the action as `FAILED` with detailed diagnostic rejection reasons.

## 5. Standalone CLI Usage
```bash
# Run verification self-test suite
python modules/soar/standalone.py --self-test

# Block malicious source IP with a 1-hour TTL
python modules/soar/standalone.py --playbook block_ip --target 203.0.113.55 --ttl-seconds 3600

# Quarantine a compromised host while preserving SOC ports 8000 and 22
python modules/soar/standalone.py --playbook isolate_host --target srv-app-01 --allowed-ports 8000,22

# Suspend a compromised user identity
python modules/soar/standalone.py --playbook disable_user --target compromised_user

# Export execution result to JSON and forward telemetry to Ingestion REST API
python modules/soar/standalone.py --playbook block_ip --target 198.51.100.4 --export-json result.json --forward
```

## 6. Contract Conformance
Consumes and produces `contracts/actions/action_contract.json`:
* `action_type`: `"block_ip"`, `"isolate_host"`, `"disable_user"`, `"webhook_notification"`
* `status`: `"PENDING"` $\to$ `"COMPLETED"` / `"FAILED"`
