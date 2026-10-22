# Dynamic Risk Engine Capability Module (X9)

## 1. Overview
The Dynamic Risk Engine provides multi-factor quantitative risk scoring for security incidents, assets, and overall organizational security posture. It operates as an advanced algorithmic module incorporating asset criticality, threat velocity, CISA KEV exploitability, and topological blast radius exposure.

## 2. Decoupled Architecture (Law 1, Law 2, Law 6)
* Strictly decoupled from `backend/app/` (Law 1).
* Cross-module findings adhere strictly to `contracts/python/models.py` (`FindingContract`) (Law 2).
* Evaluates context from CMDB assets (`M2`), active alerts (`M5`), and threat intelligence (`X5`).
* Computes deterministic, bounded risk metrics $[0, 100]$ without mutating core database tables directly.
* Standalone-first verification supported via `--self-test` CLI and unit tests (Law 6).

## 3. Quantitative Scoring Dimensions & Formula
The composite risk score is evaluated as:
$$\text{RiskScore} = \min\left(100, \left\lfloor (S_{\text{base}} \times M_{\text{crit}}) + V_{\text{threat}} + E_{\text{exploit}} + B_{\text{blast}} \right\rceil\right)$$

Where:
* **Base Severity ($S_{\text{base}}$)**: Critical (35), High (25), Medium (15), Low (5).
* **Asset Criticality Multiplier ($M_{\text{crit}}$)**:
  - Critical: $2.0\times$
  - High: $1.5\times$
  - Medium: $1.0\times$
  - Low: $0.8\times$
* **Threat Velocity ($V_{\text{threat}}$)**: $\min(20, \max(0, (\text{alert\_count} - 1) \times 3.0))$
* **Exploitability & Exposure ($E_{\text{exploit}}$)**:
  - CISA KEV active exploitation or $\text{CVSS} \ge 9.0$: $+25.0$
  - $\text{CVSS} \ge 7.0$: $+15.0$
  - Otherwise: $0.0$
* **Topological Blast Radius ($B_{\text{blast}}$)**:
  - Crown Jewel lateral exposure: $+20.0$
  - Reachable network nodes: $\min(15.0, \text{reachable\_nodes} \times 2.5)$

## 4. Risk Tiers
* **Critical**: $\text{RiskScore} \ge 80$
* **High**: $60 \le \text{RiskScore} < 80$
* **Medium**: $35 \le \text{RiskScore} < 60$
* **Low**: $\text{RiskScore} < 35$

## 5. Standalone CLI Usage

```bash
# Run built-in validation test suite
python -m modules.risk_engine.standalone --self-test

# Evaluate specific asset risk scenario
python -m modules.risk_engine.standalone \
  --asset-id server-prod-01 \
  --criticality high \
  --severity high \
  --alert-count 4 \
  --cisa-kev \
  --blast-nodes 2
```

## 6. Contract Conformance
Emits `FindingContract`:
* `rule_id`: `RULE-RISK-DYNAMIC-ESCALATION`
* `mitre_attack_id`: `T1190` (Exploit Public-Facing Application) if CISA KEV present, else `T1071` (Application Layer Protocol).
