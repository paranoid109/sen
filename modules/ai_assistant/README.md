# AI SOC Analyst Assistant Capability Module (X13)

## 1. Overview
The AI SOC Analyst Assistant Capability Module provides an interactive, natural-language Copilot for security analysts, accelerating triage, narrative generation, and root-cause hypothesis testing.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Interacts with SentinelX strictly via read-only REST endpoints or serialized contract structures.
* Never runs dynamic code generation inside the core detection engine (prohibited by Architectural Rule A4).
* Emits recommendations, summarizations, and search query suggestions.

## 3. Core Capabilities
* **Incident Summarization**: Synthesizes multi-alert timelines into concise executive and technical debriefs.
* **Triage Recommendations**: Suggests whether an alert represents a true positive or false positive based on evidence and history.
* **Search & Filter Synthesis**: Translates natural language questions ("Show me all failed logins from external IPs yesterday") into structured REST API queries.

## 4. Contract Conformance
Consumes `contracts/incidents/incident_contract.json` and produces formatted Markdown debriefs and recommendations.
