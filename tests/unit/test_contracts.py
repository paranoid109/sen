"""Unit tests for SentinelX contracts and schema parity.

Verifies:
1. All 5 JSON schemas conform to Draft-07.
2. Pydantic v2 models validate realistic payloads and produce exact JSON Schema compliant outputs.
3. Every schema property exists in the corresponding Pydantic model with strict parity.
4. Schema violations (missing required fields, out-of-range bounds, unknown enum values, extra properties)
   fail validation in both Pydantic and JSON Schema.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from jsonschema import Draft7Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from contracts.python.models import (
    ActionContract,
    ActionStatus,
    ActionType,
    AlertContract,
    AlertStatus,
    EventContract,
    FindingContract,
    IncidentContract,
    IncidentStatus,
    SeverityLevel,
    TimelineItem,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTRACTS_DIR = REPO_ROOT / "contracts"


def load_json_schema(relative_path: str) -> dict[str, Any]:
    schema_path = CONTRACTS_DIR / relative_path
    assert schema_path.exists(), f"Schema file not found: {schema_path}"
    with open(schema_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def event_schema() -> dict[str, Any]:
    return load_json_schema("events/event_contract.json")


@pytest.fixture
def finding_schema() -> dict[str, Any]:
    return load_json_schema("findings/finding_contract.json")


@pytest.fixture
def alert_schema() -> dict[str, Any]:
    return load_json_schema("alerts/alert_contract.json")


@pytest.fixture
def incident_schema() -> dict[str, Any]:
    return load_json_schema("incidents/incident_contract.json")


@pytest.fixture
def action_schema() -> dict[str, Any]:
    return load_json_schema("actions/action_contract.json")


@pytest.fixture
def valid_event_data() -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "source_port": 54321,
        "event_type": "auth_failed",
        "target_host": "server-prod-01",
        "target_asset_id": str(uuid.uuid4()),
        "event_time": "2026-10-07T12:00:00Z",
        "ingest_time": "2026-10-07T12:00:01Z",
        "raw_payload": "Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
        "details": {"user": "admin", "service": "sshd"},
    }


@pytest.fixture
def valid_finding_data() -> dict[str, Any]:
    return {
        "finding_id": str(uuid.uuid4()),
        "tool_name": "web_security_analyzer",
        "rule_id": "RULE-WEB-SQLI",
        "severity": "high",
        "target": "https://api.sentinelx.local/login",
        "description": "SQL injection pattern detected in query parameters",
        "evidence": {"param": "id", "payload": "1' OR '1'='1"},
        "timestamp": "2026-10-07T12:00:00Z",
        "mitre_attack_id": "T1190",
    }


@pytest.fixture
def valid_alert_data() -> dict[str, Any]:
    return {
        "alert_id": str(uuid.uuid4()),
        "rule_id": "RULE-AUTH-001",
        "rule_name": "SSH Brute-Force Authentication Attempt",
        "severity": "high",
        "status": "NEW",
        "mitre_attack_id": "T1110",
        "source_ip": "192.168.1.100",
        "target_asset_id": str(uuid.uuid4()),
        "target_host": "server-prod-01",
        "dedup_key": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "occurrence_count": 5,
        "first_seen": "2026-10-07T11:55:00Z",
        "last_seen": "2026-10-07T12:00:00Z",
        "evidence": [str(uuid.uuid4())],
        "created_at": "2026-10-07T12:00:01Z",
        "updated_at": "2026-10-07T12:00:01Z",
    }


@pytest.fixture
def valid_incident_data() -> dict[str, Any]:
    return {
        "incident_id": str(uuid.uuid4()),
        "title": "Multiple SSH Brute Force Attacks against Production Gateway",
        "description": "Correlated incident aggregating repeated brute force attempts",
        "severity": "critical",
        "status": "OPEN",
        "risk_score": 85,
        "target_asset_id": str(uuid.uuid4()),
        "target_host": "server-prod-01",
        "alert_ids": [str(uuid.uuid4())],
        "timeline": [
            {
                "timestamp": "2026-10-07T12:00:01Z",
                "event_type": "incident_created",
                "description": "Incident automatically created from high-severity alert",
                "source": "IncidentService",
            }
        ],
        "created_at": "2026-10-07T12:00:01Z",
        "updated_at": "2026-10-07T12:00:01Z",
    }


@pytest.fixture
def valid_action_data() -> dict[str, Any]:
    return {
        "action_id": str(uuid.uuid4()),
        "action_type": "webhook_notification",
        "incident_id": str(uuid.uuid4()),
        "target": "https://hooks.slack.com/services/T00/B00/X00",
        "parameters": {"channel": "#soc-alerts", "urgent": True},
        "status": "PENDING",
        "requested_by": "system",
        "requested_at": "2026-10-07T12:00:02Z",
        "executed_at": None,
        "result": None,
    }


# =========================================================================
# 1. Draft-07 Schema Validation Tests
# =========================================================================


@pytest.mark.parametrize(
    "relative_schema_path",
    [
        "events/event_contract.json",
        "findings/finding_contract.json",
        "alerts/alert_contract.json",
        "incidents/incident_contract.json",
        "actions/action_contract.json",
    ],
)
def test_json_schemas_are_valid_draft7(relative_schema_path: str):
    schema = load_json_schema(relative_schema_path)
    Draft7Validator.check_schema(schema)


# =========================================================================
# 2. Pydantic Model Instantiation & Schema Cross-Validation
# =========================================================================


def test_event_contract_parity(event_schema: dict[str, Any], valid_event_data: dict[str, Any]):
    # Validate against JSON schema directly
    jsonschema.validate(instance=valid_event_data, schema=event_schema)

    # Validate with Pydantic
    model = EventContract.model_validate(valid_event_data)
    assert str(model.event_id) == valid_event_data["event_id"]
    assert model.destination_port == 22

    # Dump to JSON mode and re-validate against JSON schema
    dumped = model.model_dump(mode="json")
    jsonschema.validate(instance=dumped, schema=event_schema)


def test_finding_contract_parity(
    finding_schema: dict[str, Any], valid_finding_data: dict[str, Any]
):
    jsonschema.validate(instance=valid_finding_data, schema=finding_schema)

    model = FindingContract.model_validate(valid_finding_data)
    assert model.severity == SeverityLevel.HIGH
    assert model.severity == "high"

    dumped = model.model_dump(mode="json")
    jsonschema.validate(instance=dumped, schema=finding_schema)


def test_alert_contract_parity(alert_schema: dict[str, Any], valid_alert_data: dict[str, Any]):
    jsonschema.validate(instance=valid_alert_data, schema=alert_schema)

    model = AlertContract.model_validate(valid_alert_data)
    assert model.status == AlertStatus.NEW
    assert model.status == "NEW"
    assert model.occurrence_count == 5

    dumped = model.model_dump(mode="json")
    jsonschema.validate(instance=dumped, schema=alert_schema)


def test_incident_contract_parity(
    incident_schema: dict[str, Any], valid_incident_data: dict[str, Any]
):
    jsonschema.validate(instance=valid_incident_data, schema=incident_schema)

    model = IncidentContract.model_validate(valid_incident_data)
    assert model.status == IncidentStatus.OPEN
    assert model.risk_score == 85
    assert len(model.timeline) == 1
    assert isinstance(model.timeline[0], TimelineItem)

    dumped = model.model_dump(mode="json")
    jsonschema.validate(instance=dumped, schema=incident_schema)


def test_action_contract_parity(action_schema: dict[str, Any], valid_action_data: dict[str, Any]):
    jsonschema.validate(instance=valid_action_data, schema=action_schema)

    model = ActionContract.model_validate(valid_action_data)
    assert model.action_type == ActionType.WEBHOOK_NOTIFICATION
    assert model.status == ActionStatus.PENDING

    dumped = model.model_dump(mode="json")
    jsonschema.validate(instance=dumped, schema=action_schema)


# =========================================================================
# 3. Field Parity Checks
# =========================================================================


@pytest.mark.parametrize(
    "model_cls, relative_schema_path",
    [
        (EventContract, "events/event_contract.json"),
        (FindingContract, "findings/finding_contract.json"),
        (AlertContract, "alerts/alert_contract.json"),
        (IncidentContract, "incidents/incident_contract.json"),
        (ActionContract, "actions/action_contract.json"),
    ],
)
def test_field_parity_between_pydantic_and_json_schema(model_cls: type, relative_schema_path: str):
    schema = load_json_schema(relative_schema_path)
    schema_properties = set(schema["properties"].keys())
    model_fields = set(model_cls.model_fields.keys())

    # Every property defined in JSON Schema must exist in Pydantic model
    assert (
        schema_properties == model_fields
    ), f"Mismatch in {model_cls.__name__}: schema={schema_properties}, model={model_fields}"

    # Required fields in schema must be required (no default) in model
    schema_required = set(schema.get("required", []))
    model_required = {name for name, field in model_cls.model_fields.items() if field.is_required()}
    assert (
        schema_required == model_required
    ), f"Required fields mismatch in {model_cls.__name__}: schema={schema_required}, model={model_required}"


# =========================================================================
# 4. Strict Validation & Boundary Failure Tests
# =========================================================================


def test_missing_required_fields_rejected(
    valid_event_data: dict[str, Any], event_schema: dict[str, Any]
):
    invalid_data = valid_event_data.copy()
    del invalid_data["event_id"]

    with pytest.raises(PydanticValidationError):
        EventContract.model_validate(invalid_data)

    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_data, schema=event_schema)


def test_extra_unknown_fields_rejected(
    valid_event_data: dict[str, Any], event_schema: dict[str, Any]
):
    invalid_data = {**valid_event_data, "unauthorized_injected_field": "exploit"}

    with pytest.raises(PydanticValidationError):
        EventContract.model_validate(invalid_data)

    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_data, schema=event_schema)


def test_invalid_severity_enum_rejected(
    valid_finding_data: dict[str, Any], finding_schema: dict[str, Any]
):
    invalid_data = {**valid_finding_data, "severity": "catastrophic"}

    with pytest.raises(PydanticValidationError):
        FindingContract.model_validate(invalid_data)

    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_data, schema=finding_schema)


def test_incident_risk_score_bounds_rejected(
    valid_incident_data: dict[str, Any], incident_schema: dict[str, Any]
):
    # Risk score > 100
    invalid_high = {**valid_incident_data, "risk_score": 105}
    with pytest.raises(PydanticValidationError):
        IncidentContract.model_validate(invalid_high)
    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_high, schema=incident_schema)

    # Risk score < 0
    invalid_low = {**valid_incident_data, "risk_score": -5}
    with pytest.raises(PydanticValidationError):
        IncidentContract.model_validate(invalid_low)
    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_low, schema=incident_schema)


def test_port_bounds_rejected(valid_event_data: dict[str, Any], event_schema: dict[str, Any]):
    invalid_port = {**valid_event_data, "destination_port": 70000}
    with pytest.raises(PydanticValidationError):
        EventContract.model_validate(invalid_port)
    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_port, schema=event_schema)

    invalid_port_zero = {**valid_event_data, "source_port": 0}
    with pytest.raises(PydanticValidationError):
        EventContract.model_validate(invalid_port_zero)
    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_port_zero, schema=event_schema)


def test_alert_dedup_key_length_enforced(
    valid_alert_data: dict[str, Any], alert_schema: dict[str, Any]
):
    # Invalid length (63 characters instead of 64)
    invalid_dedup = {**valid_alert_data, "dedup_key": "a" * 63}
    with pytest.raises(PydanticValidationError):
        AlertContract.model_validate(invalid_dedup)
    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_dedup, schema=alert_schema)


def test_alert_evidence_cap_enforced(
    valid_alert_data: dict[str, Any], alert_schema: dict[str, Any]
):
    # Evidence list exceeds cap of 100 items
    invalid_evidence = {**valid_alert_data, "evidence": [str(uuid.uuid4()) for _ in range(101)]}
    with pytest.raises(PydanticValidationError):
        AlertContract.model_validate(invalid_evidence)
    with pytest.raises(JsonSchemaValidationError):
        jsonschema.validate(instance=invalid_evidence, schema=alert_schema)


# =========================================================================
# 5. TypeScript Interface Parity Tests (Law 2 / Component 8)
# =========================================================================


def test_typescript_types_file_exists_and_matches_contracts():
    """Validates that frontend/src/types/index.ts defines corresponding types with contract field parity."""
    ts_types_file = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"
    assert ts_types_file.exists(), f"Frontend TypeScript types file not found at {ts_types_file}"

    ts_content = ts_types_file.read_text(encoding="utf-8")

    # Enums verification
    for sev in ["critical", "high", "medium", "low"]:
        assert f'"{sev}"' in ts_content

    for alert_st in ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]:
        assert f'"{alert_st}"' in ts_content

    for inc_st in ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"]:
        assert f'"{inc_st}"' in ts_content

    # Interface declarations
    for iface in ["User", "Asset", "Alert", "Incident", "IncidentDetail", "AuditLog", "AuditVerify"]:
        assert f"interface {iface}" in ts_content

    # Key fields parity for Alert
    alert_fields = ["rule_id", "severity", "status", "source_ip", "dedup_key", "occurrence_count", "evidence"]
    for field in alert_fields:
        assert f"{field}:" in ts_content

    # Key fields parity for Incident
    inc_fields = ["title", "severity", "status", "risk_score"]
    for field in inc_fields:
        assert f"{field}:" in ts_content
