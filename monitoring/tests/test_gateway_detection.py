"""Offline tests: CYR-DET-006/007, sanitization, normalization and scan integration."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from monitoring.detector import scan_jsonl
from monitoring.gateway_detection import (
    AUTHORIZATION_CODES,
    UNAUTHORIZED_CODES,
    detect_gateway_decision,
    emit_gateway_audit,
    normalize_gateway_audit,
)


@pytest.fixture
def raw_gateway_audit() -> dict:
    return {
        "request_id": "9e04bcb5-9acc-46ab-a320-dd697a580619",
        "time_epoch": 1791916800.0,
        "user_id": "SENSITIVE_USER_ID_NEVER_COPY",
        "agent_id": "cyranta-ops-agent",
        "role": "support_readonly",
        "tool": "issue_refund",
        "resource": "SENSITIVE_ORDER_ID_NEVER_COPY",
        "allowed": False,
        "decision_code": "ROLE_TOOL_DENIED",
        "bearer_token": "SENSITIVE_BEARER_TOKEN_NEVER_COPY",
        "arguments": "SENSITIVE_ARGUMENTS_NEVER_COPY",
    }


@pytest.mark.parametrize("code", sorted(UNAUTHORIZED_CODES))
def test_unauthorized_rule_codes(raw_gateway_audit: dict, code: str) -> None:
    raw_gateway_audit["decision_code"] = code
    safe = normalize_gateway_audit(raw_gateway_audit)
    alert = detect_gateway_decision(safe)
    assert alert["rule_id"] == "CYR-DET-006"
    assert alert["decision_code"] == code
    assert alert["severity"] == "medium"


@pytest.mark.parametrize("code", sorted(AUTHORIZATION_CODES))
def test_authorization_rule_codes(raw_gateway_audit: dict, code: str) -> None:
    raw_gateway_audit["decision_code"] = code
    safe = normalize_gateway_audit(raw_gateway_audit)
    alert = detect_gateway_decision(safe)
    assert alert["rule_id"] == "CYR-DET-007"
    assert alert["decision_code"] == code
    assert alert["severity"] == "high"


def test_no_sensitive_fields_exported(raw_gateway_audit: dict) -> None:
    safe = normalize_gateway_audit(raw_gateway_audit)
    alert = detect_gateway_decision(safe)
    assert set(safe) == {"event_type", "request_id", "ts", "allowed", "decision_code"}
    assert set(alert) == {
        "alert_id", "rule_id", "severity", "event_type", "request_id",
        "event_ts", "decision_code", "reason",
    }
    serialized = json.dumps((safe, alert))
    for marker in (
        "SENSITIVE_USER_ID_NEVER_COPY",
        "SENSITIVE_ORDER_ID_NEVER_COPY",
        "SENSITIVE_BEARER_TOKEN_NEVER_COPY",
        "SENSITIVE_ARGUMENTS_NEVER_COPY",
    ):
        assert marker not in serialized


def test_allowed_decision_no_alert(raw_gateway_audit: dict) -> None:
    raw_gateway_audit["allowed"] = True
    raw_gateway_audit["decision_code"] = "ALLOWED"
    assert detect_gateway_decision(normalize_gateway_audit(raw_gateway_audit)) is None


def test_non_security_denial_is_not_mislabelled(raw_gateway_audit: dict) -> None:
    raw_gateway_audit["decision_code"] = "TOOL_INPUT_REJECTED"
    assert detect_gateway_decision(normalize_gateway_audit(raw_gateway_audit)) is None


@pytest.mark.parametrize("value", [True, False, float("nan"), float("inf"), float("-inf"), 10 ** 1000, "bad"])
def test_invalid_epoch_rejected(raw_gateway_audit: dict, value: object) -> None:
    raw_gateway_audit["time_epoch"] = value
    assert normalize_gateway_audit(raw_gateway_audit) is None


def test_missing_and_contradictory_decisions_rejected(raw_gateway_audit: dict) -> None:
    raw_gateway_audit["allowed"] = True
    assert normalize_gateway_audit(raw_gateway_audit) is None
    raw_gateway_audit["allowed"] = False
    raw_gateway_audit["decision_code"] = "ALLOWED"
    assert normalize_gateway_audit(raw_gateway_audit) is None
    raw_gateway_audit["allowed"] = "false"
    assert normalize_gateway_audit(raw_gateway_audit) is None
    raw_gateway_audit["request_id"] = "not-a-uuid"
    assert normalize_gateway_audit(raw_gateway_audit) is None


def test_naive_and_invalid_normalized_ts_rejected(raw_gateway_audit: dict) -> None:
    event = normalize_gateway_audit(raw_gateway_audit)
    event["ts"] = "2026-10-13T16:00:00"
    assert detect_gateway_decision(event) is None
    event["ts"] = "invalid"
    assert detect_gateway_decision(event) is None
    event["ts"] = "2026-10-13T16:00:00Z"
    assert detect_gateway_decision(event) is not None


def test_emit_normalizes_before_writing(raw_gateway_audit: dict) -> None:
    output: list[dict] = []
    assert emit_gateway_audit([raw_gateway_audit], output.append) == 1
    assert output == [normalize_gateway_audit(raw_gateway_audit)]


def test_gateway_audit_scanned_and_deduplicated(tmp_path: Path, raw_gateway_audit: dict) -> None:
    event_path = tmp_path / "gateway.jsonl"
    output_path = tmp_path / "alerts.jsonl"
    second = {**raw_gateway_audit, "request_id": str(uuid4()), "decision_code": "APPROVAL_REQUIRED"}
    benign = {**raw_gateway_audit, "request_id": str(uuid4()), "decision_code": "ALLOWED", "allowed": True}
    malformed = {**raw_gateway_audit, "request_id": "invalid"}
    normalized = normalize_gateway_audit(second)
    event_path.write_text("\n".join(json.dumps(x) for x in (
        raw_gateway_audit, raw_gateway_audit, normalized, benign, malformed,
        {"event_type": "irrelevant"},
    )) + "\n", encoding="utf-8")
    summary = scan_jsonl(event_path, output_path)
    assert summary.to_dict() == {
        "lines": 6, "alerts": 2, "ignored": 2, "malformed": 1, "duplicates": 1,
    }
    alerts = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert {a["rule_id"] for a in alerts} == {"CYR-DET-006", "CYR-DET-007"}
    assert "SENSITIVE_" not in output_path.read_text(encoding="utf-8")
    assert scan_jsonl(event_path, output_path) == summary
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 2


def test_real_gateway_audit_adapter() -> None:
    from agent.security.tool_gateway import SERVICE_ID, Principal, ToolGateway
    from agent.tools.mock_tools import MockRetailTools

    gateway = ToolGateway(MockRetailTools(), now=lambda: 1791916800.0)
    actor = Principal(
        user_id="LAB-USER", role="support_readonly", agent_id=SERVICE_ID,
        order_ids=frozenset({"CYR-ORDER-1007"}), skus=frozenset(),
    )
    decision = gateway.execute(actor, "issue_refund", {"order_id": "CYR-ORDER-1007", "amount": "20"})
    assert decision.code == "ROLE_TOOL_DENIED"
    assert len(gateway.audit) == 1
    safe = normalize_gateway_audit(gateway.audit[0])
    alert = detect_gateway_decision(safe)
    assert alert["rule_id"] == "CYR-DET-006"
    assert alert["request_id"] == decision.request_id


def test_unknown_code_is_not_exported(raw_gateway_audit: dict) -> None:
    raw_gateway_audit["decision_code"] = "UNTRUSTED_USER_MESSAGE"
    assert normalize_gateway_audit(raw_gateway_audit) is None
