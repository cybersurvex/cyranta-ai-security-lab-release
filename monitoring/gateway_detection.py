"""CYR-DET-006/007: privacy-preserving detection of Project 3 gateway denials.

All exported event/alert keys are explicit allowlists. Nothing in this module
changes, grants, retries, or executes a ToolGateway decision.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

RULE_UNAUTHORIZED = "CYR-DET-006"
RULE_AUTHORIZATION = "CYR-DET-007"

# Exact codes emitted by ToolGateway.execute(), not heuristic string matching.
UNAUTHORIZED_CODES = frozenset({
    "UNKNOWN_TOOL",
    "AGENT_IDENTITY_DENIED",
    "ROLE_TOOL_DENIED",
    "RESOURCE_DENIED",
    "CAPABILITY_REQUIRED",
    "CAPABILITY_SCOPE_MISMATCH",
})
AUTHORIZATION_CODES = frozenset({
    "CAPABILITY_INVALID_OR_EXPIRED",
    "APPROVAL_REQUIRED",
    "APPROVAL_INVALID_OR_EXPIRED",
    "APPROVAL_SCOPE_MISMATCH",
    "EMERGENCY_REVOKED",
})
DETECTABLE_CODES = UNAUTHORIZED_CODES | AUTHORIZATION_CODES
# Other exact outcomes produced by execute(); keep code values in telemetry
# restricted to trusted enums, never arbitrary free-form event strings.
KNOWN_CODES = DETECTABLE_CODES | frozenset({
    "ALLOWED", "INVALID_AMOUNT", "UNKNOWN_ORDER", "REFUND_LIMIT_EXCEEDED",
    "DUPLICATE_REFUND", "TOOL_INPUT_REJECTED",
})


def _valid_request_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def _valid_timestamp(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        return None
    return timestamp.isoformat()


def normalize_gateway_audit(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Transform one *trusted* ToolGateway.audit dict into sanitized telemetry.

    Input must come from the trusted application, NOT an LLM request or bearer
    token. User IDs, resource IDs, tool arguments and tokens are never copied.
    """
    request_id = _valid_request_id(record.get("request_id"))
    epoch = record.get("time_epoch")
    allowed = record.get("allowed")
    code = record.get("decision_code")
    if (
        request_id is None
        or isinstance(epoch, bool)
        or not isinstance(epoch, (int, float))
        or not isinstance(allowed, bool)
        or not isinstance(code, str)
        or code not in KNOWN_CODES
    ):
        return None
    # Never allow a contradictory ALLOWED/denied state into normalized events.
    if (allowed and code != "ALLOWED") or (not allowed and code == "ALLOWED"):
        return None
    try:
        timestamp_seconds = float(epoch)
        if not math.isfinite(timestamp_seconds):
            return None
        event_ts = datetime.fromtimestamp(timestamp_seconds, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None
    return {
        "event_type": "tool_decision",
        "request_id": request_id,
        "ts": event_ts,
        "allowed": allowed,
        "decision_code": code,
    }


def detect_gateway_decision(event: Mapping[str, Any]) -> dict[str, str] | None:
    """Detect only known negative decisions, without copying untrusted fields."""
    if event.get("event_type") != "tool_decision" or event.get("allowed") is not False:
        return None
    code = event.get("decision_code")
    if not isinstance(code, str) or code not in DETECTABLE_CODES:
        return None
    request_id = _valid_request_id(event.get("request_id"))
    event_ts = _valid_timestamp(event.get("ts"))
    if request_id is None or event_ts is None:
        return None

    if code in UNAUTHORIZED_CODES:
        rule_id = RULE_UNAUTHORIZED
        severity = "medium"
        reason = "Gateway denied a tool request based on identity, role, resource or scope"
    else:
        rule_id = RULE_AUTHORIZATION
        severity = "high"
        reason = "Gateway rejected capability or approval, or emergency revocation is active"

    alert_id = hashlib.sha256(f"{rule_id}:{request_id}".encode()).hexdigest()[:24]
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "severity": severity,
        "event_type": "tool_decision",
        "request_id": request_id,
        "event_ts": event_ts,
        "decision_code": code,  # Exact allowlisted code: no user-controlled text.
        "reason": reason,
    }


def emit_gateway_audit(
    records: Iterable[Mapping[str, Any]],
    writer: Callable[[dict[str, Any]], None],
) -> int:
    """Write sanitized decisions using the existing app.telemetry.write_event.

    Call from *trusted* harness after gateway.execute(). Caller should pass
    only new audit records (e.g. gateway.audit[previous_count:]) to avoid
    unnecessary repeated telemetry writes. No gateway internals are changed.
    """
    emitted = 0
    for raw in records:
        safe = normalize_gateway_audit(raw)
        if safe is not None:
            writer(safe)
            emitted += 1
    return emitted
