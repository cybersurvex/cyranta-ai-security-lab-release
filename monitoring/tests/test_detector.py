"""Offline regression tests for CYR-DET-001. No model or database required."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from monitoring.detector import RULE_ID, detect_blocked_request, scan_jsonl


@pytest.fixture
def example_event() -> dict:
    return {
        "ts": "2026-10-13T16:00:00+00:00",
        "event_type": "llm_request",
        "request_id": "d53a9cba-9f19-4b9e-a8fe-6c63b9ce8fc0",
        "session_hash": "abc123def4567890",
        "security_profile": "hardened",
        "model": "local-model",
        "status": "blocked",
        "blocked": True,
        "scope_limited": False,
        "input_flags": ["UNTRUSTED_ATTACK_STRING"],
        "output_flags": [],
        "dlp_redacted": False,
        "prompt_sha256": "a" * 64,
        "prompt_chars": 29,
        "response_chars": 0,
        "latency_ms": 2.4,
        "prompt": "SENSITIVE_PROMPT_NEVER_COPY",
        "response": "SENSITIVE_RESPONSE_NEVER_COPY",
    }


def test_blocked_llm_request_produces_one_alert(example_event: dict) -> None:
    alert = detect_blocked_request(example_event)
    assert alert is not None
    assert alert["rule_id"] == RULE_ID
    assert alert["request_id"] == example_event["request_id"]
    assert alert["severity"] == "medium"
    assert alert["event_ts"] == example_event["ts"]


def test_allowed_request_is_ignored(example_event: dict) -> None:
    example_event["blocked"] = False
    assert detect_blocked_request(example_event) is None


def test_other_event_type_is_ignored(example_event: dict) -> None:
    example_event["event_type"] = "tool_decision"
    assert detect_blocked_request(example_event) is None


@pytest.mark.parametrize("invalid_blocked", [1, "true", None, 0])
def test_only_boolean_true_triggers(example_event: dict, invalid_blocked: object) -> None:
    example_event["blocked"] = invalid_blocked
    assert detect_blocked_request(example_event) is None


def test_invalid_request_id_does_not_enter_alert(example_event: dict) -> None:
    example_event["request_id"] = "secret:bad-id"
    assert detect_blocked_request(example_event) is None


def test_invalid_or_naive_timestamp_is_rejected(example_event: dict) -> None:
    example_event["ts"] = "2026-10-13T16:00:00"
    assert detect_blocked_request(example_event) is None
    example_event["ts"] = "no valid timestamp"
    assert detect_blocked_request(example_event) is None


def test_utc_z_timestamp_is_accepted(example_event: dict) -> None:
    example_event["ts"] = "2026-10-13T16:00:00Z"
    assert detect_blocked_request(example_event)["event_ts"] == "2026-10-13T16:00:00+00:00"


def test_no_event_content_leaks_into_alert(example_event: dict) -> None:
    alert = detect_blocked_request(example_event)
    serialized = json.dumps(alert)
    for sensitive_value in (
        "SENSITIVE_PROMPT_NEVER_COPY",
        "SENSITIVE_RESPONSE_NEVER_COPY",
        "UNTRUSTED_ATTACK_STRING",
        "abc123def4567890",
    ):
        assert sensitive_value not in serialized
    assert set(alert) == {
        "alert_id",
        "rule_id",
        "severity",
        "event_type",
        "request_id",
        "event_ts",
        "reason",
    }


def test_scan_jsonl_deduplicates_and_counts_malformed(
    tmp_path: Path, example_event: dict
) -> None:
    source = tmp_path / "events.jsonl"
    sink = tmp_path / "alerts.jsonl"
    benign_event = {**example_event, "request_id": str(uuid4()), "blocked": False}
    invalid_blocked = {**example_event, "request_id": "wrong"}
    source.write_text(
        "\n".join(
            (
                json.dumps(example_event),
                json.dumps(example_event),
                json.dumps(benign_event),
                json.dumps(invalid_blocked),
                "{not-json}",
                "[]",
            )
        ) + "\n",
        encoding="utf-8",
    )
    summary = scan_jsonl(source, sink)
    assert summary.to_dict() == {
        "lines": 6,
        "alerts": 1,
        "ignored": 1,
        "malformed": 3,
        "duplicates": 1,
    }
    alerts = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == RULE_ID
    assert "SENSITIVE_PROMPT_NEVER_COPY" not in sink.read_text(encoding="utf-8")
    # A second run must replace (not append to) the alerts file.
    assert scan_jsonl(source, sink) == summary
    assert len(sink.read_text(encoding="utf-8").splitlines()) == 1


def test_input_cannot_be_overwritten(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="different"):
        scan_jsonl(source, source)
    assert source.read_text(encoding="utf-8") == "{}\n"


def test_missing_input_does_not_replace_existing_alerts(tmp_path: Path) -> None:
    sink = tmp_path / "alerts.jsonl"
    sink.write_text("previous alerts\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        scan_jsonl(tmp_path / "missing.jsonl", sink)
    assert sink.read_text(encoding="utf-8") == "previous alerts\n"
