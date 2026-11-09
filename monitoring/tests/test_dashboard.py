"""Project 4.3 regression tests: offline, no Ollama/ChromaDB/network required."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from uuid import uuid4

import pytest

from monitoring.dashboard import (
    AlertLoad,
    _json_for_html,
    _parse_alert,
    generate,
    load_alerts,
    load_triage,
    main,
    render_dashboard,
    update_triage,
)


def make_alert(rule: str = "CYR-DET-001", **changes: object) -> dict:
    rid = str(uuid4())
    event = {
        "alert_id": hashlib.sha256(f"{rule}:{rid}".encode()).hexdigest()[:24],
        "request_id": rid,
        "rule_id": rule,
        "severity": "high" if rule == "CYR-DET-007" else "medium",
        "event_type": "llm_request" if rule == "CYR-DET-001" else "tool_decision",
        "event_ts": "2026-10-16T12:00:00+00:00",
        "reason": "from detector, not trusted",
    }
    if rule == "CYR-DET-006":
        event["decision_code"] = "ROLE_TOOL_DENIED"
    if rule == "CYR-DET-007":
        event["decision_code"] = "APPROVAL_INVALID_OR_EXPIRED"
    event.update(changes)
    return event


def put_events(path: Path, *events: object) -> None:
    path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")


def test_valid_chatbot_event() -> None:
    alert = _parse_alert(make_alert())
    assert alert is not None
    assert alert.rule_id == "CYR-DET-001"
    assert alert.decision_code == ""


@pytest.mark.parametrize("rule", ["CYR-DET-006", "CYR-DET-007"])
def test_valid_gateway_events(rule: str) -> None:
    alert = _parse_alert(make_alert(rule))
    assert alert is not None
    assert alert.rule_id == rule


@pytest.mark.parametrize("field,value", [
    ("rule_id", "CYR-DET-999"), ("severity", "low"),
    ("event_type", "something else"), ("alert_id", "a" * 24),
    ("request_id", "secret-user-identifier"), ("event_ts", "yesterday"),
    ("event_ts", "2026-10-16T12:00:00"),
])
def test_bad_records_rejected(field: str, value: str) -> None:
    assert _parse_alert(make_alert(**{field: value})) is None


@pytest.mark.parametrize("value", [["NOT_A_CODE"], "ARBITRARY_SECRET", "ALLOWED", None])
def test_invalid_gateway_decision_is_rejected(value: object) -> None:
    assert _parse_alert(make_alert("CYR-DET-006", decision_code=value)) is None


def test_extra_content_never_enters_report() -> None:
    record = make_alert(
        prompt="SECRET_PROMPT_NEVER_COPY",
        response="SECRET_RESPONSE_NEVER_COPY",
        user_id="PRIVATE_USER_ID",
        reason="SECRET_REASON_NEVER_COPY",
        token="BEARER_TOKEN_NEVER_COPY",
    )
    alert = _parse_alert(record)
    assert alert is not None
    report = render_dashboard(AlertLoad([alert]), {})
    for secret in ["SECRET_PROMPT_NEVER_COPY", "SECRET_RESPONSE_NEVER_COPY",
                   "PRIVATE_USER_ID", "SECRET_REASON_NEVER_COPY", "BEARER_TOKEN_NEVER_COPY"]:
        assert secret not in report
    assert 'connect-src \'none\'' in report
    assert 'http://' not in report and 'https://' not in report


def test_html_safe_json_escaping() -> None:
    encoded = _json_for_html({"value": "</script><script>alert('x')</script>&"})
    assert "<" not in encoded and ">" not in encoded and "&" not in encoded
    assert json.loads(encoded) == {"value": "</script><script>alert('x')</script>&"}


def test_report_includes_csp_hash() -> None:
    report = render_dashboard(AlertLoad([]), {})
    assert re.search(r"script-src 'sha256-[A-Za-z0-9+/]+=*'", report)
    assert "__ALERT_DATA__" not in report
    assert 'id="total"' in report


def test_empty_report_is_valid(tmp_path: Path) -> None:
    source = tmp_path / "alerts.jsonl"
    source.write_text("", encoding="utf-8")
    output = tmp_path / "report.html"
    summary = generate(source, tmp_path / "triage.json", output)
    assert summary.alerts == []
    assert output.exists()
    assert '"total":0' in output.read_text(encoding="utf-8")


def test_count_duplicates_and_invalid_json(tmp_path: Path) -> None:
    alert = make_alert()
    source = tmp_path / "alerts.jsonl"
    put_events(source, alert, alert, [], make_alert("CYR-DET-007"))
    with source.open("a", encoding="utf-8") as sink:
        sink.write("{invalid-json}\n")
    summary = load_alerts(source)
    assert (summary.lines, len(summary.alerts), summary.invalid, summary.duplicates) == (5, 2, 2, 1)


def test_triage_roundtrip_and_report(tmp_path: Path) -> None:
    event = make_alert("CYR-DET-007")
    alert_path = tmp_path / "alerts.jsonl"
    triage_path = tmp_path / "triage.json"
    report_path = tmp_path / "report.html"
    put_events(alert_path, event)
    alert_id = event["alert_id"]
    update_triage(alert_path, triage_path, alert_id, "investigating")
    assert load_triage(triage_path)[alert_id] == "investigating"
    update_triage(alert_path, triage_path, alert_id, "confirmed")
    assert load_triage(triage_path)[alert_id] == "confirmed"
    generate(alert_path, triage_path, report_path)
    report = report_path.read_text(encoding="utf-8")
    assert '"confirmed":1' in report
    assert '"high":1' in report
    assert '"open":0' in report


def test_unknown_alert_cannot_be_triaged(tmp_path: Path) -> None:
    source, store = tmp_path / "alerts.jsonl", tmp_path / "triage.json"
    put_events(source, make_alert())
    with pytest.raises(ValueError, match="not present"):
        update_triage(source, store, "a" * 24, "resolved")
    assert not store.exists()


@pytest.mark.parametrize("status", ["", "escalated", "ALLOWED", "confirmed; rm -rf /"])
def test_invalid_triage_status_rejected(tmp_path: Path, status: str) -> None:
    event = make_alert()
    source, store = tmp_path / "alerts.jsonl", tmp_path / "triage.json"
    put_events(source, event)
    with pytest.raises(ValueError):
        update_triage(source, store, event["alert_id"], status)


def test_corrupted_triage_not_overwritten(tmp_path: Path) -> None:
    event = make_alert()
    source, store = tmp_path / "alerts.jsonl", tmp_path / "triage.json"
    put_events(source, event)
    store.write_text("{bad JSON", encoding="utf-8")
    with pytest.raises(ValueError):
        update_triage(source, store, event["alert_id"], "confirmed")
    assert store.read_text(encoding="utf-8") == "{bad JSON"


def test_report_must_not_overwrite_input_or_triage(tmp_path: Path) -> None:
    source = tmp_path / "alerts.jsonl"
    store = tmp_path / "triage.json"
    put_events(source, make_alert())
    with pytest.raises(ValueError, match="differ"):
        generate(source, store, source)
    with pytest.raises(ValueError, match="differ"):
        generate(source, store, store)
    assert source.exists()


def test_cli_generate_and_triage(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    event = make_alert()
    source, store, output = (tmp_path / p for p in ("alerts.jsonl", "triage.json", "report.html"))
    put_events(source, event)
    assert main(["triage", "--alerts", str(source), "--triage-file", str(store),
                 "--alert-id", event["alert_id"], "--status", "false_positive"]) == 0
    assert main(["generate", "--alerts", str(source), "--triage-file", str(store),
                 "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["alerts"] == 1
    assert '"triage_status":"false_positive"' in output.read_text(encoding="utf-8")
