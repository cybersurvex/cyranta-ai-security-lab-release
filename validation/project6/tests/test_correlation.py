"""Project 6.3: offline SOC correlation and provenance boundary tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from monitoring.dashboard import _parse_alert
from monitoring.detector import detect_blocked_request
from monitoring.gateway_detection import detect_gateway_decision
from validation.project6 import correlation

ROOT = Path(__file__).resolve().parents[3]
SHA = "a" * 40


@pytest.fixture
def local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    output = tmp_path / "fresh"
    monkeypatch.setattr(correlation, "_output", lambda _root, _destination: output)
    monkeypatch.setattr(correlation.ac, "_revision", lambda _root: (SHA, True))
    return output


def _json(path: Path, name: str) -> dict:
    return json.loads((path / name).read_text(encoding="utf-8"))


def _write(path: Path, name: str, doc: dict) -> None:
    (path / name).write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")


def _alerts():
    rows = []
    for event in correlation.fixture_events():
        safe = detect_blocked_request(event)
        if safe is None:
            safe = detect_gateway_decision(event)
        if safe is not None:
            alert = _parse_alert(safe)
            assert alert is not None
            rows.append(alert)
    return rows


def test_fixture_is_bounded_and_synthetic() -> None:
    rows = correlation.fixture_events()
    assert len(rows) == 5
    assert rows[0] == rows[3]
    assert {row["request_id"] for row in rows} == {
        correlation.FIXTURE_REQUEST_A,
        correlation.FIXTURE_REQUEST_B,
        correlation.FIXTURE_REQUEST_C,
    }
    assert all(not ({"prompt", "secret", "user_id", "tool_args"} & row.keys()) for row in rows)


def test_actual_project4_detectors_produce_three_alerts() -> None:
    from monitoring.detector import RULE_ID

    alerts = _alerts()
    assert [row.rule_id for row in alerts] == [RULE_ID, "CYR-DET-006", "CYR-DET-007", RULE_ID]
    assert len({row.alert_id for row in alerts}) == 3


def test_correlate_intentional_shared_id_only() -> None:
    cases = correlation.correlate(_alerts()[:3])
    correlation._check_cases(cases)
    assert sorted(case["alert_count"] for case in cases) == [1, 2]
    assert all(case["confirmed_incident"] is False for case in cases)
    assert all(case["triage_state"] == "not_triaged" for case in cases)


def test_unrelated_ids_never_join_even_with_same_time() -> None:
    alerts = _alerts()[:3]
    event = correlation.fixture_events()[1].copy()
    event["request_id"] = "44444444-4444-4444-8444-444444444444"
    safe = detect_gateway_decision(event)
    assert safe is not None
    changed = _parse_alert(safe)
    assert changed is not None
    cases = correlation.correlate([alerts[0], changed])
    assert len(cases) == 2
    assert all(case["alert_count"] == 1 for case in cases)


@pytest.mark.parametrize("minutes", [6, 10, 60])
def test_outside_time_window_stays_separate(minutes: int) -> None:
    alerts = _alerts()[:2]
    new_time = datetime.fromisoformat(alerts[1].event_ts) + timedelta(minutes=minutes - 1)
    updated = replace(alerts[1], event_ts=new_time.isoformat())
    cases = correlation.correlate([alerts[0], updated])
    assert len(cases) == 2


def test_exact_boundary_joins() -> None:
    alerts = _alerts()[:2]
    updated = replace(alerts[1], event_ts="2026-11-02T12:05:00+00:00")
    assert correlation.correlate([alerts[0], updated])[0]["alert_count"] == 2


def test_no_join_by_shared_rule_or_severity() -> None:
    alerts = _alerts()[:3]
    assert len(correlation.correlate([alerts[0], alerts[2]])) == 2


def test_duplicate_alert_rejected() -> None:
    alerts = _alerts()
    with pytest.raises(correlation.CorrelationError):
        correlation.correlate(alerts)


def test_foreign_alert_type_rejected() -> None:
    with pytest.raises(correlation.CorrelationError):
        correlation.correlate([{"alert_id": "fake"}])


@pytest.mark.parametrize("window", [0, -1, 3601, True, 2.0, "300"])
def test_invalid_window_rejected(window: object) -> None:
    with pytest.raises(correlation.CorrelationError):
        correlation.correlate([], window_seconds=window)


def test_empty_alerts_produce_no_incidents() -> None:
    assert correlation.correlate([]) == []


def test_hash_case_id_stable() -> None:
    first = correlation.correlate(_alerts()[:3])
    second = correlation.correlate(list(reversed(_alerts()[:3])))
    assert first == second
    assert all(len(row["case_id"]) == 24 for row in first)


def test_run_creates_sanitized_evidence(local: Path) -> None:
    result = correlation.run(ROOT)
    assert result["events"] == 5
    assert result["alerts"] == 3
    assert result["duplicates_ignored"] == 1
    assert result["benign_ignored"] == 1
    assert result["cases"] == 2
    assert result["multi_alert_cases"] == 1
    assert result["incident_confirmed"] is False
    report = _json(local, "incident-cases.json")
    assert report["scenario_context"] == "CYR-P6-SCN-006"
    assert report["project6_2_evidence_link_verified"] is False
    assert report["open_registered_risks"] == 1
    assert report["security_assured_release_approved"] is False
    assert "NOT A CONFIRMED INCIDENT" in (local / "incident-report.md").read_text(encoding="utf-8")
    for file in correlation.EVIDENCE_FILES:
        contents = (local / file).read_text(encoding="utf-8")
        assert "CYR-ORDER-1007" not in contents
        assert "CYR-DEMO-KEY" not in contents
        assert "UNTRUSTED_DOCUMENT_INSTRUCTION_MARKER" not in contents


def test_verify_generated_evidence(local: Path) -> None:
    correlation.run(ROOT)
    result = correlation.verify(ROOT)
    assert result["revision_matches"] is True
    assert result["clean_committed_local_record"] is True
    assert result["independently_attested"] is False
    assert result["incident_confirmed"] is False
    assert result["control_effectiveness_verified"] is False


def test_repeated_run_does_not_overwrite(local: Path) -> None:
    correlation.run(ROOT)
    before = _json(local, "evidence-manifest.json")
    with pytest.raises(correlation.CorrelationError):
        correlation.run(ROOT)
    assert _json(local, "evidence-manifest.json") == before


def test_modified_evidence_rejected(local: Path) -> None:
    correlation.run(ROOT)
    (local / "incident-report.md").write_text("FORGED CONFIRMED INCIDENT", encoding="utf-8")
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_missing_evidence_rejected(local: Path) -> None:
    correlation.run(ROOT)
    (local / "alerts.jsonl").unlink()
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_manifest_extra_field_rejected(local: Path) -> None:
    correlation.run(ROOT)
    doc = _json(local, "evidence-manifest.json")
    doc["approved_by"] = "fictional-analyst"
    _write(local, "evidence-manifest.json", doc)
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


@pytest.mark.parametrize("field,value", [
    ("signed", True),
    ("kind", "independently_attested"),
    ("source_commit", "not_sha"),
    ("source_sha256", {}),
    ("files_sha256", {}),
    ("schema_version", True),
    ("schema_version", 3),
])
def test_manifest_tampering_rejected(local: Path, field: str, value: object) -> None:
    correlation.run(ROOT)
    doc = _json(local, "evidence-manifest.json")
    doc[field] = value
    _write(local, "evidence-manifest.json", doc)
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


@pytest.mark.parametrize("field", [
    "project6_2_evidence_link_verified", "live_attacks_executed", "incident_confirmed",
    "independently_attested", "control_effectiveness_verified", "compliance_certified",
    "security_assured_release_approved",
])
def test_fake_assurance_claims_rejected(local: Path, field: str) -> None:
    correlation.run(ROOT)
    doc = _json(local, "incident-cases.json")
    doc[field] = True
    _write(local, "incident-cases.json", doc)
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_different_revision_is_not_clean_attestation(monkeypatch: pytest.MonkeyPatch, local: Path) -> None:
    correlation.run(ROOT)
    monkeypatch.setattr(correlation.ac, "_revision", lambda _root: ("b" * 40, True))
    result = correlation.verify(ROOT)
    assert result["revision_matches"] is False
    assert result["clean_committed_local_record"] is False


def test_dirty_snapshot_fails_clean_record(monkeypatch: pytest.MonkeyPatch, local: Path) -> None:
    correlation.run(ROOT)
    monkeypatch.setattr(correlation.ac, "_revision", lambda _root: (SHA, False))
    assert correlation.verify(ROOT)["clean_committed_local_record"] is False


def test_dirty_capture_fails_clean_record(monkeypatch: pytest.MonkeyPatch, local: Path) -> None:
    monkeypatch.setattr(correlation.ac, "_revision", lambda _root: (SHA, False))
    correlation.run(ROOT)
    assert correlation.verify(ROOT)["clean_committed_local_record"] is False


def test_invalid_detector_counts_fail_closed(monkeypatch: pytest.MonkeyPatch, local: Path) -> None:
    from monitoring.detector import ScanSummary

    monkeypatch.setattr(correlation, "scan_jsonl", lambda *_: ScanSummary())
    with pytest.raises(correlation.CorrelationError):
        correlation.run(ROOT)


def test_output_path_escape_rejected() -> None:
    with pytest.raises(correlation.gd.DashboardError):
        correlation._output(ROOT, ROOT.parent / "unsafe")


def test_symlink_manifest_rejected(local: Path, tmp_path: Path) -> None:
    correlation.run(ROOT)
    link = local / "evidence-manifest.json"
    data = link.read_bytes()
    link.unlink()
    outside = tmp_path / "outside.json"
    outside.write_bytes(data)
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_local_report_includes_response_not_automated_containment(local: Path) -> None:
    correlation.run(ROOT)
    text = (local / "response-playbook.md").read_text(encoding="utf-8")
    assert "No production action" in text
    assert "explicit authorization" in text
    assert "not triaged" in text


def test_cli_run_and_verify(monkeypatch: pytest.MonkeyPatch, local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert correlation.main(["run", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["cases"] == 2
    assert correlation.main(["verify", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["clean_committed_local_record"] is True


def test_cli_missing_evidence_exits_fail_closed(local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert correlation.main(["verify", "--repo-root", str(ROOT)]) == 2
    assert "correlation failed" in capsys.readouterr().err


def test_cli_repeated_run_exits_fail_closed(local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    correlation.run(ROOT)
    assert correlation.main(["run", "--repo-root", str(ROOT)]) == 2
    assert "correlation failed" in capsys.readouterr().err


def test_no_scenario_manifests_modified(local: Path) -> None:
    from validation.project6.schema import SPECS

    original = {
        sid: (ROOT / "validation/project6/scenarios" / f"{sid}.json").read_bytes()
        for sid in SPECS
    }
    correlation.run(ROOT)
    for sid in SPECS:
        assert (ROOT / "validation/project6/scenarios" / f"{sid}.json").read_bytes() == original[sid]


def _resign_local_hash(local: Path, filename: str) -> None:
    """Illustrate why an unsigned hash manifest alone is not an authenticity proof."""
    doc = _json(local, "evidence-manifest.json")
    doc["files_sha256"][filename] = correlation._hash(local / filename)
    _write(local, "evidence-manifest.json", doc)


def test_forged_alert_extra_field_rejected_even_with_updated_manifest(local: Path) -> None:
    correlation.run(ROOT)
    path = local / "alerts.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["prompt"] = "FAKE_PRIVATE_PAYLOAD"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    _resign_local_hash(local, "alerts.jsonl")
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_forged_event_rejected_even_with_updated_manifest(local: Path) -> None:
    correlation.run(ROOT)
    path = local / "events.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["prompt"] = "FAKE_PRIVATE_PAYLOAD"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    _resign_local_hash(local, "events.jsonl")
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_forged_case_link_rejected_even_with_updated_manifest(local: Path) -> None:
    correlation.run(ROOT)
    document = _json(local, "incident-cases.json")
    document["cases"][1]["confirmed_incident"] = True
    _write(local, "incident-cases.json", document)
    _resign_local_hash(local, "incident-cases.json")
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_changed_source_hash_rejected(local: Path) -> None:
    correlation.run(ROOT)
    manifest = _json(local, "evidence-manifest.json")
    manifest["source_sha256"]["monitoring/detector.py"] = "0" * 64
    _write(local, "evidence-manifest.json", manifest)
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)


def test_changed_risk_not_silently_accepted(monkeypatch: pytest.MonkeyPatch, local: Path) -> None:
    correlation.run(ROOT)
    original = correlation.schema.validate

    def changed(root: Path) -> dict:
        result = original(root)
        result["open_registered_risks"] = 0
        return result

    monkeypatch.setattr(correlation.schema, "validate", changed)
    with pytest.raises(correlation.CorrelationError):
        correlation.verify(ROOT)
