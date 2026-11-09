"""Offline tests for Project 4.4 controlled SOC exercise and evidence integrity."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest

from monitoring import incident_simulation as sim
from monitoring.dashboard import load_alerts
from monitoring.detector import scan_jsonl


@pytest.fixture
def exercise(tmp_path: Path) -> Path:
    dest = tmp_path / "fictional-case"
    assert sim.run_simulation(dest) == {
        "scenarios": 4,
        "alerts": 3,
        "benign_controls": 1,
        "all_expected_detections_matched": True,
    }
    return dest


def test_build_scenarios_uses_real_gateway_and_synthetic_llm() -> None:
    scenarios = sim.build_scenarios()
    assert [s.scenario_id for s in scenarios] == [
        "SIM-LLM-001", "SIM-GATE-006", "SIM-GATE-007", "SIM-CTRL-000"
    ]
    assert [s.expected_rule for s in scenarios] == [
        "CYR-DET-001", "CYR-DET-006", "CYR-DET-007", None
    ]
    assert [s.origin for s in scenarios] == [
        "synthetic_chatbot_event", "real_mock_gateway_decision",
        "real_mock_gateway_decision", "real_mock_gateway_decision",
    ]
    for case in scenarios:
        assert str(UUID(case.request_id)) == case.request_id
        assert set(case.event) <= {
            "event_type", "request_id", "ts", "status", "blocked", "allowed", "decision_code"
        }


def test_denial_decisions_and_benign_control() -> None:
    scenarios = sim.build_scenarios()
    assert scenarios[1].event["decision_code"] == "ROLE_TOOL_DENIED"
    assert scenarios[2].event["decision_code"] == "APPROVAL_INVALID_OR_EXPIRED"
    assert scenarios[3].event["decision_code"] == "ALLOWED"
    assert scenarios[3].event["allowed"] is True
    assert all(s.event["allowed"] is False for s in scenarios[1:3])


def test_scanner_matches_all_expected_rules(tmp_path: Path) -> None:
    scenarios = sim.build_scenarios()
    source = tmp_path / "events.jsonl"
    dest = tmp_path / "alerts.jsonl"
    source.write_text(
        "\n".join(json.dumps(s.event) for s in scenarios) + "\n", encoding="utf-8"
    )
    summary = scan_jsonl(source, dest)
    assert summary.lines == 4
    assert summary.alerts == 3
    assert summary.ignored == 1
    assert summary.malformed == summary.duplicates == 0


def test_report_contains_only_simulated_result_claims(exercise: Path) -> None:
    report = json.loads((exercise / "case-report.json").read_text(encoding="utf-8"))
    assert report["scope"] == "OFFLINE_FICTIONAL_SIMULATION_ONLY"
    assert report["not_a_confirmed_incident"] is True
    assert [s["result"] for s in report["cases"]] == ["pass"] * 4
    assert [s["analyst_disposition"] for s in report["cases"]] == ["not_triaged"] * 4
    assert report["cases"][-1]["observed_rules"] == []
    assert "not evidence of approval replay" in (exercise / "incident-report.md").read_text(encoding="utf-8")


def test_dashboard_reads_generated_alerts(exercise: Path) -> None:
    loaded = load_alerts(exercise / "alerts.jsonl")
    assert len(loaded.alerts) == 3
    assert not loaded.invalid and not loaded.duplicates
    assert {a.rule_id for a in loaded.alerts} == {
        "CYR-DET-001", "CYR-DET-006", "CYR-DET-007"
    }
    html = (exercise / "dashboard.html").read_text(encoding="utf-8")
    assert "AI Security Monitoring" in html
    assert "CYR-DET-007" in html


def test_evidence_manifest_unsigned_but_hashes_match(exercise: Path) -> None:
    manifest = json.loads((exercise / "evidence-manifest.json").read_text(encoding="utf-8"))
    assert manifest["signed"] is False
    assert set(manifest["files"]) == set(sim.EVIDENCE_NAMES)
    assert sim.verify_evidence(exercise) is True


@pytest.mark.parametrize("filename", sim.EVIDENCE_NAMES)
def test_tampered_evidence_fails_verification(exercise: Path, filename: str) -> None:
    with (exercise / filename).open("a", encoding="utf-8") as handle:
        handle.write("TAMPERED\n")
    assert sim.verify_evidence(exercise) is False


def test_missing_manifest_is_rejected(tmp_path: Path) -> None:
    assert sim.verify_evidence(tmp_path) is False


def test_non_json_manifest_is_rejected(exercise: Path) -> None:
    (exercise / "evidence-manifest.json").write_text("{bad json", encoding="utf-8")
    assert not sim.verify_evidence(exercise)


def test_extra_manifest_file_is_rejected(exercise: Path) -> None:
    manifest_path = exercise / "evidence-manifest.json"
    content = json.loads(manifest_path.read_text(encoding="utf-8"))
    content["files"]["../escape"] = "a" * 64
    manifest_path.write_text(json.dumps(content), encoding="utf-8")
    assert not sim.verify_evidence(exercise)


def test_existing_directory_never_overwritten(exercise: Path) -> None:
    old = (exercise / "case-report.json").read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        sim.run_simulation(exercise)
    assert (exercise / "case-report.json").read_bytes() == old


def test_generated_files_do_not_contain_bearer_or_resource_ids(exercise: Path) -> None:
    for name in (*sim.EVIDENCE_NAMES, "evidence-manifest.json"):
        payload = (exercise / name).read_text(encoding="utf-8")
        assert "CYR-ORDER-1007" not in payload
        assert "CYR-LAB-OPERATOR" not in payload
        assert "CYR-SUP-01" not in payload


def test_secret_fixture_tokens_not_serialized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agent.security.tool_gateway.secrets.token_urlsafe", lambda _n: "FICTIONAL-BEARER-NEVER-SERIALIZE"
    )
    output = tmp_path / "run"
    sim.run_simulation(output)
    for name in (*sim.EVIDENCE_NAMES, "evidence-manifest.json"):
        assert "FICTIONAL-BEARER-NEVER-SERIALIZE" not in (
            output / name
        ).read_text(encoding="utf-8")


def test_cli_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "run"
    assert sim.main(["run", "--output-dir", str(target)]) == 0
    assert json.loads(capsys.readouterr().out)["alerts"] == 3
    assert sim.main(["verify", "--output-dir", str(target)]) == 0
    assert "SHA-256" in capsys.readouterr().out


def test_cli_nonexistent_verification_exits_2(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as outcome:
        sim.main(["verify", "--output-dir", str(tmp_path / "missing")])
    assert outcome.value.code == 2
