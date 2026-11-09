"""Project 6.2 isolated contract checks, negative cases and unsigned-record validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from validation.project6 import runner, schema

ROOT = Path(__file__).resolve().parents[3]
SHA = "a" * 40


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(runner, "_folder", lambda _root, _output: tmp_path)
    monkeypatch.setattr(runner.ac, "_revision", lambda _root: (SHA, True))
    return tmp_path


def _load(path: Path) -> dict:
    return json.loads((path / "execution-evidence.json").read_text(encoding="utf-8"))


def _save(path: Path, data: dict) -> None:
    (path / "execution-evidence.json").write_text(json.dumps(data) + "\n", encoding="utf-8")


@pytest.mark.parametrize("sid", tuple(schema.SPECS))
def test_six_real_adapters_return_pass(sid: str) -> None:
    assert runner._execute(sid) == {
        "scenario_id": sid,
        "assertion_id": schema.SPECS[sid]["assertion_id"],
        "expected_decision": schema.SPECS[sid]["expected_decision"],
        "observed_decision": schema.SPECS[sid]["expected_decision"],
        "status": "passed",
        "reason_code": "condition_matched",
        "evidence_scope": "offline_local_contract_with_simulated_rag_storage",
    }


def test_runner_calls_real_chatbot_guards() -> None:
    assert runner._chatbot_direct() is True
    assert runner._chatbot_encoded() is True


def test_runner_calls_real_rag_filters() -> None:
    assert runner._rag_access() is True
    assert runner._rag_trust() is True


def test_runner_calls_agent_and_monitor() -> None:
    assert runner._agent_denial() is True
    assert runner._monitor_alert() is True


@pytest.mark.parametrize("sid", tuple(schema.SPECS))
def test_failed_assertion_fail_closed(monkeypatch: pytest.MonkeyPatch, sid: str) -> None:
    monkeypatch.setitem(runner.CHECKS, sid, lambda: False)
    result = runner._execute(sid)
    assert result["status"] == "failed"
    assert result["observed_decision"] == "not_established"
    assert result["reason_code"] == "condition_not_met"


@pytest.mark.parametrize("sid", tuple(schema.SPECS))
def test_exception_does_not_leak_payload(monkeypatch: pytest.MonkeyPatch, sid: str) -> None:
    def boom() -> bool:
        raise RuntimeError("SENSITIVE_ATTACK_STRING_NEVER_EXPORT")

    monkeypatch.setitem(runner.CHECKS, sid, boom)
    result = runner._execute(sid)
    assert result["status"] == "error"
    assert "SENSITIVE_ATTACK_STRING_NEVER_EXPORT" not in json.dumps(result)


def test_local_query_filters_do_not_return_quarantined_or_hr_docs() -> None:
    records = [
        {"document_id": "hr", "metadata": {"allow_employee": False, "trust_level": "trusted"}},
        {"document_id": "quarantine", "metadata": {"allow_employee": True, "trust_level": "quarantined"}},
        {"document_id": "public", "metadata": {"allow_employee": True, "trust_level": "trusted"}},
    ]
    calls = []
    fake = runner._fake_query(records, calls)
    returned = fake("x", n_results=3, where={"$and": [{"allow_employee": True}, {"trust_level": "trusted"}]})
    assert [x["document_id"] for x in returned] == ["public"]


@pytest.mark.parametrize("where", [None, {"allow_hr": True}, {"$or": []}, {}])
def test_wrong_rag_filter_cannot_satisfy_trusted_query(where: dict | None) -> None:
    assert runner._where_match({"allow_employee": True, "trust_level": "trusted"}, where) is (where is None)


def test_run_persists_only_allowlisted_observations(isolated: Path) -> None:
    result = runner.run(ROOT)
    assert result["passed"] == 6 and result["failed"] == 0
    record = _load(isolated)
    assert record.keys() == runner.RECORD_FIELDS
    assert record["totals"] == {"scenarios": 6, "passed": 6, "failed": 0}
    assert len(record["catalogue_sha256"]) == 12
    assert len(record["source_sha256"]) == len(runner.SOURCE_FILES)
    assert record["open_registered_risks"] == 1
    assert record["live_attacks_executed"] is False
    assert record["security_assured_release_approved"] is False
    text = json.dumps(record)
    for disallowed in ("CYR-DEMO-KEY-FAKE", "UNTRUSTED_DOCUMENT_INSTRUCTION_MARKER", "SENSITIVE_ATTACK_STRING"):
        assert disallowed not in text


def test_report_reads_own_evidence_and_preserves_disclaimers(isolated: Path) -> None:
    runner.run(ROOT)
    summary = runner.report(ROOT)
    assert summary["passed"] == 6
    assert summary["clean_committed_local_record"] is True
    assert summary["independently_attested"] is False
    assert summary["control_effectiveness_verified"] is False
    text = (isolated / "execution-report.md").read_text(encoding="utf-8")
    assert "UNSIGNED LOCAL RECORD" in text
    assert "no Chroma" in text


def test_stale_revision_does_not_match(monkeypatch: pytest.MonkeyPatch, isolated: Path) -> None:
    runner.run(ROOT)
    monkeypatch.setattr(runner.ac, "_revision", lambda _root: ("b" * 40, True))
    report = runner.report(ROOT)
    assert report["revision_matches"] is False
    assert report["clean_committed_local_record"] is False


def test_dirty_snapshot_does_not_match(monkeypatch: pytest.MonkeyPatch, isolated: Path) -> None:
    runner.run(ROOT)
    monkeypatch.setattr(runner.ac, "_revision", lambda _root: (SHA, False))
    assert runner.report(ROOT)["clean_committed_local_record"] is False


def test_dirty_capture_does_not_match(monkeypatch: pytest.MonkeyPatch, isolated: Path) -> None:
    monkeypatch.setattr(runner.ac, "_revision", lambda _root: (SHA, False))
    runner.run(ROOT)
    assert runner.report(ROOT)["clean_committed_local_record"] is False


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2),
    ("kind", "independent_attestation"), ("head_sha", "bad"),
    ("independently_attested", True), ("control_effectiveness_verified", True),
    ("compliance_certified", True), ("security_assured_release_approved", True),
    ("live_attacks_executed", True), ("worktree_clean_at_run", "true"),
    ("open_registered_risks", 0), ("totals", {"scenarios": 6, "passed": 6, "failed": 1}),
])
def test_tampered_evidence_rejected(isolated: Path, field: str, value: object) -> None:
    runner.run(ROOT)
    record = _load(isolated)
    record[field] = value
    _save(isolated, record)
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


@pytest.mark.parametrize("field,value", [
    ("scenario_id", "CYR-P6-SCN-900"),
    ("assertion_id", "fake_verification"),
    ("expected_decision", "allow"),
    ("status", "approved"),
    ("reason_code", "signed"),
    ("observed_decision", "allow"),
    ("evidence_scope", "live_attested"),
    ("status", []),
    ("reason_code", {}),
])
def test_tampered_scenario_rejected(isolated: Path, field: str, value: object) -> None:
    runner.run(ROOT)
    record = _load(isolated)
    record["scenario_results"][0][field] = value
    _save(isolated, record)
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


def test_added_field_rejected(isolated: Path) -> None:
    runner.run(ROOT)
    record = _load(isolated)
    record["approved_by"] = "fabricated"
    _save(isolated, record)
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


def test_missing_scenario_rejected(isolated: Path) -> None:
    runner.run(ROOT)
    record = _load(isolated)
    record["scenario_results"].pop()
    _save(isolated, record)
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


def test_duplicate_json_keys_rejected(isolated: Path) -> None:
    runner.run(ROOT)
    text = (isolated / "execution-evidence.json").read_text(encoding="utf-8")
    (isolated / "execution-evidence.json").write_text(text.replace('"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'), encoding="utf-8")
    with pytest.raises(ValueError):
        runner.report(ROOT)


def test_wrong_hashes_rejected(isolated: Path) -> None:
    runner.run(ROOT)
    record = _load(isolated)
    record["source_sha256"]["app/security.py"] = "0" * 64
    _save(isolated, record)
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


def test_missing_record_rejected(isolated: Path) -> None:
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


def test_oversized_record_rejected(isolated: Path) -> None:
    (isolated / "execution-evidence.json").write_bytes(b"A" * (runner.MAX_RECORD_BYTES + 1))
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


def test_error_result_does_not_look_like_pass(monkeypatch: pytest.MonkeyPatch, isolated: Path) -> None:
    monkeypatch.setitem(runner.CHECKS, "CYR-P6-SCN-001", lambda: False)
    result = runner.run(ROOT)
    assert result["passed"] == 5 and result["failed"] == 1
    report = runner.report(ROOT)
    assert report["failed"] == 1
    assert _load(isolated)["scenario_results"][0]["observed_decision"] == "not_established"


def test_cli_plan(capsys: pytest.CaptureFixture[str]) -> None:
    assert runner.main(["plan", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["execution"] == "not_started"


def test_cli_run_failure_exit_is_nonzero(monkeypatch: pytest.MonkeyPatch, isolated: Path, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setitem(runner.CHECKS, "CYR-P6-SCN-001", lambda: False)
    assert runner.main(["run", "--repo-root", str(ROOT)]) == 1
    assert json.loads(capsys.readouterr().out)["failed"] == 1


def test_cli_report_missing_record_exit_is_nonzero(isolated: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert runner.main(["report", "--repo-root", str(ROOT)]) == 2
    assert "validation failed" in capsys.readouterr().err


def test_cli_run_success(monkeypatch: pytest.MonkeyPatch, isolated: Path, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(runner, "CHECKS", {sid: (lambda: True) for sid in schema.SPECS})
    assert runner.main(["run", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["passed"] == 6


def test_unknown_adapter_exception_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    def noisy() -> bool:
        raise OSError("never_print_local_secret")

    monkeypatch.setitem(runner.CHECKS, "CYR-P6-SCN-002", noisy)
    assert runner._execute("CYR-P6-SCN-002")["reason_code"] == "adapter_error"


def test_boolean_true_only_means_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(runner.CHECKS, "CYR-P6-SCN-001", lambda: 1)
    assert runner._execute("CYR-P6-SCN-001")["status"] == "failed"


def test_source_file_inventory_is_fixed() -> None:
    assert set(runner.SOURCE_FILES) >= {"app/security.py", "rag/app/retriever.py", "agent/security/tool_gateway.py", "monitoring/detector.py"}
    assert len(runner._catalogue_paths()) == 12


def test_path_escape_rejected() -> None:
    with pytest.raises((runner.gd.DashboardError, runner.RunnerError)):
        runner._folder(ROOT, ROOT.parent / "escape")


def test_symlinked_record_rejected(isolated: Path, tmp_path: Path) -> None:
    destination = tmp_path / "outside.json"
    destination.write_text("{}", encoding="utf-8")
    link = isolated / "execution-evidence.json"
    try:
        link.symlink_to(destination)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not available")
    with pytest.raises(runner.RunnerError):
        runner.report(ROOT)


def test_missing_dependency_fails_record_not_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable() -> bool:
        raise ImportError("chromadb unavailable")

    monkeypatch.setitem(runner.CHECKS, "CYR-P6-SCN-003", unavailable)
    result = runner._execute("CYR-P6-SCN-003")
    assert result["status"] == "error"
    assert result["observed_decision"] == "not_established"


def test_expected_status_not_used_as_observed_shortcut(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(runner.CHECKS, "CYR-P6-SCN-006", lambda: False)
    actual = runner._execute("CYR-P6-SCN-006")
    assert actual["expected_decision"] == "alert"
    assert actual["observed_decision"] == "not_established"


def test_module_does_not_forge_signed_attestation(isolated: Path) -> None:
    runner.run(ROOT)
    record = _load(isolated)
    assert not record["independently_attested"]
    assert not record["control_effectiveness_verified"]
    assert not record["security_assured_release_approved"]
    assert all(row["evidence_scope"] == "offline_local_contract_with_simulated_rag_storage" for row in record["scenario_results"])


def test_no_external_calls_from_scenarios(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    def no_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected external HTTP call")

    monkeypatch.setattr(httpx, "post", no_network)
    for check in runner.CHECKS.values():
        assert check() is True
