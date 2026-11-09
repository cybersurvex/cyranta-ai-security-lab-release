"""Project 5.3: offline fixtures, local pytest capture, and tamper failures."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from governance.project5 import assurance_checks as ac

DATA_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "test-repo"
    root.mkdir()
    source_root = DATA_DIR
    for name in ("assets.json", "risks.json", "controls.json"):
        target = root / "governance" / "project5" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / name, target)
    for paths in ac.SUITES.values():
        for item in paths:
            target = root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("def test_placeholder():\n    assert True\n", encoding="utf-8")
    (root / ".gitignore").write_text("telemetry/governance/\n.pytest_cache/\n__pycache__/\n*.pyc\n", encoding="utf-8")
    commands = (("init", "-q"), ("config", "user.email", "local@example.invalid"),
                ("config", "user.name", "Local CI Fixture"), ("add", "."),
                ("commit", "-qm", "synthetic fixture"))
    for args in commands:
        subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)
    return root


def _out(repo: Path) -> Path:
    return repo / "telemetry" / "governance" / "p53"


def _artifact(repo: Path) -> Path:
    return _out(repo) / "test-evidence.json"


def _write_artifact(repo: Path, record: dict) -> None:
    _artifact(repo).write_text(json.dumps(record), encoding="utf-8")


def test_plan_is_allowlisted():
    assert len(ac.SUITES) == 5
    assert len(ac.CONTROL_SUITES) == 7
    assert ac.CONTROL_SUITES["CYR-CTL-006"] == ()
    assert all(path.startswith(("tests/", "rag/tests/", "agent/tests/", "monitoring/tests/", "governance/project5/tests/"))
               for paths in ac.SUITES.values() for path in paths)


def test_registry_baseline(repo):
    assets, risks, catalogue = ac._registry(repo)
    assert len(assets["assets"]) == 5
    assert len(risks["risks"]) == 1
    assert len(catalogue["controls"]) == 7


def test_real_pytest_groups_and_report(repo):
    summary = ac.collect(repo, _out(repo), timeout=25)
    assert summary["passed_suites"] == 5
    assert summary["recorded_tests"] == sum(len(p) for p in ac.SUITES.values())
    assert summary["worktree_clean_at_capture"] is True
    report = ac.report(repo, _out(repo))
    assert report["clean_committed_snapshot"] is True
    assert report["open_registered_risks"] == 1
    assert report["control_effectiveness_verified"] is False
    assert report["security_assured_release_approved"] is False
    assert report["ci_observation"] == "not_collected"
    payload = json.loads((_out(repo) / "assurance-summary.json").read_text())
    controls = {c["control_id"]: c for c in payload["control_checks"]}
    assert controls["CYR-CTL-001"]["recorded_test_pass"] is True
    assert controls["CYR-CTL-006"]["recorded_test_pass"] is False
    assert all(c["effectiveness_verified"] is False for c in controls.values())
    assert "NOT APPROVED" not in (_out(repo) / "assurance-report.md").read_text()
    assert "NO ASSURANCE OR RELEASE APPROVAL" in (_out(repo) / "assurance-report.md").read_text()


def test_capture_no_raw_test_output(repo):
    target = repo / ac.SUITES["chatbot"][0]
    target.write_text('def test_ok():\n    print("PRIVATE_PROBE_DO_NOT_STORE")\n    assert True\n', encoding="utf-8")
    ac.collect(repo, _out(repo), timeout=25)
    for path in _out(repo).iterdir():
        assert "PRIVATE_PROBE_DO_NOT_STORE" not in path.read_text(encoding="utf-8")
        assert path.suffix != ".xml"


def test_missing_test_path_reported(repo):
    (repo / ac.SUITES["rag"][0]).unlink()
    item = ac._execute_suite(repo, "rag", 15)
    assert item["status"] == "missing"
    assert item["exit_code"] is None


def test_failing_test_records_failed_not_pass(repo):
    (repo / ac.SUITES["agent"][0]).write_text(
        "def test_bad():\n    assert False\n", encoding="utf-8")
    item = ac._execute_suite(repo, "agent", 25)
    assert item["status"] == "failed"
    assert item["failures"] == 1


def test_skipped_test_not_recorded_as_pass(repo):
    (repo / ac.SUITES["agent"][0]).write_text(
        "import pytest\n@pytest.mark.skip\ndef test_skipped():\n    pass\n", encoding="utf-8")
    item = ac._execute_suite(repo, "agent", 25)
    assert item["status"] == "failed"
    assert item["skipped"] == 1


@pytest.mark.parametrize("xml", [
    "invalid", "<testsuites></testsuites>",
    "<!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><testsuite></testsuite>",
    "<user><testcase/></user>",
])
def test_rejects_invalid_junit(repo, xml):
    path = repo / "junit.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(ac.AssuranceError):
        ac._junit_counts(path)


def test_rejects_oversized_junit(repo):
    path = repo / "junit.xml"
    path.write_bytes(b" " * (ac.MAX_JUNIT_BYTES + 1))
    with pytest.raises(ac.AssuranceError, match="oversized"):
        ac._junit_counts(path)


@pytest.mark.parametrize("path", ["../.env", ".env", "/tmp/bad", "rag//secret", "a/../b", "C:\\private"])
def test_unsafe_source_path_rejected(repo, path):
    with pytest.raises(ac.AssuranceError):
        ac._in_repo(repo, path)


def test_output_must_be_local_and_nested(repo):
    with pytest.raises(ac.AssuranceError):
        ac._destination(repo, repo / "telemetry" / "governance")
    with pytest.raises(ac.AssuranceError):
        ac._destination(repo, repo.parent)


def test_invalid_timeout(repo):
    with pytest.raises(ac.AssuranceError, match="Timeout"):
        ac.collect(repo, _out(repo), timeout=0)


def test_symlinked_file_rejected(repo, tmp_path):
    path = repo / ac.SUITES["agent"][0]
    path.unlink()
    outside = tmp_path / "outside.py"
    outside.write_text("def test_x(): assert True\n")
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks requires Windows privileges on this host")
    with pytest.raises(ac.AssuranceError):
        ac._suite_hashes(repo)


def test_source_changed_requires_new_collection(repo, monkeypatch):
    _fake_collect(repo, monkeypatch)
    data = repo / "governance" / "project5" / "controls.json"
    data.write_text(data.read_text() + "\n", encoding="utf-8")
    with pytest.raises(ac.AssuranceError, match="Registry sources changed"):
        ac.report(repo, _out(repo))


def test_test_file_changed_requires_new_collection(repo, monkeypatch):
    _fake_collect(repo, monkeypatch)
    path = repo / ac.SUITES["chatbot"][0]
    path.write_text(path.read_text() + "\n", encoding="utf-8")
    with pytest.raises(ac.AssuranceError, match="Test files changed"):
        ac.report(repo, _out(repo))


def _fake_collect(repo, monkeypatch):
    monkeypatch.setattr(ac, "_execute_suite", lambda *_: {
        "status": "passed", "tests": 1, "failures": 0, "errors": 0,
        "skipped": 0, "exit_code": 0,
    })
    return ac.collect(repo, _out(repo))


def test_stale_git_commit_not_matched(repo, monkeypatch):
    _fake_collect(repo, monkeypatch)
    (repo / "CHANGELOG").write_text("new revision\n", encoding="utf-8")
    subprocess.run(["git", "add", "CHANGELOG"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "change"], cwd=repo, check=True)
    data = ac.report(repo, _out(repo))
    assert data["clean_committed_snapshot"] is False


def test_dirty_capture_never_clean_snapshot(repo, monkeypatch):
    (repo / "WIP").write_text("untracked\n", encoding="utf-8")
    _fake_collect(repo, monkeypatch)
    assert ac.report(repo, _out(repo))["clean_committed_snapshot"] is False


def test_unexpected_suite_rejected(repo, monkeypatch):
    _fake_collect(repo, monkeypatch)
    record = json.loads(_artifact(repo).read_text())
    record["suites"]["malicious_extra"] = record["suites"]["rag"]
    _write_artifact(repo, record)
    with pytest.raises(ac.AssuranceError, match="suite identifiers"):
        ac.report(repo, _out(repo))


def test_contradictory_pass_rejected(repo, monkeypatch):
    _fake_collect(repo, monkeypatch)
    record = json.loads(_artifact(repo).read_text())
    record["suites"]["rag"]["failures"] = 1
    _write_artifact(repo, record)
    with pytest.raises(ac.AssuranceError, match="Contradictory"):
        ac.report(repo, _out(repo))


def test_malformed_manifest_rejected(repo):
    _out(repo).mkdir(parents=True)
    _artifact(repo).write_text("not JSON", encoding="utf-8")
    with pytest.raises((ac.AssuranceError, ValueError)):
        ac.report(repo, _out(repo))


def test_no_manifest_rejected(repo):
    with pytest.raises(ac.AssuranceError, match="collect first"):
        ac.report(repo, _out(repo))


def test_broken_catalogue_never_runs_tests(repo, monkeypatch):
    catalogue = repo / "governance" / "project5" / "controls.json"
    data = json.loads(catalogue.read_text())
    data["controls"][0]["review_status"] = "approved"
    catalogue.write_text(json.dumps(data))
    monkeypatch.setattr(ac, "_execute_suite", lambda *_: pytest.fail("must not run"))
    with pytest.raises(ValueError):
        ac.collect(repo, _out(repo))


@pytest.mark.parametrize("run_id", ["0", "-1", "abc", "1;echo x", "1" * 20])
def test_bad_run_id_rejected(repo, run_id):
    with pytest.raises(ac.AssuranceError, match="run ID"):
        ac.ci_check(repo, _out(repo), run_id=run_id)


def _mock_gh(monkeypatch, sha):
    original = ac.subprocess.run
    def caller(cmd, **kwargs):
        if cmd[:3] == ["gh", "run", "view"]:
            data = {"status": "completed", "conclusion": "success",
                    "headSha": sha, "event": "push", "workflowName": "security-gate"}
            return SimpleNamespace(returncode=0, stdout=json.dumps(data), stderr="")
        return original(cmd, **kwargs)
    monkeypatch.setattr(ac.subprocess, "run", caller)


def test_ci_query_for_current_head_not_attested(repo, monkeypatch):
    sha, _ = ac._revision(repo)
    _mock_gh(monkeypatch, sha)
    outcome = ac.ci_check(repo, _out(repo), run_id="39299690492")
    assert outcome["revision_matches"] is True
    assert outcome["reported_success_for_current_clean_head"] is True
    assert outcome["independently_attested"] is False


def test_old_ci_run_must_not_cover_feature_commit(repo, monkeypatch):
    _mock_gh(monkeypatch, "a" * 40)
    outcome = ac.ci_check(repo, _out(repo), run_id="39299690492")
    assert outcome["revision_matches"] is False
    assert outcome["reported_success_for_current_clean_head"] is False


def test_ci_matching_head_but_dirty_still_unverified(repo, monkeypatch):
    sha, _ = ac._revision(repo)
    _mock_gh(monkeypatch, sha)
    (repo / "UNCOMMITTED").write_text("not tracked\n")
    assert not ac.ci_check(repo, _out(repo), run_id="39299690492")[
        "reported_success_for_current_clean_head"]


def test_ci_query_metadata_in_report(repo, monkeypatch):
    _fake_collect(repo, monkeypatch)
    sha, _ = ac._revision(repo)
    _mock_gh(monkeypatch, sha)
    ac.ci_check(repo, _out(repo), run_id="39299690492")
    result = ac.report(repo, _out(repo))
    assert result["ci_observation"] == "github_cli_reported_success_for_current_clean_head"
    assert result["security_assured_release_approved"] is False


def test_main_plan_succeeds(repo, capsys):
    assert ac.main(["plan", "--repo-root", str(repo)]) == 0
    assert len(json.loads(capsys.readouterr().out)["suite_groups"]) == 5


def test_main_report_missing_evidence_exits_cleanly(repo, capsys):
    assert ac.main(["report", "--repo-root", str(repo)]) == 2
    response = capsys.readouterr()
    assert "collect first" in response.err
    assert "Traceback" not in response.err


def test_missing_suites_return_exit_three(repo, monkeypatch, capsys):
    monkeypatch.setattr(ac, "_execute_suite", lambda *_: {
        "status": "missing", "tests": 0, "failures": 0,
        "errors": 0, "skipped": 0, "exit_code": None,
    })
    assert ac.main(["collect", "--repo-root", str(repo)]) == 3
    assert json.loads(capsys.readouterr().out)["passed_suites"] == 0


def test_output_path_cannot_escape(repo):
    with pytest.raises(ac.AssuranceError):
        ac._destination(repo, Path("../outside"))


def test_report_records_open_risk_and_unassigned_controls(repo, monkeypatch):
    _fake_collect(repo, monkeypatch)
    result = ac.report(repo, _out(repo))
    assert result["controls_needing_human_review"] == 7
    assert result["compliance_certified"] is False
    payload = json.loads((_out(repo) / "assurance-summary.json").read_text())
    assert "CYRANTA-DEP-001" in (_out(repo) / "assurance-report.md").read_text()
    assert payload["control_checks"][-1]["review_status"] == "needs_human_review"
    assert all(not row["effectiveness_verified"] for row in payload["control_checks"])


def test_no_executable_user_supplied_commands():
    source = (DATA_DIR / "assurance_checks.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "eval(" not in source
    assert "telemetry/events.jsonl" not in source
    assert "LOG_RAW_CONTENT" not in source
