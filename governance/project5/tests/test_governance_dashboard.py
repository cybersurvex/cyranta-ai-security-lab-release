"""Project 5.4 — deterministic dashboard, offline controls, and negative cases."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from governance.project5 import assurance_checks as ac
from governance.project5 import governance_dashboard as gd

DATA_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("assets.json", "risks.json", "controls.json"):
        src = DATA_DIR / name
        dest = root / "governance" / "project5" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
    controls = json.loads((DATA_DIR / "controls.json").read_text(encoding="utf-8"))
    for row in controls["controls"]:
        for item in row["evidence"]:
            path = root / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            if item["path_type"] == "directory":
                path.mkdir(exist_ok=True)
            elif not path.exists():
                path.write_text("synthetic test fixture only", encoding="utf-8")
    for files in ac.SUITES.values():
        for item in files:
            path = root / item
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text("def test_placeholder(): assert True\n", encoding="utf-8")
    (root / ".gitignore").write_text("telemetry/governance/\n__pycache__/\n", encoding="utf-8")
    for cmd in (
        ("init", "-q"), ("config", "user.email", "fixture@example.invalid"),
        ("config", "user.name", "Fixture"), ("add", "."),
        ("commit", "-qm", "baseline"),
    ):
        subprocess.run(["git", *cmd], cwd=root, capture_output=True, check=True)
    return root


def _evidence(repo: Path) -> Path:
    return repo / "telemetry" / "governance" / "project5-3"


def _out(repo: Path) -> Path:
    return repo / "telemetry" / "governance" / "project5-4"


def _mock_collect(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ac, "_execute_suite", lambda *_: {
        "status": "passed", "tests": 3, "failures": 0,
        "errors": 0, "skipped": 0, "exit_code": 0,
    })
    ac.collect(repo, _evidence(repo))


def _ci_record(repo: Path, **updates) -> None:
    sha, _ = ac._revision(repo)
    payload = {
        "schema_version": 1,
        "source": "github_cli_live_query_unsigned",
        "run_id": "39624158800",
        "status": "completed",
        "conclusion": "success",
        "event": "push",
        "workflow_name": "security-gate",
        "head_sha": sha,
        "expected_head_sha": sha,
        "revision_matches": True,
        "worktree_clean_at_query": True,
        "reported_success_for_current_clean_head": True,
        "independently_attested": False,
    }
    payload.update(updates)
    path = _evidence(repo) / "ci-observation.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_baseline_without_test_manifest_is_unverified(repo):
    data = gd.snapshot(repo, _evidence(repo))
    assert data["totals"]["assets"] == 5
    assert data["totals"]["controls"] == 7
    assert data["totals"]["evidence_references"] == 20
    assert data["totals"]["evidence_located"] == 20
    assert data["totals"]["open_risks"] == 1
    assert data["totals"]["recorded_passed_suites"] == 0
    assert data["snapshot"]["clean_committed_test_snapshot"] is False
    assert data["snapshot"]["ci_observation"]["state"] == "not_collected"
    assert all(not row["recorded_test_pass"] for row in data["controls"])
    assert all(row["owner"] is None for row in data["controls"])


def test_clean_collected_snapshot_is_local_only(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    data = gd.snapshot(repo, _evidence(repo))
    assert data["snapshot"]["clean_committed_test_snapshot"] is True
    assert data["totals"]["recorded_passed_suites"] == 5
    assert data["totals"]["recorded_tests"] == 15
    control = {item["control_id"]: item for item in data["controls"]}
    assert control["CYR-CTL-001"]["commit_bound_local_test_record"] is True
    assert control["CYR-CTL-006"]["recorded_test_pass"] is False
    assert control["CYR-CTL-006"]["open_linked_risks"] == ["CYRANTA-DEP-001"]
    assert all(not item["control_effectiveness_verified"] for item in data["controls"])
    assert data["compliance_certified"] is False
    assert data["security_assured_release_approved"] is False


def test_valid_ci_is_only_reported_success(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    _ci_record(repo)
    data = gd.snapshot(repo, _evidence(repo))
    assert data["snapshot"]["ci_observation"]["state"] == "github_cli_reported_success_for_current_clean_head"
    assert data["snapshot"]["ci_observation"]["independently_attested"] is False
    assert data["control_effectiveness_verified"] is False


@pytest.mark.parametrize("change", [
    {"status": "in_progress"},
    {"conclusion": "failure"},
    {"event": "pull_request"},
    {"workflow_name": "unreviewed-workflow"},
    {"head_sha": "a" * 40},
    {"expected_head_sha": "a" * 40},
    {"revision_matches": False},
    {"worktree_clean_at_query": False},
    {"reported_success_for_current_clean_head": False},
])
def test_stale_or_mismatched_ci_never_success(repo, change):
    _ci_record(repo, **change)
    result = gd.snapshot(repo, _evidence(repo))
    assert result["snapshot"]["ci_observation"]["state"] == "stale_or_unverified"


@pytest.mark.parametrize("update", [
    {"independently_attested": True},
    {"extra_field": "certified"},
    {"schema_version": 2},
    {"run_id": "1; echo unsafe"},
    {"worktree_clean_at_query": "true"},
])
def test_invalid_ci_metadata_fails_closed(repo, update):
    _ci_record(repo, **update)
    with pytest.raises(gd.DashboardError):
        gd.snapshot(repo, _evidence(repo))


def test_dirty_worktree_invalidates_test_and_ci(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    _ci_record(repo)
    (repo / "untracked.txt").write_text("changed", encoding="utf-8")
    data = gd.snapshot(repo, _evidence(repo))
    assert data["snapshot"]["clean_committed_test_snapshot"] is False
    assert data["snapshot"]["ci_observation"]["state"] == "stale_or_unverified"
    assert all(not row["commit_bound_local_test_record"] for row in data["controls"])


def test_new_commit_invalidates_old_evidence(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    (repo / "CHANGELOG.txt").write_text("next revision", encoding="utf-8")
    subprocess.run(["git", "add", "CHANGELOG.txt"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-qm", "next"], cwd=repo, capture_output=True, check=True)
    data = gd.snapshot(repo, _evidence(repo))
    assert data["snapshot"]["clean_committed_test_snapshot"] is False


def test_tampered_test_manifest_rejected(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    path = _evidence(repo) / "test-evidence.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["suites"]["rag"]["failures"] = 1
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ac.AssuranceError, match="Contradictory"):
        gd.snapshot(repo, _evidence(repo))


def test_changed_registry_rejected_by_manifest(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    path = repo / "governance" / "project5" / "risks.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ac.AssuranceError, match="Registry sources changed"):
        gd.snapshot(repo, _evidence(repo))


def test_missing_evidence_path_remains_gap(repo):
    (repo / "app" / "security.py").unlink()
    data = gd.snapshot(repo, _evidence(repo))
    assert data["totals"]["evidence_missing"] == 1
    assert data["totals"]["evidence_located"] == 19
    assert data["control_effectiveness_verified"] is False


@pytest.mark.parametrize("bad", ["../outside", ".", "telemetry", "telemetry/governance", "telemetry/governance/../secrets"])
def test_unsafe_report_directory_rejected(repo, bad):
    with pytest.raises(gd.DashboardError):
        gd._local_folder(repo, Path(bad))


def test_overlapping_input_output_rejected(repo):
    with pytest.raises(gd.DashboardError, match="overlap"):
        gd.build(repo, _evidence(repo), _evidence(repo))


def test_symlinked_input_file_rejected(repo, tmp_path):
    path = _evidence(repo) / "test-evidence.json"
    path.parent.mkdir(parents=True)
    outside = tmp_path / "evidence.json"
    outside.write_text("{}", encoding="utf-8")
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this Windows host")
    with pytest.raises(gd.DashboardError, match="Symlink"):
        gd.snapshot(repo, _evidence(repo))


def test_symlinked_output_directory_rejected(repo, tmp_path):
    dest = _out(repo)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this Windows host")
    with pytest.raises(gd.DashboardError):
        gd._local_folder(repo, dest)


def test_html_is_inert_and_csp_hash_is_present(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    data = gd.snapshot(repo, _evidence(repo))
    output = gd.render_html(data)
    assert "<script" not in output
    assert "<iframe" not in output
    assert "<img" not in output
    assert "http://" not in output
    assert "https://" not in output
    assert "onclick=" not in output
    assert "style=" not in output
    assert "default-src &#x27;none&#x27;" in output
    assert "style-src &#x27;sha256-" in output
    assert "NO CERTIFICATION, RISK ACCEPTANCE OR RELEASE AUTHORIZATION" in output
    assert "CYRANTA-DEP-001" in output
    assert "PYSEC-" not in output  # Aggregate report deliberately omits advisory details.


def test_html_escapes_untrusted_referents(repo):
    data = gd.snapshot(repo, _evidence(repo))
    altered = copy.deepcopy(data)
    altered["controls"][0]["title"] = '<img src=x onerror="alert(1)">'
    document = gd.render_html(altered)
    assert '<img src=x onerror' not in document
    assert '&lt;img src=x onerror' in document


def test_build_is_deterministic_and_offline(repo, monkeypatch):
    _mock_collect(repo, monkeypatch)
    result = gd.build(repo, _evidence(repo), _out(repo))
    assert result["controls"] == 7
    assert result["open_risks"] == 1
    assert result["clean_committed_test_snapshot"] is True
    files = ["audit-summary.json", "audit-report.md", "governance-dashboard.html"]
    previous = [(_out(repo) / name).read_bytes() for name in files]
    gd.build(repo, _evidence(repo), _out(repo))
    assert previous == [(_out(repo) / name).read_bytes() for name in files]
    summary = json.loads((_out(repo) / files[0]).read_text(encoding="utf-8"))
    assert summary["security_assured_release_approved"] is False
    assert summary["compliance_certified"] is False
    assert "control_effectiveness_verified" in summary
    assert "CYRANTA-DEP-001" in (_out(repo) / files[1]).read_text(encoding="utf-8")
    assert "NO CERTIFICATION" in (_out(repo) / files[2]).read_text(encoding="utf-8")


def test_build_without_manifest_is_clear_gap(repo):
    result = gd.build(repo, _evidence(repo), _out(repo))
    assert result["recorded_passed_suites"] == 0
    assert result["ci_observation"] == "not_collected"
    assert result["clean_committed_test_snapshot"] is False


def test_cli_validate_and_build(repo, capsys):
    assert gd.main(["validate", "--repo-root", str(repo)]) == 0
    assert json.loads(capsys.readouterr().out)["controls"] == 7
    assert gd.main(["build", "--repo-root", str(repo)]) == 0
    assert json.loads(capsys.readouterr().out)["open_risks"] == 1


def test_cli_fails_without_leaking_traceback(repo, capsys):
    code = gd.main(["build", "--repo-root", str(repo), "--output-dir", "../outside"])
    assert code == 2
    captured = capsys.readouterr()
    assert "Governance dashboard failed" in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""


def test_module_does_not_access_raw_telemetry_or_network():
    source = (DATA_DIR / "governance_dashboard.py").read_text(encoding="utf-8")
    assert "subprocess.run" not in source
    assert "import requests" not in source
    assert "import urllib" not in source
    assert "telemetry/events.jsonl" not in source
    assert "LOG_RAW_CONTENT" not in source
