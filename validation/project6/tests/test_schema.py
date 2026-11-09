"""Project 6.1 scenario manifest validation and malicious-input rejection."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from validation.project6 import schema

SOURCE_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Isolated fixture with original Project 5 declarations."""
    root = tmp_path / "cyranta"
    for name in ("assets.json", "risks.json", "controls.json"):
        src = SOURCE_ROOT / "governance" / "project5" / name
        dest = root / "governance" / "project5" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
    for folder in ("scenarios", "fixtures"):
        for src in (SOURCE_ROOT / schema.ROOT / folder).glob("*.json"):
            dest = root / schema.ROOT / folder / src.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
    return root


def _path(repo: Path, sid: str, folder: str = "scenarios") -> Path:
    return repo / schema.ROOT / folder / f"{sid}.json"


def _mutate(repo: Path, sid: str, changes: dict, folder: str = "scenarios") -> None:
    path = _path(repo, sid, folder)
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(changes)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_baseline_is_six_only_and_never_approved(repo: Path) -> None:
    assert schema.validate(repo) == {
        "scenario_count": 6, "scenarios_not_run": 6,
        "synthetic_metadata_fixtures": 6, "live_attacks_executed": False,
        "control_effectiveness_verified": False, "risk_decisions_changed": False,
        "open_registered_risks": 1, "security_assured_release_approved": False,
        "compliance_certified": False,
    }


def test_cli_validate_and_list(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert schema.main(["validate", "--repo-root", str(repo)]) == 0
    assert json.loads(capsys.readouterr().out)["scenarios_not_run"] == 6
    assert schema.main(["list", "--repo-root", str(repo)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result["scenarios"]) == 6
    assert all(row["execution_status"] == "not_run" for row in result["scenarios"])
    assert {row["scenario_id"] for row in result["scenarios"]} == set(schema.SPECS)


def test_cli_errors_sanitized(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _path(repo, "CYR-P6-SCN-001").unlink()
    assert schema.main(["validate", "--repo-root", str(repo)]) == 2
    out = capsys.readouterr()
    assert "Scenario catalogue failed" in out.err
    assert "Traceback" not in out.err


@pytest.mark.parametrize("sid", list(schema.SPECS))
def test_each_scenario_is_frozen_and_synthetic(repo: Path, sid: str) -> None:
    scenario = json.loads(_path(repo, sid).read_text(encoding="utf-8"))
    fixture = json.loads(_path(repo, sid, "fixtures").read_text(encoding="utf-8"))
    assert scenario["execution_status"] == "not_run"
    assert scenario["finding_id"] is None
    assert scenario["registered_risk_ids"] == []
    assert fixture["synthetic"] is True
    assert fixture["contains_live_payload"] is False
    assert schema.validate(repo)["scenario_count"] == 6


@pytest.mark.parametrize("field,value", [
    ("scenario_id", "CYR-P6-SCN-999"),
    ("scenario_type", "malicious_override"),
    ("asset_ids", ["CYR-AST-999"]),
    ("asset_ids", ["CYR-AST-001", "CYR-AST-001"]),
    ("control_ids", ["CYR-CTL-999"]),
    ("control_ids", ["CYR-CTL-006"]),
    ("control_ids", ["CYR-CTL-001", "CYR-CTL-001"]),
    ("fixture_id", "unreviewed-fixture"),
    ("expected_decision", "allow"),
    ("assertion_id", "automatically_certify"),
    ("mode", "live_external_target"),
    ("execution_status", "passed"),
    ("finding_id", "CYR-LLM-001"),
    ("registered_risk_ids", ["CYRANTA-DEP-001"]),
    ("human_review_required", False),
    ("human_review_required", 1),
    ("title", "Forged | Status"),
    ("title", "Fake\nApproved"),
    ("schema_version", True),
    ("schema_version", "1"),
    ("schema_version", 2),
])
def test_scenario_unreviewed_values_rejected(repo: Path, field: str, value: object) -> None:
    _mutate(repo, "CYR-P6-SCN-001", {field: copy.deepcopy(value)})
    with pytest.raises(schema.ScenarioError):
        schema.validate(repo)


@pytest.mark.parametrize("bad_path", [
    "../.env", "C:\\Users\\me\\.env", "validation/project6/fixtures/../../.env",
    "/etc/passwd", "validation/project6/fixtures/CYR-P6-SCN-002.json",
    "validation/project6/scenarios/CYR-P6-SCN-001.json",
    "validation/project6/fixtures/.env", "validation/project6/fixtures/CYR-P6-SCN-001.json/other",
])
def test_unsafe_fixture_paths_rejected(repo: Path, bad_path: str) -> None:
    _mutate(repo, "CYR-P6-SCN-001", {"fixture_path": bad_path})
    with pytest.raises(schema.ScenarioError):
        schema.validate(repo)


@pytest.mark.parametrize("field,value", [
    ("fixture_id", "arbitrary"),
    ("scenario_id", "CYR-P6-SCN-999"),
    ("fixture_kind", "live_api_prompt"),
    ("input_class", "user_supplied"),
    ("expected_signal", "production_action"),
    ("synthetic", False),
    ("synthetic", 1),
    ("contains_live_payload", True),
    ("schema_version", 2),
])
def test_fixture_unreviewed_values_rejected(repo: Path, field: str, value: object) -> None:
    _mutate(repo, "CYR-P6-SCN-003", {field: value}, "fixtures")
    with pytest.raises(schema.ScenarioError):
        schema.validate(repo)


@pytest.mark.parametrize("folder", ["fixtures", "scenarios"])
def test_unexpected_file_rejected(repo: Path, folder: str) -> None:
    (repo / schema.ROOT / folder / "CYR-P6-SCN-007.json").write_text("{}")
    with pytest.raises(schema.ScenarioError, match="Unexpected file count"):
        schema.validate(repo)


@pytest.mark.parametrize("folder", ["fixtures", "scenarios"])
def test_missing_file_rejected(repo: Path, folder: str) -> None:
    _path(repo, "CYR-P6-SCN-005", folder).unlink()
    with pytest.raises(schema.ScenarioError, match="Unexpected file count"):
        schema.validate(repo)


def test_duplicate_scenario_id_cannot_be_claimed(repo: Path) -> None:
    _mutate(repo, "CYR-P6-SCN-002", {"scenario_id": "CYR-P6-SCN-001"})
    with pytest.raises(schema.ScenarioError):
        schema.validate(repo)


@pytest.mark.parametrize("folder", ["fixtures", "scenarios"])
def test_duplicate_json_keys_rejected(repo: Path, folder: str) -> None:
    path = _path(repo, "CYR-P6-SCN-001", folder)
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(schema.ScenarioError, match="Duplicate JSON key"):
        schema.validate(repo)


@pytest.mark.parametrize("content", [b"{bad", b"\xff\xfe", b'{"x": NaN}', b'[]'])
def test_invalid_or_nonobject_json_rejected(repo: Path, content: bytes) -> None:
    _path(repo, "CYR-P6-SCN-003").write_bytes(content)
    with pytest.raises(schema.ScenarioError):
        schema.validate(repo)


def test_oversized_file_rejected(repo: Path) -> None:
    _path(repo, "CYR-P6-SCN-001").write_bytes(b" " * (schema.MAX_JSON_BYTES + 1))
    with pytest.raises(schema.ScenarioError, match="oversized"):
        schema.validate(repo)


@pytest.mark.parametrize("folder", ["fixtures", "scenarios"])
def test_symlinked_metadata_rejected(repo: Path, folder: str, tmp_path: Path) -> None:
    target = _path(repo, "CYR-P6-SCN-001", folder)
    target.unlink()
    external = tmp_path / f"external-{folder}.json"
    external.write_text("{}", encoding="utf-8")
    try:
        target.symlink_to(external)
    except OSError:
        pytest.skip("Windows symlink permissions are unavailable")
    with pytest.raises(schema.ScenarioError):
        schema.validate(repo)


def test_symlinked_fixture_directory_rejected(repo: Path, tmp_path: Path) -> None:
    fixture_dir = repo / schema.ROOT / "fixtures"
    moved = tmp_path / "moved-fixtures"
    fixture_dir.rename(moved)
    try:
        fixture_dir.symlink_to(moved, target_is_directory=True)
    except OSError:
        pytest.skip("Windows directory symlink permissions are unavailable")
    with pytest.raises(schema.ScenarioError, match="symlinked"):
        schema.validate(repo)


def test_project5_risk_decision_cannot_be_forged(repo: Path) -> None:
    path = repo / "governance/project5/risks.json"
    data = json.loads(path.read_text())
    data["risks"][0]["decision"] = "accepted"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        schema.validate(repo)


def test_project5_control_owner_cannot_be_assigned_silently(repo: Path) -> None:
    path = repo / "governance/project5/controls.json"
    data = json.loads(path.read_text())
    data["controls"][0]["owner"] = "unverified"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        schema.validate(repo)


def test_unreviewed_approval_field_rejected(repo: Path) -> None:
    path = _path(repo, "CYR-P6-SCN-001")
    data = json.loads(path.read_text())
    data["certified"] = True
    path.write_text(json.dumps(data))
    with pytest.raises(schema.ScenarioError, match="schema"):
        schema.validate(repo)


def test_no_execution_or_risk_writes_in_source() -> None:
    code = (SOURCE_ROOT / "validation/project6/schema.py").read_text(encoding="utf-8")
    assert "subprocess" not in code
    assert "import requests" not in code
    assert "shell=True" not in code
    assert "open(" not in code
    assert "_atomic_write" not in code
    assert "telemetry/events.jsonl" not in code
