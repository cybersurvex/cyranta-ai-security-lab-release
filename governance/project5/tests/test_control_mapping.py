"""Project 5.2: deterministic offline mapping and deliberate negative tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from governance.project5.control_mapping import (
    MappingError,
    assess,
    generate_report,
    main,
    validate_mapping,
)
from governance.project5.registry import RegistryError, _read_json

DATA_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample() -> tuple[dict, dict, dict]:
    def load(name: str) -> dict:
        return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))

    return load("controls.json"), load("assets.json"), load("risks.json")


@pytest.fixture
def repo(tmp_path: Path, sample: tuple[dict, dict, dict]) -> Path:
    catalogue, assets, risks = sample
    for name, data in (("controls.json", catalogue), ("assets.json", assets), ("risks.json", risks)):
        dest = tmp_path / "governance" / "project5" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(data), encoding="utf-8")
    for control in catalogue["controls"]:
        for evidence in control["evidence"]:
            dest = tmp_path / evidence["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            if evidence["path_type"] == "directory":
                dest.mkdir(exist_ok=True)
            elif not dest.exists():
                dest.write_text("synthetic test fixture only", encoding="utf-8")
    return tmp_path


def _source_paths(repo: Path) -> tuple[Path, Path, Path]:
    base = repo / "governance" / "project5"
    return base / "controls.json", base / "assets.json", base / "risks.json"


def test_seven_control_baseline_no_approval(sample):
    catalogue, assets, risks = sample
    result = validate_mapping(catalogue, assets, risks)
    assert result == {
        "controls": 7, "evidence_references": 20,
        "controls_needing_human_review": 7,
        "controls_with_declared_gaps": 7,
        "unassigned_control_owners": 7,
        "open_registered_risks": 1,
        "security_assured_release_approved": False,
        "compliance_certified": False,
    }


def test_frameworks_are_broad_functions_not_clause_claims(sample):
    catalogue, _, _ = sample
    assert all(row["nist_ai_rmf_functions"] for row in catalogue["controls"])
    assert all(row["iso_42001_theme"] for row in catalogue["controls"])
    assert all(row["owner"] is None for row in catalogue["controls"])
    assert not any("42001:" in json.dumps(row) for row in catalogue["controls"])


def test_open_dependency_risk_linked_to_controls(sample):
    catalogue, _, _ = sample
    mapping = {row["control_id"]: row for row in catalogue["controls"]}
    assert "CYRANTA-DEP-001" in mapping["CYR-CTL-006"]["risk_ids"]
    assert "CYRANTA-DEP-001" in mapping["CYR-CTL-007"]["risk_ids"]


def test_presence_is_not_effectiveness(sample, repo):
    catalogue, assets, risks = sample
    result = assess(catalogue, assets, risks, repo)
    summary = result["summary"]
    assert summary["evidence_located"] == 20
    assert summary["evidence_missing"] == 0
    assert summary["evidence_untrusted"] == 0
    assert summary["effectiveness_verified"] is False
    assert all(row["effectiveness_verified"] is False for row in result["controls"])
    assert all(row["review_status"] == "needs_human_review" for row in result["controls"])


def test_missing_evidence_reported_without_assurance(sample, repo):
    catalogue, assets, risks = sample
    target = repo / "app" / "security.py"
    target.unlink()
    result = assess(catalogue, assets, risks, repo)
    assert result["summary"]["evidence_missing"] == 1
    assert result["summary"]["effectiveness_verified"] is False


def test_directory_must_be_directory(sample, repo):
    catalogue, assets, risks = sample
    directory = repo / "rag" / "app"
    directory.rmdir()
    directory.write_text("not a directory", encoding="utf-8")
    result = assess(catalogue, assets, risks, repo)
    assert result["summary"]["evidence_missing"] == 1


def test_file_must_be_file(sample, repo):
    catalogue, assets, risks = sample
    target = repo / "app" / "security.py"
    target.unlink()
    target.mkdir()
    assert assess(catalogue, assets, risks, repo)["summary"]["evidence_missing"] == 1


def test_symlink_to_external_target_not_trusted(sample, repo, tmp_path):
    catalogue, assets, risks = sample
    evidence = repo / "app" / "security.py"
    evidence.unlink()
    outside = tmp_path.parent / "untrusted-evidence-outside-repo.tmp"
    outside.write_text("untrusted", encoding="utf-8")
    try:
        evidence.symlink_to(outside)
        result = assess(catalogue, assets, risks, repo)
        assert result["summary"]["evidence_untrusted"] == 1
    finally:
        outside.unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("key", "invalid"),
    [
        ("control_id", "CYR-CTL-ABC"),
        ("title", "Evil | Markdown"),
        ("title", "Bad\nline"),
        ("iso_42001_theme", "A.1.2 compliant"),
        ("owner", "fake risk officer"),
        ("review_status", "approved"),
        ("known_gaps", []),
        ("known_gaps", ["Missing", "Missing"]),
        ("known_gaps", ["Vulnerable | etc"]),
        ("asset_ids", ["CYR-AST-999"]),
        ("asset_ids", ["CYR-AST-001", "CYR-AST-001"]),
        ("risk_ids", ["CYRANTA-DEP-999"]),
        ("nist_ai_rmf_functions", ["COMPLIANT"]),
        ("nist_ai_rmf_functions", ["MAP", "MAP"]),
    ],
)
def test_invalid_control_fields_are_rejected(sample, key, invalid):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"][0][key] = invalid
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


@pytest.mark.parametrize("bad", ["../.env", "/etc/passwd", "C:\\secrets", "app//security.py", "app/./main.py", "app/../../.env", "app/a|b.py", "app/a\nb.py", ".env"])
def test_unsafe_evidence_paths_rejected(sample, bad):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"][0]["evidence"][0]["path"] = bad
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


@pytest.mark.parametrize("key,value", [("kind", "passed"), ("path_type", "remote"), ("kind", [])])
def test_unsupported_evidence_metadata_rejected(sample, key, value):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"][0]["evidence"][0][key] = value
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


def test_repeated_evidence_rejected(sample):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"][0]["evidence"].append(copy.deepcopy(catalogue["controls"][0]["evidence"][0]))
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


def test_duplicate_control_id_rejected(sample):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"].append(copy.deepcopy(catalogue["controls"][0]))
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


def test_extra_unreviewed_control_field_rejected(sample):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"][0]["certified"] = True
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


def test_extra_evidence_field_rejected(sample):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"][0]["evidence"][0]["content"] = "sensitive"
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


@pytest.mark.parametrize("bad", [False, "1", 2, 1.0, None])
def test_schema_version_rejected(sample, bad):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["schema_version"] = bad
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


def test_empty_catalogue_rejected(sample):
    catalogue, assets, risks = copy.deepcopy(sample)
    catalogue["controls"] = []
    with pytest.raises(MappingError):
        validate_mapping(catalogue, assets, risks)


def test_registry_must_remain_unaccepted(sample):
    catalogue, assets, risks = copy.deepcopy(sample)
    risks["risks"][0]["decision"] = "accepted"
    with pytest.raises(RegistryError, match="Risk resolution"):
        validate_mapping(catalogue, assets, risks)


def test_report_is_deterministic_and_sanitized(sample, repo):
    catalogue, assets, risks = sample
    catalogue_path, assets_path, risks_path = _source_paths(repo)
    output = repo / "telemetry" / "governance" / "p52"
    summary1 = generate_report(
        catalogue, assets, risks, repo, catalogue_path, assets_path, risks_path, output
    )
    files = (output / "control-summary.json", output / "control-mapping.md")
    first = tuple(path.read_bytes() for path in files)
    summary2 = generate_report(
        catalogue, assets, risks, repo, catalogue_path, assets_path, risks_path, output
    )
    assert summary1 == summary2
    assert first == tuple(path.read_bytes() for path in files)
    report = json.loads(files[0].read_text(encoding="utf-8"))
    assert report["summary"]["controls"] == 7
    assert len(report["source_sha256"]["catalogue"]) == 64
    assert all(not row["effectiveness_verified"] for row in report["controls"])
    assert "CERTIFICATION OR RELEASE APPROVAL" in files[1].read_text(encoding="utf-8")
    assert ".env" not in files[1].read_text(encoding="utf-8")


def test_report_refuses_external_output_dir(sample, repo, tmp_path):
    catalogue, assets, risks = sample
    paths = _source_paths(repo)
    with pytest.raises(MappingError, match="telemetry/governance"):
        generate_report(catalogue, assets, risks, repo, *paths, tmp_path.parent)


def test_report_refuses_governance_root_dir(sample, repo):
    catalogue, assets, risks = sample
    paths = _source_paths(repo)
    with pytest.raises(MappingError, match="run-name"):
        generate_report(catalogue, assets, risks, repo, *paths, repo / "telemetry" / "governance")


def test_cli_validate_and_report_without_external_connections(repo, capsys):
    code = main(["validate", "--repo-root", str(repo)])
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["controls"] == 7
    code = main(["report", "--repo-root", str(repo)])
    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["evidence_located"] == 20
    assert (repo / "telemetry" / "governance" / "project5-2" / "control-mapping.md").is_file()


def test_cli_rejects_registry_input_outside_repo(repo, tmp_path, capsys):
    outside = tmp_path.parent / "outside-cyranta.txt"
    outside.write_text("x", encoding="utf-8")
    try:
        code = main(["validate", "--repo-root", str(repo), "--catalogue", str(outside)])
        assert code == 2
        output = capsys.readouterr()
        assert "under repository root" in output.err
        assert "Traceback" not in output.err
    finally:
        outside.unlink(missing_ok=True)


def test_duplicate_json_keys_rejected(repo):
    source = repo / "governance" / "project5" / "controls.json"
    source.write_text('{"schema_version":1,"schema_version":1,"controls":[]}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        _read_json(source)


def test_source_module_does_not_request_network_or_read_raw_telemetry():
    module = (DATA_DIR / "control_mapping.py").read_text(encoding="utf-8")
    assert "import requests" not in module
    assert "import urllib" not in module
    assert "telemetry/events.jsonl" not in module
    assert "LOG_RAW_CONTENT" not in module
