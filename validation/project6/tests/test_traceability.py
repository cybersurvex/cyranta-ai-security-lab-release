"""Project 6.4: source-bound, fail-closed offline governance crosswalk tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from validation.project6 import traceability as t

ROOT = Path(__file__).resolve().parents[3]
SHA = "a" * 40


@pytest.fixture
def local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    output = tmp_path / "fresh"
    monkeypatch.setattr(t, "_folder", lambda _root, _out: output)
    monkeypatch.setattr(t.ac, "_revision", lambda _root: (SHA, True))
    return output


@pytest.fixture
def isolated_repo(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A disposable copy of only reviewed metadata; never edit real source."""
    out = tmp_path / "reviewed"
    for rel in (*t.REGISTRIES, *t.DOCUMENTS,
                "validation/project6/schema.py", "validation/project6/runner.py",
                "validation/project6/correlation.py", "validation/project6/traceability.py"):
        src = ROOT / rel
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    for rel in ("validation/project6/scenarios", "validation/project6/fixtures"):
        shutil.copytree(ROOT / rel, out / rel)
    monkeypatch.setattr(t.ac, "_revision", lambda _root: (SHA, True))
    return out


def _read(local: Path, filename: str = "traceability-index.json") -> dict:
    return json.loads((local / filename).read_text(encoding="utf-8"))


def _write(local: Path, filename: str, data: dict) -> None:
    (local / filename).write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")


def _rehash(local: Path, filename: str) -> None:
    manifest = _read(local, "evidence-manifest.json")
    manifest["files_sha256"][filename] = t.ac._hash(local / filename)
    _write(local, "evidence-manifest.json", manifest)


def test_source_archive_references_are_all_allowlisted() -> None:
    assert len(t.FINDINGS) == 3
    assert len(t.DOCUMENTS) == 6
    assert len(t.SOURCES) == 13
    assert len(set(t.SOURCES)) == len(t.SOURCES)
    assert t.RISK_ID == "CYRANTA-DEP-001"


def test_plan_validates_actual_registry_and_documents() -> None:
    assets, risks, controls = t._inputs(ROOT)
    assert (len(assets["assets"]), len(risks["risks"]), len(controls["controls"])) == (5, 1, 7)


@pytest.mark.parametrize("fid", list(t.FINDINGS))
def test_finding_narratives_are_separate_from_risks(fid: str) -> None:
    records = t._records(*t._inputs(ROOT))
    record = next(row for row in records if row["record_id"] == fid)
    assert record["record_kind"] == "historical_finding_document"
    assert record["registered_risk_ids"] == []
    assert record["link_basis"] == "proposed_narrative_to_control_crosswalk_unapproved"
    assert record["human_review_required"] is True
    assert record["incident_finding_link_verified"] is False
    assert record["control_effectiveness_verified"] is False


def test_dependency_risk_is_registry_declared_and_open() -> None:
    rows = t._records(*t._inputs(ROOT))
    assert len(rows) == 4
    risk = rows[-1]
    assert risk["record_id"] == t.RISK_ID
    assert risk["registered_risk_ids"] == [t.RISK_ID]
    assert risk["control_ids"] == ["CYR-CTL-006", "CYR-CTL-007"]
    assert risk["link_basis"] == "explicit_project5_control_risk_ids"


def test_build_creates_only_allowlisted_sanitized_artifacts(local: Path) -> None:
    result = t.build(ROOT)
    assert result["historical_finding_documents"] == 3
    assert result["traceability_records"] == 4
    assert result["registered_open_risks"] == 1
    assert result["controls_needing_human_review"] == 7
    assert result["unassigned_asset_owners"] == 5
    assert result["unassigned_control_owners"] == 7
    assert result["approved_finding_control_links"] == 0
    assert {p.name for p in local.iterdir()} == {*t.OUTPUTS, "evidence-manifest.json"}
    index = _read(local)
    assert index["synthetic_project6_3_cases_linked_to_findings"] == 0
    assert index["risk_decisions_changed"] is False
    assert index["scenario_manifests_modified"] is False
    assert index["summary"]["registered_open_risks"] == 1
    assert all(index[key] is False for key in t.FORBIDDEN_ASSURANCE)
    output = "".join(p.read_text(encoding="utf-8") for p in local.iterdir())
    for secret in ("CYR-ORDER-1007", "CYR-DEMO-KEY-FAKE", "CYR-REFUND-0001",
                   "transcript.txt", "3ec28ef1-c193"):
        assert secret not in output


def test_verify_clean_local_snapshot_without_independent_attestation(local: Path) -> None:
    t.build(ROOT)
    result = t.verify(ROOT)
    assert result["revision_matches"] is True
    assert result["clean_committed_local_record"] is True
    assert result["registered_risk_still_open"] is True
    assert result["independently_attested"] is False
    assert result["control_effectiveness_verified"] is False
    assert result["security_assured_release_approved"] is False


def test_report_distinguishes_claims_from_verification(local: Path) -> None:
    t.build(ROOT)
    text = (local / "traceability-report.md").read_text(encoding="utf-8")
    assert "UNSIGNED LOCAL CROSSWALK" in text
    assert "human" in text.lower()
    assert "raw execution logs" in text
    assert "No Project 6.3 synthetic incident candidate" in text
    assert "risk remains open" in text


def test_repeated_build_cannot_overwrite(local: Path) -> None:
    t.build(ROOT)
    previous = (local / "evidence-manifest.json").read_bytes()
    with pytest.raises(t.TraceabilityError):
        t.build(ROOT)
    assert (local / "evidence-manifest.json").read_bytes() == previous


@pytest.mark.parametrize("filename", [*t.OUTPUTS, "evidence-manifest.json"])
def test_removed_evidence_fails_closed(local: Path, filename: str) -> None:
    t.build(ROOT)
    (local / filename).unlink()
    with pytest.raises((t.TraceabilityError, ValueError, OSError)):
        t.verify(ROOT)


@pytest.mark.parametrize("filename", [*t.OUTPUTS])
def test_changed_evidence_hash_fails(local: Path, filename: str) -> None:
    t.build(ROOT)
    with (local / filename).open("a", encoding="utf-8") as out:
        out.write("FORGED_APPROVAL")
    with pytest.raises(t.TraceabilityError):
        t.verify(ROOT)


@pytest.mark.parametrize("field,value", [
    ("signed", True), ("kind", "independent_attestation"),
    ("schema_version", 2), ("schema_version", True),
    ("source_commit", "not-a-hash"), ("source_sha256", {}),
    ("files_sha256", {}),
])
def test_tampered_manifest_rejected(local: Path, field: str, value: object) -> None:
    t.build(ROOT)
    manifest = _read(local, "evidence-manifest.json")
    manifest[field] = value
    _write(local, "evidence-manifest.json", manifest)
    with pytest.raises(t.TraceabilityError):
        t.verify(ROOT)


@pytest.mark.parametrize("field,value", [
    ("kind", "approved_controls"), ("schema_version", 2),
    ("worktree_clean_at_capture", "true"),
    ("risk_decisions_changed", True),
    ("incident_finding_link_verified", True),
    ("retest_artifacts_independently_inspected", True),
    ("independently_attested", True),
    ("control_effectiveness_verified", True),
    ("compliance_certified", True),
    ("security_assured_release_approved", True),
    ("synthetic_project6_3_cases_linked_to_findings", 2),
])
def test_modified_index_rejected_even_with_updated_hash(local: Path, field: str, value: object) -> None:
    t.build(ROOT)
    index = _read(local)
    index[field] = value
    _write(local, t.OUTPUTS[0], index)
    _rehash(local, t.OUTPUTS[0])
    with pytest.raises(t.TraceabilityError):
        t.verify(ROOT)


@pytest.mark.parametrize("field,value", [
    ("control_ids", ["CYR-CTL-006"]),
    ("asset_ids", ["CYR-AST-005"]),
    ("registered_risk_ids", ["CYRANTA-DEP-001"]),
    ("link_basis", "approved_control_assignment"),
    ("human_review_required", False),
])
def test_finding_link_forgery_rejected_even_with_new_hash(local: Path, field: str, value: object) -> None:
    t.build(ROOT)
    index = _read(local)
    index["records"][0][field] = value
    _write(local, t.OUTPUTS[0], index)
    _rehash(local, t.OUTPUTS[0])
    with pytest.raises(t.TraceabilityError):
        t.verify(ROOT)


def test_report_rewrite_with_new_hash_is_still_rejected(local: Path) -> None:
    t.build(ROOT)
    (local / t.OUTPUTS[1]).write_text("# CERTIFIED RELEASE", encoding="utf-8")
    _rehash(local, t.OUTPUTS[1])
    with pytest.raises(t.TraceabilityError):
        t.verify(ROOT)


def test_missing_source_fails_closed(monkeypatch: pytest.MonkeyPatch, isolated_repo: Path) -> None:
    (isolated_repo / t.FINDINGS["CYR-LLM-002"]["documents"][0]).unlink()
    with pytest.raises(t.TraceabilityError):
        t._inputs(isolated_repo)


def test_swapped_finding_identity_is_rejected(isolated_repo: Path) -> None:
    path = isolated_repo / "findings/CYR-DET-003.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("# CYR-DET-003", "# CYR-LLM-002", 1), encoding="utf-8")
    with pytest.raises(t.TraceabilityError):
        t._inputs(isolated_repo)


def test_changed_risk_registration_fails(isolated_repo: Path) -> None:
    path = isolated_repo / "governance/project5/risks.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["risks"][0]["status"] = "closed"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError):
        t._inputs(isolated_repo)


def test_modified_control_risk_link_fails(isolated_repo: Path) -> None:
    path = isolated_repo / "governance/project5/controls.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["controls"][5]["risk_ids"] = []
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(t.TraceabilityError):
        t._records(*t._inputs(isolated_repo))


def test_source_change_invalidates_previous_hashes(monkeypatch: pytest.MonkeyPatch,
                                                     local: Path, isolated_repo: Path) -> None:
    t.build(isolated_repo)
    doc = isolated_repo / "findings/CYR-DET-003.md"
    doc.write_text(doc.read_text(encoding="utf-8") + "\nLocal edit\n", encoding="utf-8")
    with pytest.raises(t.TraceabilityError):
        t.verify(isolated_repo)


def test_unsafe_output_rejected() -> None:
    with pytest.raises(t.gd.DashboardError):
        t._folder(ROOT, ROOT.parent / "unsafe")


def test_unallowlisted_source_rejected() -> None:
    with pytest.raises(t.TraceabilityError):
        t._source(ROOT, ".env")


def test_source_symlink_rejected(isolated_repo: Path) -> None:
    path = isolated_repo / "findings/CYR-DET-003.md"
    path.unlink()
    try:
        path.symlink_to(ROOT / "findings/CYR-DET-003.md")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable")
    with pytest.raises((t.TraceabilityError, t.ac.AssuranceError)):
        t._source(isolated_repo, "findings/CYR-DET-003.md")


def test_evidence_symlink_rejected(local: Path, tmp_path: Path) -> None:
    t.build(ROOT)
    path = local / "evidence-manifest.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    try:
        path.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(t.TraceabilityError):
        t.verify(ROOT)


def test_oversized_manifest_rejected(local: Path) -> None:
    t.build(ROOT)
    (local / "evidence-manifest.json").write_bytes(b"A" * (t.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(t.TraceabilityError):
        t.verify(ROOT)


def test_duplicate_manifest_keys_rejected(local: Path) -> None:
    t.build(ROOT)
    path = local / "evidence-manifest.json"
    path.write_text(path.read_text(encoding="utf-8").replace(
        '"schema_version": 1,', '"schema_version": 1, "schema_version": 1,', 1,
    ), encoding="utf-8")
    with pytest.raises(ValueError):
        t.verify(ROOT)


@pytest.mark.parametrize("clean,expected", [(True, True), (False, False)])
def test_clean_capture_requires_clean_now(monkeypatch: pytest.MonkeyPatch, local: Path,
                                          clean: bool, expected: bool) -> None:
    t.build(ROOT)
    monkeypatch.setattr(t.ac, "_revision", lambda _root: (SHA, clean))
    assert t.verify(ROOT)["clean_committed_local_record"] is expected


def test_changed_head_does_not_match(monkeypatch: pytest.MonkeyPatch, local: Path) -> None:
    t.build(ROOT)
    monkeypatch.setattr(t.ac, "_revision", lambda _root: ("b" * 40, True))
    result = t.verify(ROOT)
    assert result["revision_matches"] is False
    assert result["clean_committed_local_record"] is False


def test_dirty_capture_does_not_claim_clean(monkeypatch: pytest.MonkeyPatch, local: Path) -> None:
    monkeypatch.setattr(t.ac, "_revision", lambda _root: (SHA, False))
    t.build(ROOT)
    assert t.verify(ROOT)["clean_committed_local_record"] is False


def test_plan_cli_does_not_write(monkeypatch: pytest.MonkeyPatch,
                                 local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert t.main(["plan", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["assurance_approved"] is False
    assert not local.exists()


def test_build_verify_cli(monkeypatch: pytest.MonkeyPatch,
                          local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert t.main(["build", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["traceability_records"] == 4
    assert t.main(["verify", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["clean_committed_local_record"] is True


def test_missing_report_cli_fails_without_file_text(monkeypatch: pytest.MonkeyPatch,
                                                    local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert t.main(["verify", "--repo-root", str(ROOT)]) == 2
    output = capsys.readouterr()
    assert "traceability failed" in output.err
    assert "C:\\" not in output.err


def test_duplicate_build_cli_exits_nonzero(monkeypatch: pytest.MonkeyPatch,
                                            local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    t.build(ROOT)
    assert t.main(["build", "--repo-root", str(ROOT)]) == 2
    assert "traceability failed" in capsys.readouterr().err
