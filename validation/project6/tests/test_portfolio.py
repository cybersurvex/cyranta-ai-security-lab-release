"""Project 6.5: fail-closed workflow boundaries and unsigned portfolio tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from validation.project6 import portfolio as p

ROOT = Path(__file__).resolve().parents[3]
SHA = "a" * 40


@pytest.fixture
def local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    folder = tmp_path / "fresh"
    monkeypatch.setattr(p, "_folder", lambda _root, _out: folder)
    monkeypatch.setattr(p.ac, "_revision", lambda _root: (SHA, True))
    return folder


def _load(folder: Path, name: str) -> dict:
    return json.loads((folder / name).read_text(encoding="utf-8"))


def _write(folder: Path, name: str, data: dict) -> None:
    (folder / name).write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")


def _rehash(folder: Path, name: str) -> None:
    manifest = _load(folder, "evidence-manifest.json")
    manifest["files_sha256"][name] = p.ac._hash(folder / name)
    _write(folder, "evidence-manifest.json", manifest)


def _change(monkeypatch: pytest.MonkeyPatch, path: str, new_text: str) -> None:
    real = p._read_source
    monkeypatch.setattr(p, "_read_source",
                        lambda root, relative: new_text if relative == path else real(root, relative))


def _hosted() -> str:
    return p._read_source(ROOT, ".github/workflows/ci.yml")


def test_reviewed_sources_and_scope() -> None:
    assert len(p.SOURCES) == len(set(p.SOURCES))
    assert ".env" not in p.SOURCES
    assert len(p.FORBIDDEN_APPROVALS) == len(set(p.FORBIDDEN_APPROVALS))
    assert p.DEFAULT_OUTPUT == Path("telemetry/governance/project6-5")


def test_policy_check_is_read_only_and_offline() -> None:
    before = set(ROOT.iterdir())
    outcome = p.check(ROOT)
    assert set(ROOT.iterdir()) == before
    assert outcome["runtime_model_called"] is False
    assert outcome["scope"] == "offline_ci_and_declarative_governance_only"
    assert outcome["dependency_risk_decision"] == "pending_review"
    assert outcome["dependency_rag_audit_in_green_gate"] is False
    assert all(outcome[field] is False for field in p.FORBIDDEN_APPROVALS)


def test_workflow_boundaries_match_original_intent() -> None:
    result = p._workflow_guard(ROOT)
    assert all(result.values())
    assert p._job_names(_hosted()) == ["deterministic-security-gate"]
    assert p._yaml_events(_hosted()) == {"push", "pull_request"}
    assert result["public_hosted_ci_only"] is True
    assert result["private_runner_workflow_absent"] is True
    assert result["raw_local_redteam_evidence_absent"] is True


def test_governance_uses_registry_not_fabricated_incidents() -> None:
    out = p._governance(ROOT)
    assert out["scenario_manifest_count"] == 6
    assert out["scenario_manifests_not_run"] == 6
    assert out["historical_finding_documents"] == 3
    assert out["synthetic_incidents_confirmed"] == 0
    assert out["approved_finding_control_links"] == 0
    assert out["registered_open_dependency_risks"] == 1
    assert out["unassigned_assets"] == 5
    assert out["unassigned_controls"] == 7


@pytest.mark.parametrize("malicious", [
    "pull_request_target:", "workflow_run:", "repository_dispatch:",
    "schedule:", "secrets.MY_TOKEN",
])
def test_unsafe_hosted_event_or_secret_fails(monkeypatch: pytest.MonkeyPatch, malicious: str) -> None:
    _change(monkeypatch, ".github/workflows/ci.yml", _hosted() + "\n" + malicious)
    with pytest.raises(p.PortfolioError):
        p._workflow_guard(ROOT)


@pytest.mark.parametrize("needle,replacement", [
    ("persist-credentials: false", "persist-credentials: true"),
    ("contents: read", "contents: write"),
    ("runs-on: ubuntu-latest", "runs-on: self-hosted"),
    ("pull_request:", "workflow_dispatch:"),
    ("      - main", "      - development"),
    ("uses: actions/checkout@v4", "uses: actions/checkout@v1"),
    ("bash scripts/security_gate.sh", "echo skipped"),
])
def test_hosted_regression_fails(monkeypatch: pytest.MonkeyPatch,
                                needle: str, replacement: str) -> None:
    before = _hosted()
    assert needle in before
    _change(monkeypatch, ".github/workflows/ci.yml", before.replace(needle, replacement, 1))
    with pytest.raises(p.PortfolioError):
        p._workflow_guard(ROOT)


@pytest.mark.parametrize("filename", [
    "local-redteam.yml", "untrusted.yml", "extra.yaml", "dispatch.yml",
    "ci-backup.yml", "deploy.yml", "workflow.txt", "private-runner.yml",
])
def test_public_edition_rejects_additional_workflow(tmp_path: Path, filename: str) -> None:
    directory = tmp_path / ".github/workflows"
    directory.mkdir(parents=True)
    (directory / "ci.yml").write_text(_hosted(), encoding="utf-8")
    (directory / filename).write_text("name: Unreviewed\n", encoding="utf-8")
    with pytest.raises(p.PortfolioError):
        p._workflow_guard(tmp_path)


@pytest.mark.parametrize("malicious", [
    "self-hosted", "local_redteam_gate.ps1", "11434", "actions/upload-artifact@v4",
])
def test_public_hosted_ci_rejects_private_boundary(monkeypatch: pytest.MonkeyPatch,
                                                   malicious: str) -> None:
    _change(monkeypatch, ".github/workflows/ci.yml", _hosted() + "\n# " + malicious)
    with pytest.raises(p.PortfolioError):
        p._workflow_guard(ROOT)


@pytest.mark.parametrize("replacement", [
    "LAB_FAKE_SECRET=not-approved\n", "API_KEY=actual-key\n",
    "OLLAMA_MODEL=internal-private-model\n", "LOG_RAW_CONTENT=true\n",
    "OLLAMA_BASE_URL=http://public-endpoint.invalid\n",
])
def test_public_env_template_fails_if_changed(monkeypatch: pytest.MonkeyPatch,
                                              replacement: str) -> None:
    _change(monkeypatch, ".env.example", p.PUBLIC_ENV_EXAMPLE + replacement)
    with pytest.raises(p.PortfolioError):
        p.check(ROOT)


def test_public_placeholder_example_exact() -> None:
    assert p._read_source(ROOT, ".env.example") == p.PUBLIC_ENV_EXAMPLE


def test_public_sources_exclude_private_workflow() -> None:
    assert ".github/workflows/local-redteam.yml" not in p.SOURCES
    assert ".env.example" in p.SOURCES
    assert "docs/phase7/PUBLIC-EDITION-REVIEW.md" in p.SOURCES


@pytest.mark.parametrize("private_path", [
    "scripts/local_redteam_gate.ps1",
    "results/local-redteam/raw-results.json",
])
def test_public_edition_rejects_private_runner_files(tmp_path: Path, private_path: str) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(_hosted(), encoding="utf-8")
    target = tmp_path / private_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("fictional local-only fixture", encoding="utf-8")
    with pytest.raises(p.PortfolioError):
        p._workflow_guard(tmp_path)


@pytest.mark.parametrize("needle", [
    "set -euo pipefail", "python -m compileall -q", "ruff check .",
    "python -m validation.project6.portfolio check", "python -m pytest -q",
    "bandit -q -r", "validation/project6/portfolio.py",
    "pip-audit -r requirements.txt", "pip-audit -r requirements-agent.txt",
])
def test_gate_step_removed_fails(monkeypatch: pytest.MonkeyPatch, needle: str) -> None:
    before = p._read_source(ROOT, "scripts/security_gate.sh")
    assert needle in before
    _change(monkeypatch, "scripts/security_gate.sh", before.replace(needle, "removed", 1))
    with pytest.raises(p.PortfolioError):
        p._gate_guard(ROOT)


def test_unreviewed_rag_audit_not_silently_declared_green(monkeypatch: pytest.MonkeyPatch) -> None:
    before = p._read_source(ROOT, "scripts/security_gate.sh")
    _change(monkeypatch, "scripts/security_gate.sh", before + "\npip-audit -r requirements-rag.txt\n")
    with pytest.raises(p.PortfolioError):
        p._gate_guard(ROOT)


def test_missing_portfolio_navigation_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    before = p._read_source(ROOT, "README.md")
    _change(monkeypatch, "README.md", before.replace("PORTFOLIO-AND-REPRODUCIBILITY.md", "removed"))
    with pytest.raises(p.PortfolioError):
        p.check(ROOT)


def test_unallowlisted_secret_path_fails() -> None:
    with pytest.raises(p.PortfolioError):
        p._source(ROOT, ".env")


def test_unapproved_dependency_risk_closure_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    original = p.traceability._inputs

    def modified(root: Path):
        assets, risks, controls = original(root)
        risks["risks"][0]["status"] = "closed"
        return assets, risks, controls

    monkeypatch.setattr(p.traceability, "_inputs", modified)
    with pytest.raises(p.PortfolioError):
        p.check(ROOT)


def test_unapproved_owner_change_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    original = p.traceability._inputs

    def modified(root: Path):
        assets, risks, controls = original(root)
        assets["assets"][0]["owner"] = "self-appointed"
        return assets, risks, controls

    monkeypatch.setattr(p.traceability, "_inputs", modified)
    with pytest.raises(p.PortfolioError):
        p.check(ROOT)


def test_build_creates_only_three_reports(local: Path) -> None:
    result = p.build(ROOT)
    assert result["scenario_manifests"] == 6
    assert result["registered_open_risks"] == 1
    assert result["security_assured_release_approved"] is False
    assert {file.name for file in local.iterdir()} == {*p.OUTPUTS, "evidence-manifest.json"}
    index = _load(local, "portfolio-index.json")
    assert index["dependency_risk_accepted"] is False
    assert index["matching_postmerge_github_ci_verified"] is False
    text = (local / "portfolio-summary.md").read_text(encoding="utf-8")
    assert "UNSIGNED LOCAL REVIEW" in text
    assert "ChromaDB" in text
    assert "attestation" in text
    assert "CYR-DEMO-KEY-FAKE-7F4C2A" not in text


def test_clean_fixture_verification_without_independent_attestation(local: Path) -> None:
    p.build(ROOT)
    result = p.verify(ROOT)
    assert result["revision_matches"] is True
    assert result["clean_committed_local_record"] is True
    assert result["registered_risk_still_open"] is True
    assert result["matching_postmerge_github_ci_verified"] is False
    assert result["control_effectiveness_verified"] is False
    assert result["independently_attested"] is False


def test_build_refuses_overwrite(local: Path) -> None:
    p.build(ROOT)
    before = (local / "portfolio-summary.md").read_bytes()
    with pytest.raises(p.PortfolioError):
        p.build(ROOT)
    assert (local / "portfolio-summary.md").read_bytes() == before


@pytest.mark.parametrize("name", [*p.OUTPUTS, "evidence-manifest.json"])
def test_missing_report_rejected(local: Path, name: str) -> None:
    p.build(ROOT)
    (local / name).unlink()
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


@pytest.mark.parametrize("name", [*p.OUTPUTS])
def test_hash_mismatch_rejected(local: Path, name: str) -> None:
    p.build(ROOT)
    with (local / name).open("a", encoding="utf-8") as f:
        f.write("FORGED RELEASE APPROVAL")
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


@pytest.mark.parametrize("field,value", [
    ("signed", True), ("source_commit", "not-a-sha"),
    ("kind", "independent_attestation"), ("schema_version", True),
    ("schema_version", 2), ("source_sha256", {}), ("files_sha256", {}),
])
def test_manifest_tamper_fails(local: Path, field: str, value: object) -> None:
    p.build(ROOT)
    document = _load(local, "evidence-manifest.json")
    document[field] = value
    _write(local, "evidence-manifest.json", document)
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


@pytest.mark.parametrize("field,value", [
    ("independently_attested", True),
    ("security_assured_release_approved", True),
    ("dependency_risk_accepted", True),
    ("matching_postmerge_github_ci_verified", True),
    ("production_ready", True),
    ("worktree_clean_at_capture", "true"),
    ("governance", {}),
])
def test_forged_report_rejected_with_updated_hash(local: Path, field: str, value: object) -> None:
    p.build(ROOT)
    document = _load(local, p.OUTPUTS[0])
    document[field] = value
    _write(local, p.OUTPUTS[0], document)
    _rehash(local, p.OUTPUTS[0])
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


def test_rewritten_markdown_with_updated_hash_is_rejected(local: Path) -> None:
    p.build(ROOT)
    (local / p.OUTPUTS[1]).write_text("# CERTIFIED PRODUCTION", encoding="utf-8")
    _rehash(local, p.OUTPUTS[1])
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


def test_changed_source_hash_rejected(local: Path) -> None:
    p.build(ROOT)
    manifest = _load(local, "evidence-manifest.json")
    manifest["source_sha256"][".github/workflows/local-redteam.yml"] = "0" * 64
    _write(local, "evidence-manifest.json", manifest)
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


def test_dirty_current_tree_is_not_clean_verification(local: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p.build(ROOT)
    monkeypatch.setattr(p.ac, "_revision", lambda _root: (SHA, False))
    assert p.verify(ROOT)["clean_committed_local_record"] is False


def test_different_current_revision_does_not_match(local: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p.build(ROOT)
    monkeypatch.setattr(p.ac, "_revision", lambda _root: ("b" * 40, True))
    result = p.verify(ROOT)
    assert result["revision_matches"] is False
    assert result["clean_committed_local_record"] is False


def test_dirty_capture_cannot_claim_clean(local: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(p.ac, "_revision", lambda _root: (SHA, False))
    p.build(ROOT)
    assert p.verify(ROOT)["clean_committed_local_record"] is False


def test_symlink_manifest_rejected(local: Path, tmp_path: Path) -> None:
    p.build(ROOT)
    path = local / "evidence-manifest.json"
    data = path.read_bytes()
    path.unlink()
    target = tmp_path / "outside.json"
    target.write_bytes(data)
    try:
        path.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


def test_oversized_manifest_rejected(local: Path) -> None:
    p.build(ROOT)
    (local / "evidence-manifest.json").write_bytes(b"A" * (p.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(p.PortfolioError):
        p.verify(ROOT)


def test_unsafely_located_output_rejected() -> None:
    with pytest.raises(p.gd.DashboardError):
        p._folder(ROOT, ROOT.parent / "unsafe")


def test_cli_check_has_no_file_output(local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert p.main(["check", "--repo-root", str(ROOT)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["scope"] == "offline_ci_and_declarative_governance_only"
    assert not local.exists()


def test_cli_build_verify(local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert p.main(["build", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["signed"] is False
    assert p.main(["verify", "--repo-root", str(ROOT)]) == 0
    assert json.loads(capsys.readouterr().out)["revision_matches"] is True


def test_cli_missing_evidence_reports_safe_error(local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert p.main(["verify", "--repo-root", str(ROOT)]) == 2
    out = capsys.readouterr()
    assert "portfolio failed" in out.err
    assert "C:\\" not in out.err


def test_cli_repeated_build_returns_failure(local: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p.build(ROOT)
    assert p.main(["build", "--repo-root", str(ROOT)]) == 2
    assert "portfolio failed" in capsys.readouterr().err
