"""Project 6.5: offline CI-boundary guard and unsigned portfolio evidence.

No live model, self-hosted runner, GitHub API, credentials or attack replay.
A local clean-commit record is not third-party authentication or approval.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from governance.project5 import assurance_checks as ac
from governance.project5 import governance_dashboard as gd
from governance.project5.registry import _read_json
from validation.project6 import schema, traceability

DEFAULT_OUTPUT = Path("telemetry/governance/project6-5")
OUTPUTS = ("portfolio-index.json", "portfolio-summary.md")
MAX_MANIFEST_BYTES = 32 * 1024
MAX_REPORT_BYTES = 128 * 1024
PUBLIC_ENV_EXAMPLE = (
    "# Safe example configuration; no real credentials.\n"
    "OLLAMA_BASE_URL=http://127.0.0.1:11434\n"
    "OLLAMA_MODEL=replace-with-your-installed-local-model\n"
    "SECURITY_PROFILE=hardened\n"
    "LOG_LEVEL=INFO\n"
    "LOG_RAW_CONTENT=false\n"
    "APP_PORT=8000\n"
    "LAB_FAKE_SECRET=CYR-DEMO-KEY-FAKE-7F4C2A\n"
)

SOURCES = (
    ".github/workflows/ci.yml",
    ".env.example",
    "docs/phase7/PUBLIC-EDITION-REVIEW.md",
    "scripts/security_gate.sh",
    ".gitignore",
    "README.md",
    "SECURITY.md",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-rag.txt",
    "governance/project5/assets.json",
    "governance/project5/controls.json",
    "governance/project5/risks.json",
    "validation/project6/schema.py",
    "validation/project6/runner.py",
    "validation/project6/correlation.py",
    "validation/project6/traceability.py",
    "validation/project6/portfolio.py",
    "README-PROJECT6-1-SCENARIO-CATALOGUE.md",
    "README-PROJECT6-2-DETERMINISTIC-RUNNER.md",
    "README-PROJECT6-3-INCIDENT-CORRELATION.md",
    "README-PROJECT6-4-GOVERNANCE-TRACEABILITY.md",
    "README-PROJECT6-5-CI-PORTFOLIO.md",
    "docs/project6/PORTFOLIO-AND-REPRODUCIBILITY.md",
)
FORBIDDEN_APPROVALS = (
    "independently_attested", "compliance_certified",
    "control_effectiveness_verified", "security_assured_release_approved",
    "incident_confirmed", "finding_control_links_approved", "dependency_risk_accepted",
    "historical_retests_independently_verified", "production_ready",
    "matching_postmerge_github_ci_verified",
)


class PortfolioError(ValueError):
    """Unsafe CI configuration, governance conflict or modified local evidence."""


def _source(root: Path, relative: str) -> Path:
    if relative not in SOURCES:
        raise PortfolioError("Unreviewed source path")
    cursor = root
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise PortfolioError("Symlinked source or ancestor")
    path = root / relative
    if not path.resolve().is_relative_to(root):
        raise PortfolioError("Source path escapes repository")
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT_BYTES:
        raise PortfolioError("Missing or oversized reviewed source")
    return path


def _read_source(root: Path, path: str) -> str:
    return _source(root, path).read_text(encoding="utf-8-sig")


def _hashes(root: Path) -> dict[str, str]:
    return {rel: ac._hash(_source(root, rel)) for rel in SOURCES}


def _block(text: str, name: str) -> str:
    """Read an exact top-level YAML mapping from the two reviewed simple files.

    This is deliberately NOT a general YAML parser; any changed workflow shape
    requires review and update of this guard rather than silent acceptance.
    """
    pattern = re.compile(rf"^{re.escape(name)}:[ \t]*$", re.MULTILINE)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise PortfolioError("Missing or duplicate top-level workflow field")
    start = matches[0].end()
    rest = text[start:]
    next_key = re.search(r"^(?![ \t]|#|$)[\w-]+:", rest, re.MULTILINE)
    return rest[:next_key.start()] if next_key else rest


def _yaml_events(text: str) -> set[str]:
    events = re.findall(r"^  ([a-z_]+):[ \t]*$", _block(text, "on"), re.MULTILINE)
    if not events or len(events) != len(set(events)):
        raise PortfolioError("Unsupported workflow event block")
    return set(events)


def _job_names(text: str) -> list[str]:
    names = re.findall(r"^  ([\w-]+):[ \t]*$", _block(text, "jobs"), re.MULTILINE)
    if not names or len(names) != len(set(names)):
        raise PortfolioError("Unexpected or duplicated workflow jobs")
    return names


def _read_only_permissions(text: str) -> None:
    block = _block(text, "permissions")
    # No second token, e.g. packages:write or id-token:write, is permitted.
    if re.findall(r"^  ([\w-]+):[ \t]*(\w+)[ \t]*$", block, re.MULTILINE) != [("contents", "read")]:
        raise PortfolioError("Workflow permissions are not contents:read only")


def _checkout_safe(text: str) -> None:
    # Exactly one reviewed checkout action with no persisted GitHub token.
    matches = list(re.finditer(r"^[ \t]+uses:[ \t]+actions/checkout@([^\s#]+)", text, re.MULTILINE))
    if len(matches) != 1 or matches[0].group(1) != "v4":
        raise PortfolioError("Checkout action changed without review")
    after = text[matches[0].end():]
    # Stop at the next step, not at nested YAML keys inside the with block.
    following_step = re.search(r"^      - name:", after, re.MULTILINE)
    own_step = after[:following_step.start()] if following_step else after
    if len(re.findall(r"^          persist-credentials: false[ \t]*$", own_step, re.MULTILINE)) != 1:
        raise PortfolioError("Checkout credentials must not persist")
    if "persist-credentials: true" in text:
        raise PortfolioError("Checkout credentials enabled")


def _workflow_guard(root: Path) -> dict[str, bool]:
    """Public snapshot: exactly one hosted workflow and no private runner files."""
    workflow_dir = root / ".github/workflows"
    if workflow_dir.is_symlink() or not workflow_dir.is_dir():
        raise PortfolioError("Missing or symlinked public workflow directory")
    if {entry.name for entry in workflow_dir.iterdir()} != {"ci.yml"}:
        raise PortfolioError("Public release must contain only hosted ci.yml")
    for path in (
        root / "results/local-redteam",
        root / "scripts/local_redteam_gate.ps1",
    ):
        if path.exists() or path.is_symlink():
            raise PortfolioError("Private runner or raw evidence present in public snapshot")
    hosted = _read_source(root, ".github/workflows/ci.yml")
    if any(token in hosted for token in (
        "pull_request_target", "workflow_run:", "repository_dispatch:",
        "schedule:", "secrets.", "self-hosted", "local_redteam_gate.ps1",
        "11434", "actions/upload-artifact@",
    )):
        raise PortfolioError("Unsafe public hosted CI configuration")
    _read_only_permissions(hosted)
    _checkout_safe(hosted)
    if _yaml_events(hosted) != {"push", "pull_request"}:
        raise PortfolioError("Public CI trigger changed")
    if _job_names(hosted) != ["deterministic-security-gate"]:
        raise PortfolioError("Public CI job list changed")
    if not re.search(r"(?m)^    runs-on: ubuntu-latest[ \t]*$", hosted):
        raise PortfolioError("Public CI must use GitHub-hosted Linux")
    hosted_on = _block(hosted, "on")
    if not re.search(r"(?m)^    branches:[ \t]*\n      - main[ \t]*$", hosted_on):
        raise PortfolioError("Public main push validation missing")
    if "bash scripts/security_gate.sh" not in hosted:
        raise PortfolioError("Public security gate command missing")
    return {
        "hosted_ci_pull_requests_on_github_runner": True,
        "public_hosted_ci_only": True,
        "private_runner_workflow_absent": True,
        "checkout_credentials_not_persisted": True,
        "raw_local_redteam_evidence_absent": True,
    }


def _gate_guard(root: Path) -> None:
    gate = _read_source(root, "scripts/security_gate.sh")
    expected = (
        "set -euo pipefail", "python -m compileall -q", "ruff check .",
        "python -m validation.project6.portfolio check", "python -m pytest -q",
        "bandit -q -r", "validation/project6/schema.py", "validation/project6/runner.py",
        "validation/project6/correlation.py", "validation/project6/traceability.py",
        "validation/project6/portfolio.py", "pip-audit -r requirements.txt",
        "pip-audit -r requirements-agent.txt",
    )
    if any(gate.count(token) != 1 for token in expected):
        raise PortfolioError("Reviewed hosted security gate no longer complete")
    if re.search(r"(?m)^\s*pip-audit\s+-r\s+requirements-rag\.txt", gate):
        raise PortfolioError("RAG dependency decision cannot be silently absorbed into green CI")
    if not re.search(r"(?m)^set -euo pipefail[ \t]*$", gate):
        raise PortfolioError("Security gate must fail closed")


def _governance(root: Path) -> dict[str, int | bool]:
    scenario = schema.validate(root)
    assets, risks, controls = traceability._inputs(root)
    rows = traceability._records(assets, risks, controls)
    if len(rows) != 4 or len(risks["risks"]) != 1:
        raise PortfolioError("Reviewed traceability baseline changed")
    risk = risks["risks"][0]
    if risk["risk_id"] != "CYRANTA-DEP-001" or risk["status"] != "open" or risk["risk_owner"] is not None:
        raise PortfolioError("Unapproved dependency-risk status or owner change")
    if risk.get("decision") != "pending_review":
        raise PortfolioError("Unapproved risk decision change")
    if len(assets["assets"]) != 5 or len(controls["controls"]) != 7:
        raise PortfolioError("Governance asset/control counts changed")
    if any(item["owner"] is not None for item in assets["assets"] + controls["controls"]):
        raise PortfolioError("Owner change requires a reviewed baseline update")
    if scenario["scenario_count"] != 6 or scenario["scenarios_not_run"] != 6:
        raise PortfolioError("Scenario catalogue changed without review")
    return {
        "scenario_manifest_count": 6,
        "scenario_manifests_not_run": 6,
        "historical_finding_documents": 3,
        "synthetic_incidents_confirmed": 0,
        "approved_finding_control_links": 0,
        "registered_open_dependency_risks": 1,
        "unassigned_assets": 5,
        "controls_needing_human_review": 7,
        "unassigned_controls": 7,
        "release_authorized": False,
    }


def check(root: Path) -> dict[str, Any]:
    """Offline read-only policy inspection, safe inside hosted PR CI."""
    root = root.resolve()
    workflows = _workflow_guard(root)
    _gate_guard(root)
    counts = _governance(root)
    if "telemetry/governance/" not in _read_source(root, ".gitignore"):
        raise PortfolioError("Governance evidence is not ignored by Git")
    if "PORTFOLIO-AND-REPRODUCIBILITY.md" not in _read_source(root, "README.md"):
        raise PortfolioError("Portfolio navigation missing")
    if _read_source(root, ".env.example") != PUBLIC_ENV_EXAMPLE:
        raise PortfolioError("Public environment example differs from reviewed placeholders")
    if "public hosted-only" not in _read_source(root, "docs/phase7/PUBLIC-EDITION-REVIEW.md"):
        raise PortfolioError("Public edition release boundary is missing")
    # Fail closed when the portfolio is missing; never copy its full text into output.
    _source(root, "docs/project6/PORTFOLIO-AND-REPRODUCIBILITY.md")
    _source(root, "README-PROJECT6-5-CI-PORTFOLIO.md")
    return {
        "scope": "offline_ci_and_declarative_governance_only",
        "workflow_guards": workflows,
        "governance": counts,
        "dependency_risk_id": "CYRANTA-DEP-001",
        "dependency_risk_decision": "pending_review",
        "dependency_rag_audit_in_green_gate": False,
        "runtime_model_called": False,
        **{name: False for name in FORBIDDEN_APPROVALS},
    }


def _index(root: Path, sha: str, clean: bool) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "unsigned_local_project6_5_portfolio_ci_review",
        "source_commit": sha,
        "worktree_clean_at_capture": clean,
        **check(root),
    }


def _markdown(index: dict[str, Any]) -> str:
    governance = index["governance"]
    return "\n".join([
        "# Cyranta Project 6.5 — CI and Portfolio Evidence Summary", "",
        "**UNSIGNED LOCAL REVIEW; NO SECURITY-ASSURED RELEASE APPROVAL.**", "",
        f"Recorded Git revision: `{index['source_commit']}`.",
        f"Clean worktree at capture: `{str(index['worktree_clean_at_capture']).lower()}`.", "",
        "## Offline checks (not production proof)", "",
        "- GitHub-hosted PR CI runs syntax, Ruff, offline policy, pytest, Bandit, and core/agent pip-audit.",
        "- This public snapshot has a hosted-only CI workflow, with no private runner workflow.",
        "- GitHub checkout credentials are not persisted by hosted CI.",
        "- Private local runner scripts and raw red-team evidence are excluded from public source.",
        "- GitHub Actions post-merge SHA/conclusion must be verified separately; this tool makes no GitHub API call.", "",
        "## Scoped declarations", "",
        f"- Project 6 scenario manifests: {governance['scenario_manifest_count']}; metadata status `not_run`: {governance['scenario_manifests_not_run']}.",
        f"- Historical documented findings: {governance['historical_finding_documents']} (not independently verified).",
        f"- Unassigned assets: {governance['unassigned_assets']}; unassigned controls: {governance['unassigned_controls']}.",
        f"- Open registered dependency risks: {governance['registered_open_dependency_risks']}, including `CYRANTA-DEP-001` (pending review).",
        "- Approved finding-to-control mappings: zero; actual Project 6.3 incidents confirmed: zero.",
        "- Core/agent audits in green CI do not cover the unresolved ChromaDB RAG risk.", "",
        "## Important evidence gaps", "",
        "- Project 6.2 checks use in-memory RAG fixtures, not a live ChromaDB/Ollama assurance run.",
        "- Project 6.3 correlations use deliberately matched fictional request IDs; no real incident attribution.",
        "- Project 6.4 checked-in finding narratives are proposals, not approved governance mappings.",
        "- No independent inspection of historical retest artifacts or link from 6.2 to older findings.",
        "- Workflow action tags are not pinned to full commit SHAs; provenance review is still necessary.",
        "- SHA-256 checksums detect modification of local evidence, not authorship, custody or attestation.",
        "- Human owners, risk decision and independent control assessment remain outstanding.", "",
        "## Portfolio", "",
        "See `docs/project6/PORTFOLIO-AND-REPRODUCIBILITY.md` for architecture, boundaries,",
        "reproduction commands, demo script and executive summary. Research-only milestone.", "",
    ])


def _folder(root: Path, destination: Path) -> Path:
    return gd._local_folder(root, destination)


def build(root: Path, destination: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Write a new ignored, unsigned, local-only report. Never overwrite."""
    root = root.resolve()
    folder = _folder(root, destination)
    if folder.exists():
        raise PortfolioError("Existing evidence cannot be overwritten")
    sha, clean = ac._revision(root)
    index = _index(root, sha, clean)
    sources = _hashes(root)
    folder.mkdir(parents=True, exist_ok=False)
    (folder / OUTPUTS[0]).write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (folder / OUTPUTS[1]).write_text(_markdown(index), encoding="utf-8", newline="\n")
    manifest = {
        "schema_version": 1,
        "kind": "unsigned_local_project6_5_hash_manifest",
        "source_commit": sha,
        "source_sha256": sources,
        "files_sha256": {name: ac._hash(folder / name) for name in OUTPUTS},
        "signed": False,
    }
    (folder / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return {"source_commit": sha, "worktree_clean_at_capture": clean,
            "scenario_manifests": 6, "registered_open_risks": 1,
            "signed": False, "security_assured_release_approved": False}


def _read_evidence(path: Path, limit: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise PortfolioError("Missing, symlinked or oversized evidence")
    return _read_json(path)


def verify(root: Path, destination: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Reconstruct declared evidence; hashes are NOT independent attestation."""
    root = root.resolve()
    folder = _folder(root, destination)
    manifest = _read_evidence(folder / "evidence-manifest.json", MAX_MANIFEST_BYTES)
    if (manifest.keys() != {"schema_version", "kind", "source_commit", "source_sha256", "files_sha256", "signed"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or manifest["kind"] != "unsigned_local_project6_5_hash_manifest"
            or manifest["signed"] is not False
            or not isinstance(manifest["source_commit"], str)
            or ac.FULL_SHA.fullmatch(manifest["source_commit"]) is None
            or manifest["source_sha256"] != _hashes(root)):
        raise PortfolioError("Stale or forged local portfolio manifest")
    if not isinstance(manifest["files_sha256"], dict) or set(manifest["files_sha256"]) != set(OUTPUTS):
        raise PortfolioError("Unexpected evidence file list")
    for name in OUTPUTS:
        file = folder / name
        expected = manifest["files_sha256"][name]
        if (not isinstance(expected, str) or re.fullmatch(r"[a-f0-9]{64}", expected) is None
                or file.is_symlink() or not file.is_file()
                or not 0 < file.stat().st_size <= MAX_REPORT_BYTES
                or ac._hash(file) != expected):
            raise PortfolioError("Modified or missing local portfolio evidence")
    index = _read_evidence(folder / OUTPUTS[0], MAX_REPORT_BYTES)
    recorded_clean = index.get("worktree_clean_at_capture")
    if type(recorded_clean) is not bool or index.get("source_commit") != manifest["source_commit"]:
        raise PortfolioError("Unreliable recorded source revision")
    if index != _index(root, manifest["source_commit"], recorded_clean):
        raise PortfolioError("Portfolio index no longer matches reviewed source")
    if (folder / OUTPUTS[1]).read_text(encoding="utf-8") != _markdown(index):
        raise PortfolioError("Portfolio summary was altered")
    head, clean = ac._revision(root)
    matching = head == manifest["source_commit"]
    return {
        "revision_matches": matching,
        "clean_committed_local_record": bool(matching and clean and recorded_clean),
        "offline_workflow_guard_passed": True,
        "registered_risk_still_open": True,
        "scenario_manifests": 6,
        "historical_findings": 3,
        "independently_attested": False,
        "security_assured_release_approved": False,
        "matching_postmerge_github_ci_verified": False,
        "dependency_risk_accepted": False,
        "control_effectiveness_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cyranta P6.5 offline CI and portfolio guard")
    parser.add_argument("command", choices=("check", "build", "verify"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            result = check(args.repo_root)
        elif args.command == "build":
            result = build(args.repo_root, args.output_dir)
        else:
            result = verify(args.repo_root, args.output_dir)
    except (PortfolioError, schema.ScenarioError, traceability.TraceabilityError,
            ac.AssuranceError, gd.DashboardError, OSError, ValueError, TypeError,
            IndexError, UnicodeError, KeyError) as exc:
        print(f"Project 6.5 portfolio failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
