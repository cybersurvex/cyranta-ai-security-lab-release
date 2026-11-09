"""Project 6.4: offline, unsigned finding-to-governance reference crosswalk.

The source documents make historical local-lab claims; this module checks
identity, file presence, register consistency and hashes, NOT their truth.
No incident-to-finding attribution, control approval or risk acceptance.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from governance.project5 import assurance_checks as ac
from governance.project5 import governance_dashboard as gd
from governance.project5.control_mapping import validate_mapping
from governance.project5.registry import _read_json
from validation.project6 import schema

DEFAULT_OUTPUT = Path("telemetry/governance/project6-4")
OUTPUTS = ("traceability-index.json", "traceability-report.md")
MAX_EVIDENCE_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
REGISTRIES = (
    "governance/project5/assets.json",
    "governance/project5/risks.json",
    "governance/project5/controls.json",
)
# Explicit proposals from reviewed checked-in narratives, NOT prior approved
# Project 5 finding mappings. No implicit link to Project 6.3 synthetic cases.
FINDINGS: dict[str, dict[str, Any]] = {
    "CYR-LLM-002": {
        "asset_ids": ["CYR-AST-001"],
        "control_ids": ["CYR-CTL-001"],
        "documents": ["findings/CYR-LLM-002.md"],
        "claim_scope": "reported_local_remediation_and_retest",
    },
    "CYR-DET-003": {
        "asset_ids": ["CYR-AST-001", "CYR-AST-004"],
        "control_ids": ["CYR-CTL-001", "CYR-CTL-004"],
        "documents": ["findings/CYR-DET-003.md"],
        "claim_scope": "reported_local_detector_retest",
    },
    "CYR-AGENT-001": {
        "asset_ids": ["CYR-AST-003", "CYR-AST-004"],
        "control_ids": ["CYR-CTL-003", "CYR-CTL-004"],
        "documents": [
            "agent/findings/CYR-AGENT-001.md",
            "agent/findings/CYR-AGENT-001-RETEST.md",
            "agent/findings/CYR-AGENT-001-CONTROL-VALIDATION.md",
        ],
        "claim_scope": "reported_local_mock_gateway_retest",
    },
}
DOCUMENTS = tuple(dict.fromkeys(
    path for spec in FINDINGS.values() for path in spec["documents"]
)) + ("docs/security/CHROMADB-RISK-ASSESSMENT.md",)
SOURCES = (*REGISTRIES, *DOCUMENTS,
           "validation/project6/schema.py", "validation/project6/runner.py",
           "validation/project6/correlation.py", "validation/project6/traceability.py")
RISK_ID = "CYRANTA-DEP-001"
FORBIDDEN_ASSURANCE = (
    "independently_attested", "control_effectiveness_verified",
    "compliance_certified", "incident_finding_link_verified",
    "retest_artifacts_independently_inspected", "security_assured_release_approved",
)


class TraceabilityError(ValueError):
    """Missing or unreviewed sources, invalid reference, or modified evidence."""


def _source(root: Path, relative: str) -> Path:
    """Only fixed, in-repository, non-symlinked source files."""
    if relative not in SOURCES:
        raise TraceabilityError("Unreviewed source file")
    path = ac._in_repo(root, relative)
    cursor = root
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise TraceabilityError("Source or ancestor is a symlink")
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_EVIDENCE_BYTES:
        raise TraceabilityError("Missing or oversized reviewed source")
    return path


def _hashes(root: Path) -> dict[str, str]:
    return {relative: ac._hash(_source(root, relative)) for relative in SOURCES}


def _documents(root: Path) -> None:
    """Check only identity markers; never copy document text into output."""
    for fid, spec in FINDINGS.items():
        for relative in spec["documents"]:
            first = _source(root, relative).read_text(encoding="utf-8-sig").splitlines()[0]
            if not first.startswith(f"# {fid} "):
                raise TraceabilityError("Finding document identity mismatch")
    risk_first = _source(root, DOCUMENTS[-1]).read_text(encoding="utf-8-sig").splitlines()[0]
    if not risk_first.startswith(f"# {RISK_ID} "):
        raise TraceabilityError("Risk document identity mismatch")


def _inputs(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    schema.validate(root)
    assets, risks, controls = (_read_json(_source(root, rel)) for rel in REGISTRIES)
    validate_mapping(controls, assets, risks)
    _documents(root)
    if len(assets["assets"]) != 5 or len(controls["controls"]) != 7 or len(risks["risks"]) != 1:
        raise TraceabilityError("Reviewed governance baseline changed")
    if risks["risks"][0]["risk_id"] != RISK_ID or risks["risks"][0]["status"] != "open":
        raise TraceabilityError("Risk registry differs from reviewed baseline")
    if risks["risks"][0]["source_document"] != DOCUMENTS[-1]:
        raise TraceabilityError("Risk source document mismatch")
    return assets, risks, controls


def _records(assets: dict[str, Any], risks: dict[str, Any], controls: dict[str, Any]) -> list[dict[str, Any]]:
    asset_ids = {item["asset_id"] for item in assets["assets"]}
    by_control = {item["control_id"]: item for item in controls["controls"]}
    rows: list[dict[str, Any]] = []
    for fid, spec in FINDINGS.items():
        if not set(spec["asset_ids"]).issubset(asset_ids):
            raise TraceabilityError("Unknown finding asset")
        for cid in spec["control_ids"]:
            if cid not in by_control or not (set(spec["asset_ids"]) & set(by_control[cid]["asset_ids"])):
                raise TraceabilityError("Finding control does not cover proposed asset")
        rows.append({
            "record_id": fid, "record_kind": "historical_finding_document",
            "asset_ids": spec["asset_ids"], "control_ids": spec["control_ids"],
            "link_basis": "proposed_narrative_to_control_crosswalk_unapproved",
            "source_documents": spec["documents"],
            "documented_claim_scope": spec["claim_scope"],
            "registered_risk_ids": [],
            "evidence_grade": "checked_in_narrative_located_not_independently_validated",
            "human_review_required": True,
            "incident_finding_link_verified": False,
            "retest_artifacts_independently_inspected": False,
            "control_effectiveness_verified": False,
        })
    risk = risks["risks"][0]
    actual_controls = sorted(item["control_id"] for item in controls["controls"]
                             if RISK_ID in item["risk_ids"])
    if actual_controls != ["CYR-CTL-006", "CYR-CTL-007"]:
        raise TraceabilityError("Risk-to-control registry links differ from reviewed baseline")
    if risk["asset_ids"] != ["CYR-AST-002"]:
        raise TraceabilityError("Registered risk asset differs from reviewed baseline")
    rows.append({
        "record_id": RISK_ID, "record_kind": "registered_open_dependency_risk",
        "asset_ids": risk["asset_ids"], "control_ids": actual_controls,
        "link_basis": "explicit_project5_control_risk_ids",
        "source_documents": [risk["source_document"]],
        "documented_claim_scope": "open_dependency_pending_review",
        "registered_risk_ids": [RISK_ID],
        "evidence_grade": "declarative_registry_and_risk_document_not_independent_audit",
        "human_review_required": True,
        "incident_finding_link_verified": False,
        "retest_artifacts_independently_inspected": False,
        "control_effectiveness_verified": False,
    })
    return rows


def _index(root: Path, sha: str, clean: bool) -> dict[str, Any]:
    assets, risks, controls = _inputs(root)
    return {
        "schema_version": 1,
        "kind": "unsigned_local_project6_4_finding_governance_crosswalk",
        "source_commit": sha,
        "worktree_clean_at_capture": clean,
        "records": _records(assets, risks, controls),
        "summary": {
            "historical_finding_documents": len(FINDINGS),
            "registered_open_risks": len(risks["risks"]),
            "traceability_records": len(FINDINGS) + len(risks["risks"]),
            "controls_needing_human_review": len(controls["controls"]),
            "unassigned_asset_owners": sum(a["owner"] is None for a in assets["assets"]),
            "unassigned_control_owners": sum(c["owner"] is None for c in controls["controls"]),
            "approved_finding_control_links": 0,
        },
        "synthetic_project6_3_cases_linked_to_findings": 0,
        "scenario_manifests_modified": False,
        "risk_decisions_changed": False,
        **{name: False for name in FORBIDDEN_ASSURANCE},
    }


def _markdown(index: dict[str, Any]) -> str:
    lines = [
        "# Project 6.4 — Finding-to-Governance Traceability", "",
        "**UNSIGNED LOCAL CROSSWALK — HUMAN REVIEW REQUIRED; NO APPROVAL**", "",
        f"Source revision: `{index['source_commit']}`.", "",
        "Historical finding statements are document-authored claims; this process checks",
        "document identity, registry references, presence and hashes only. It does NOT",
        "replay original attacks, inspect ignored raw results or verify remediation.", "",
        "| Record | Classification | Linked controls | Evidence status |",
        "|---|---|---|---|",
    ]
    for row in index["records"]:
        lines.append(
            f"| {row['record_id']} | {row['record_kind']} | "
            f"{', '.join(row['control_ids'])} | {row['evidence_grade']} |"
        )
    lines.extend([
        "", "## Evidence references (documents present, content not exported)", "",
    ])
    for row in index["records"]:
        lines.append(f"### {row['record_id']}")
        lines.append("")
        lines.extend(f"- `{path}`" for path in row["source_documents"])
        lines.extend(["", "Control mapping is proposed unless directly declared as a risk link.",
                      "Human review remains required.", ""])
    lines.extend([
        "## Boundaries", "",
        "- Three historical finding documents are not registered Project 5 risks.",
        "- The ChromaDB dependency risk remains open, unaccepted and ownerless.",
        "- Historical agent and chatbot retests are described in source documents,",
        "  but raw execution logs and their origin were not independently examined.",
        "- No Project 6.2 execution evidence was linked to historical findings.",
        "- No Project 6.3 synthetic incident candidate was linked to a real finding.",
        "- No control effectiveness, organizational ownership, ISO certification,",
        "  production release, incident confirmation or risk acceptance is asserted.",
        "- SHA-256 hashes are unsigned integrity checks, not trusted provenance.", "",
    ])
    return "\n".join(lines)


def _folder(root: Path, destination: Path) -> Path:
    return gd._local_folder(root, destination)


def build(root: Path, destination: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Create immutable-by-convention, unsigned local evidence; never overwrite."""
    root = root.resolve()
    target = _folder(root, destination)
    if target.exists():
        raise TraceabilityError("Evidence directory exists; choose a new output directory")
    head, clean = ac._revision(root)
    index = _index(root, head, clean)
    hashes = _hashes(root)
    target.mkdir(parents=True, exist_ok=False)
    (target / OUTPUTS[0]).write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (target / OUTPUTS[1]).write_text(_markdown(index), encoding="utf-8", newline="\n")
    manifest = {
        "schema_version": 1,
        "kind": "unsigned_local_traceability_hash_manifest",
        "source_commit": head,
        "source_sha256": hashes,
        "files_sha256": {name: ac._hash(target / name) for name in OUTPUTS},
        "signed": False,
    }
    (target / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return {**index["summary"], "source_commit": head, "worktree_clean_at_capture": clean,
            "independently_attested": False, "control_effectiveness_verified": False,
            "security_assured_release_approved": False}


def _read_evidence(path: Path, limit: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise TraceabilityError("Missing, symlinked or oversized evidence")
    return _read_json(path)


def verify(root: Path, destination: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Verify record consistency against reviewed source; NOT authorship."""
    root = root.resolve()
    target = _folder(root, destination)
    manifest = _read_evidence(target / "evidence-manifest.json", MAX_MANIFEST_BYTES)
    if (manifest.keys() != {"schema_version", "kind", "source_commit", "source_sha256", "files_sha256", "signed"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or manifest["kind"] != "unsigned_local_traceability_hash_manifest"
            or manifest["signed"] is not False
            or not isinstance(manifest["source_commit"], str)
            or ac.FULL_SHA.fullmatch(manifest["source_commit"]) is None
            or manifest["source_sha256"] != _hashes(root)):
        raise TraceabilityError("Invalid or stale evidence manifest")
    if not isinstance(manifest["files_sha256"], dict) or set(manifest["files_sha256"]) != set(OUTPUTS):
        raise TraceabilityError("Unexpected output file list")
    for name in OUTPUTS:
        actual = target / name
        expected = manifest["files_sha256"][name]
        if (not isinstance(expected, str) or len(expected) != 64
                or any(char not in "0123456789abcdef" for char in expected)
                or actual.is_symlink() or not actual.is_file()
                or not 0 < actual.stat().st_size <= MAX_EVIDENCE_BYTES
                or ac._hash(actual) != expected):
            raise TraceabilityError("Missing or changed traceability output")
    index = _read_evidence(target / OUTPUTS[0], MAX_EVIDENCE_BYTES)
    recorded_clean = index.get("worktree_clean_at_capture")
    if type(recorded_clean) is not bool or index.get("source_commit") != manifest["source_commit"]:
        raise TraceabilityError("Invalid recorded revision")
    expected_index = _index(root, manifest["source_commit"], recorded_clean)
    if index != expected_index:
        raise TraceabilityError("Traceability crosswalk differs from reviewed source")
    if (target / OUTPUTS[1]).read_text(encoding="utf-8") != _markdown(index):
        raise TraceabilityError("Human-readable traceability report was modified")
    head, clean = ac._revision(root)
    matched = head == manifest["source_commit"]
    return {
        **index["summary"], "revision_matches": matched,
        "clean_committed_local_record": bool(matched and clean and recorded_clean),
        "registered_risk_still_open": True,
        "incident_finding_link_verified": False,
        "retest_artifacts_independently_inspected": False,
        "control_effectiveness_verified": False,
        "independently_attested": False,
        "compliance_certified": False,
        "security_assured_release_approved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Project 6.4 local evidence crosswalk")
    parser.add_argument("command", choices=("plan", "build", "verify"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            root = args.repo_root.resolve()
            assets, risks, controls = _inputs(root)
            result = {"findings": len(FINDINGS), "registered_risks": len(risks["risks"]),
                      "controls": len(controls["controls"]), "assets": len(assets["assets"]),
                      "execution": "not_started", "assurance_approved": False}
        elif args.command == "build":
            result = build(args.repo_root, args.output_dir)
        else:
            result = verify(args.repo_root, args.output_dir)
    except (TraceabilityError, schema.ScenarioError, ac.AssuranceError, gd.DashboardError,
            OSError, ValueError, TypeError, IndexError, UnicodeError) as exc:
        print(f"Project 6.4 traceability failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
