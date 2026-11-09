"""Offline Project 5.2 control-to-evidence index, NOT a compliance attestation.

Reads only allowlisted registry metadata. Source evidence is checked for path
presence/type but is never opened, copied, or asserted to have passed testing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from governance.project5.registry import (
    RegistryError,
    _atomic_write,
    _read_json,
)
from governance.project5.registry import (
    validate as validate_registry,
)

CONTROL_FIELDS = frozenset({
    "control_id", "title", "asset_ids", "nist_ai_rmf_functions",
    "iso_42001_theme", "evidence", "risk_ids", "known_gaps",
    "owner", "review_status",
})
EVIDENCE_FIELDS = frozenset({"path", "kind", "path_type"})
FUNCTIONS = frozenset({"GOVERN", "MAP", "MEASURE", "MANAGE"})
ISO_THEMES = frozenset({
    "leadership and accountability",
    "AI risk assessment and treatment",
    "operational controls",
    "performance evaluation and improvement",
})
EVIDENCE_KINDS = frozenset({"implementation", "test", "documentation", "ci"})
PATH_TYPES = frozenset({"file", "directory"})
CONTROL_RE = re.compile(r"CYR-CTL-[0-9]{3}\Z")
SAFE_TEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()/+,:;-]{3,179}\Z")
SAFE_PATH_RE = re.compile(r"[A-Za-z0-9._/-]{2,180}\Z")


class MappingError(ValueError):
    """Invalid declared control mapping or unsafe local report destination."""


def _safe_path(value: Any) -> bool:
    """Strict relative POSIX path without escaping or Markdown syntax."""
    return (
        isinstance(value, str)
        and SAFE_PATH_RE.fullmatch(value) is not None
        and not any(part in {"", ".", ".."} or part.startswith(".") for part in value.split("/"))
    )


def _safe_text(value: Any) -> bool:
    return isinstance(value, str) and SAFE_TEXT_RE.fullmatch(value) is not None


def _unique_refs(refs: Any, allowed: set[str], kind: str, *, may_be_empty: bool) -> None:
    if not isinstance(refs, list) or len(refs) > 30 or (not refs and not may_be_empty):
        raise MappingError(f"Invalid {kind} references")
    if any(not isinstance(ref, str) or ref not in allowed for ref in refs):
        raise MappingError(f"Unknown {kind} reference")
    if len(refs) != len(set(refs)):
        raise MappingError(f"Duplicate {kind} reference")


def validate_mapping(
    catalogue: dict[str, Any], assets: dict[str, Any], risks: dict[str, Any]
) -> dict[str, int | bool]:
    """Validate declarative mappings and 5.1 policy; never approve controls."""
    validate_registry(assets, risks)
    if (
        not isinstance(catalogue, dict)
        or catalogue.keys() != {"schema_version", "controls"}
        or type(catalogue["schema_version"]) is not int
        or catalogue["schema_version"] != 1
    ):
        raise MappingError("Invalid control catalogue schema")
    rows = catalogue["controls"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 50:
        raise MappingError("Invalid control catalogue size")
    asset_ids = {item["asset_id"] for item in assets["assets"]}
    risk_ids = {item["risk_id"] for item in risks["risks"]}
    ids: set[str] = set()
    evidence_total = 0
    for row in rows:
        if not isinstance(row, dict) or row.keys() != CONTROL_FIELDS:
            raise MappingError("Unrecognized control fields")
        cid = row["control_id"]
        if not isinstance(cid, str) or CONTROL_RE.fullmatch(cid) is None or cid in ids:
            raise MappingError("Invalid or duplicate control ID")
        ids.add(cid)
        if not _safe_text(row["title"]):
            raise MappingError("Invalid control title")
        _unique_refs(row["asset_ids"], asset_ids, "asset", may_be_empty=False)
        _unique_refs(row["risk_ids"], risk_ids, "risk", may_be_empty=True)
        _unique_refs(
            row["nist_ai_rmf_functions"], set(FUNCTIONS), "NIST function", may_be_empty=False
        )
        if (not isinstance(row["iso_42001_theme"], str)
                or row["iso_42001_theme"] not in ISO_THEMES):
            raise MappingError("Unrecognized ISO thematic reference")
        if row["owner"] is not None or row["review_status"] != "needs_human_review":
            raise MappingError("Owner assignments and approval are not supported in 5.2")
        gaps = row["known_gaps"]
        if (
            not isinstance(gaps, list)
            or not 1 <= len(gaps) <= 20
            or any(not _safe_text(gap) for gap in gaps)
            or len(gaps) != len(set(gaps))
        ):
            raise MappingError("Invalid or missing assurance gaps")
        evidence = row["evidence"]
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 20:
            raise MappingError("Invalid evidence references")
        seen: set[str] = set()
        for item in evidence:
            if not isinstance(item, dict) or item.keys() != EVIDENCE_FIELDS:
                raise MappingError("Invalid evidence fields")
            path = item["path"]
            if not _safe_path(path) or path in seen:
                raise MappingError("Unsafe or repeated evidence path")
            seen.add(path)
            if (
                not isinstance(item["kind"], str)
                or item["kind"] not in EVIDENCE_KINDS
                or not isinstance(item["path_type"], str)
                or item["path_type"] not in PATH_TYPES
            ):
                raise MappingError("Unrecognized evidence classification")
        evidence_total += len(evidence)
    return {
        "controls": len(rows),
        "evidence_references": evidence_total,
        "controls_needing_human_review": len(rows),
        "controls_with_declared_gaps": len(rows),
        "unassigned_control_owners": len(rows),
        "open_registered_risks": len(risks["risks"]),
        "security_assured_release_approved": False,
        "compliance_certified": False,
    }


def _evidence_status(repo_root: Path, item: dict[str, str]) -> str:
    """Only presence/type; no execution, reading, or content validation."""
    base = repo_root.resolve()
    path = base / item["path"]
    # Do not dereference links outside the repository or assert linked data is trusted.
    if not path.resolve().is_relative_to(base):
        return "untrusted_path"
    if path.is_symlink():
        return "untrusted_path"
    if item["path_type"] == "directory":
        return "located" if path.is_dir() else "missing"
    return "located" if path.is_file() else "missing"


def assess(
    catalogue: dict[str, Any], assets: dict[str, Any], risks: dict[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    summary = validate_mapping(catalogue, assets, risks)
    asset_risk_ids = {risk["risk_id"] for risk in risks["risks"] if risk["status"] == "open"}
    rows: list[dict[str, Any]] = []
    evidence_located = evidence_missing = evidence_untrusted = 0
    for row in sorted(catalogue["controls"], key=lambda entry: entry["control_id"]):
        evidence_rows = []
        for ref in row["evidence"]:
            status = _evidence_status(repo_root, ref)
            evidence_located += status == "located"
            evidence_missing += status == "missing"
            evidence_untrusted += status == "untrusted_path"
            evidence_rows.append({**ref, "presence": status})
        rows.append({
            "control_id": row["control_id"],
            "title": row["title"],
            "asset_ids": row["asset_ids"],
            "nist_ai_rmf_functions": row["nist_ai_rmf_functions"],
            "iso_42001_theme": row["iso_42001_theme"],
            "evidence": evidence_rows,
            "risk_ids": row["risk_ids"],
            "open_linked_risk_ids": sorted(asset_risk_ids.intersection(row["risk_ids"])),
            "known_gaps": row["known_gaps"],
            "owner": None,
            "review_status": "needs_human_review",
            "effectiveness_verified": False,
        })
    return {
        "summary": {
            **summary,
            "evidence_located": evidence_located,
            "evidence_missing": evidence_missing,
            "evidence_untrusted": evidence_untrusted,
            "effectiveness_verified": False,
        },
        "controls": rows,
    }


def _input_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_report(
    catalogue: dict[str, Any], assets: dict[str, Any], risks: dict[str, Any],
    repo_root: Path, catalogue_path: Path, assets_path: Path,
    risks_path: Path, output_dir: Path,
) -> dict[str, Any]:
    root = repo_root.resolve()
    allowed = (root / "telemetry" / "governance").resolve()
    dest = output_dir.resolve()
    if dest == allowed or not dest.is_relative_to(allowed):
        raise MappingError("Reports must be under telemetry/governance/<run-name>")
    sources = {path.resolve() for path in (catalogue_path, assets_path, risks_path)}
    targets = (dest / "control-summary.json", dest / "control-mapping.md")
    if any(path.resolve() in sources for path in targets):
        raise MappingError("Report cannot overwrite registry inputs")
    result = assess(catalogue, assets, risks, root)
    payload = {
        "schema_version": 1,
        "scope": "isolated_local_research",
        "framework_references": {
            "nist_ai_rmf": "AI RMF 1.0 function-level only",
            "iso_iec_42001": "ISO/IEC 42001:2023 non-normative themes only",
        },
        "summary": result["summary"],
        "controls": result["controls"],
        "source_sha256": {
            "catalogue": _input_sha256(catalogue_path),
            "assets": _input_sha256(assets_path),
            "risks": _input_sha256(risks_path),
        },
        "limitations": [
            "File presence is not an execution, effectiveness, or audit verification.",
            "Framework associations are proposed and require independent review.",
            "No certification, signed evidence, risk acceptance, or release approval.",
        ],
    }
    summary = result["summary"]
    lines = [
        "# Cyranta AI Security Control Mapping — Project 5.2", "",
        "**LOCAL RESEARCH ONLY — NO CERTIFICATION OR RELEASE APPROVAL**", "",
        "NIST AI RMF 1.0 function-level thematic crosswalk; ISO/IEC 42001:2023",
        "management-system themes (not verified clauses).", "",
        (f"Controls: {summary['controls']} | Evidence located: {summary['evidence_located']} | "
         f"Missing: {summary['evidence_missing']} | Untrusted: {summary['evidence_untrusted']}"), "",
        "| Control | NIST functions | ISO theme | Open linked risks | Review |",
        "|---|---|---|---|---|",
    ]
    for row in result["controls"]:
        lines.append(
            f"| {row['control_id']} — {row['title']} | "
            f"{', '.join(row['nist_ai_rmf_functions'])} | {row['iso_42001_theme']} | "
            f"{', '.join(row['open_linked_risk_ids']) or 'none recorded'} | "
            "Human review required |"
        )
    for row in result["controls"]:
        lines.extend(["", f"## {row['control_id']}: {row['title']}", "",
                      f"Assets: {', '.join(row['asset_ids'])}", "", "Evidence path index:"])
        for ref in row["evidence"]:
            lines.append(f"- {ref['path']} ({ref['kind']}; {ref['presence']})")
        lines.extend(["", "Known gaps:"])
        for gap in row["known_gaps"]:
            lines.append(f"- {gap}")
    lines.extend([
        "", "## Important limitations", "",
        "- Located evidence is not proof that associated tests ran successfully.",
        "- Framework associations are unapproved thematic suggestions, not compliance.",
        "- The ChromaDB residual dependency risk remains open and unaccepted.",
        "- Owners are unassigned and effectiveness has not been independently verified.",
        "- SHA-256 hashes are unsigned and do not establish source authenticity.",
        "- Security-assured production release remains NOT APPROVED.", "",
    ])
    _atomic_write(targets[0], json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    _atomic_write(targets[1], "\n".join(lines))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Cyranta AI control mapping")
    parser.add_argument("command", choices=("validate", "report"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--catalogue", type=Path, default=Path("governance/project5/controls.json"))
    parser.add_argument("--assets", type=Path, default=Path("governance/project5/assets.json"))
    parser.add_argument("--risks", type=Path, default=Path("governance/project5/risks.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("telemetry/governance/project5-2"))
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    def under_root(path: Path) -> Path:
        target = path if path.is_absolute() else root / path
        if not target.resolve().is_relative_to(root):
            raise MappingError("Registry input must remain under repository root")
        return target
    try:
        catalogue_path = under_root(args.catalogue)
        assets_path = under_root(args.assets)
        risks_path = under_root(args.risks)
        catalogue = _read_json(catalogue_path)
        assets = _read_json(assets_path)
        risks = _read_json(risks_path)
        if args.command == "report":
            output = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
            summary = generate_report(
                catalogue, assets, risks, root, catalogue_path,
                assets_path, risks_path, output,
            )
        else:
            summary = validate_mapping(catalogue, assets, risks)
    except (MappingError, RegistryError, OSError, UnicodeError) as exc:
        print(f"Control mapping failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
